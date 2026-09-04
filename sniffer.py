#!/usr/bin/env python3
"""
sniffer.py - all-in-one WiFi direction finder: pick a network, a deauth flood,
or a specific MAC, then walk down its transmitter with the RSSI meter.

Built on router_hunt.py. One selection screen with four modes you cycle with
the S key:

  1. NETWORKS      - APs heard (hidden ones included), collapsed to one row per
                     physical radio by default (g toggles per-SSID).
  2. MGMT FLOODS   - channels under a deauth/disassoc flood, ranked by rate,
                     with a LIKELY SOURCE column naming the beaconing radio
                     whose signal matches each spoofed source (attribution.py).
  3. PROBE CLIENTS - client devices heard probing, with the named networks each
                     is searching for (its saved-network list).
  4. TRACK MAC     - type a MAC; it is auto-located by channel-hopping, then
                     tracked.

Hitting ENTER on any of them drops into the exact same RSSI hunt screen as
router_hunt - gradient bars, peak-hold, sparkline, warmer/colder + geiger
sounds. A GHz column shows whether each target transmits on 2.x or 5.x GHz.

Direction finding tracks the TRANSMITTER only (wlan.sa / wlan.ta), never the
destination: RSSI is the strength of whoever sent the frame, so a frame *to*
the target carries some other radio's signal and would point the wrong way.

RECEIVE-ONLY, like the rest of this toolkit: it only captures (tshark) and
retunes (iw). It never transmits; the tx_packets counter is shown as proof.
Channel hopping needs CAP_NET_ADMIN, so run with sudo after: sudo ./init-hunt.sh
"""

import argparse
import curses
import os
import signal
import sys
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deauth_hunt import (TxGuard, RSSI_FLOOR, RSSI_CEIL,
                         init_gradient, draw_gradient_bar)
from deauth_sweep import (detect_iface, iface_phy, iface_mode,
                          list_channels, set_channel)
from router_hunt import (CaptureThread, Hopper, hunt, build_target_filter,
                         valid_mac, freq_to_chan_map, decode_ssid, norm_priv,
                         ssid_display, first_int, directional_reminder,
                         parse_hunt, HUNT_FIELDS, BEACON, PROBE_RESP, Beeper)
import device_id
import attribution

DEAUTH = 12
DISASSOC = 10
PROBE_REQ = 4

# One capture feeds all four modes: beacons + probe responses (for networks),
# deauthentication frames (for floods / activity), and probe requests (for the
# client view), hopping across channels.
COMBINED_FILTER = (f"wlan.fc.type_subtype=={BEACON} || "
                   f"wlan.fc.type_subtype=={PROBE_RESP} || "
                   f"wlan.fc.type_subtype=={DEAUTH} || "
                   f"wlan.fc.type_subtype=={DISASSOC} || "
                   f"wlan.fc.type_subtype=={PROBE_REQ}")
# SSID is last: it may itself contain the '|' separator, so we rejoin the tail.
# The three WPS identity fields (cleartext device name/model/manufacturer from
# WPS-enabled beacons and probe-responses) sit at fixed indices; they are
# controlled device strings and in practice never contain a '|'. The frame
# timestamp and sequence number feed flood attribution (attribution.py).
COMBINED_FIELDS = ["wlan.fc.type_subtype", "wlan.sa", "wlan.ta", "wlan.da",
                   "wlan.bssid", "radiotap.channel.freq",
                   "radiotap.dbm_antsignal", "wlan.fixed.capabilities.privacy",
                   # PHY-capability IEs (feature 6): presence -> generation,
                   # HT MCS rx-bitmask -> spatial streams. Numeric, single
                   # occurrence, empty on frames without them (e.g. deauth).
                   "wlan.ht.capabilities", "wlan.vht.capabilities",
                   "wlan.ext_tag.he_mac_caps", "wlan.ht.mcsset.rxbitmask.8to15",
                   "wlan.ht.mcsset.rxbitmask.16to23",
                   "wps.device_name", "wps.model_name", "wps.manufacturer",
                   "frame.time_epoch", "wlan.seq",
                   "wlan.ssid"]
_N_FIXED = 18  # fields before the (possibly '|'-containing) SSID tail

BROADCAST = "ff:ff:ff:ff:ff:ff"


def fmt_ghz(freq):
    """Transmit band as the user asked: '2.4GHz' / '5.3GHz' (or '?' if unknown)."""
    if not freq:
        return "  ?  "
    return f"{freq / 1000:.1f}GHz"


def _first(v):
    """First comma-joined occurrence of a tshark field, trimmed."""
    return v.split(",")[0].strip()


def parse_combined(line):
    parts = line.split("|")
    if len(parts) < len(COMBINED_FIELDS):
        return None
    (st, sa, ta, da, bssid, freq, sig, priv,
     ht, vht, he, rx8, rx16,
     wps_name, wps_model, wps_manuf, ts, seq) = parts[:_N_FIXED]
    ssid = decode_ssid("|".join(parts[_N_FIXED:]))
    try:
        ts = float(ts)
    except ValueError:
        ts = None
    return {
        "st": first_int(st),
        "sa": _first(sa).lower(),
        "ta": _first(ta).lower(),
        "da": _first(da).lower(),
        "bssid": _first(bssid).lower(),
        "freq": first_int(freq),
        "rssi": first_int(sig),
        "chains": attribution.parse_chains(sig),   # combined first, then per RX chain
        "ts": ts,
        "seq": first_int(seq),
        "priv": norm_priv(priv),
        "has_ht": bool(_first(ht)),
        "has_vht": bool(_first(vht)),
        "has_he": bool(_first(he)),
        "streams": device_id.spatial_streams(_first(rx8), _first(rx16)),
        "wps_name": _first(wps_name),
        "wps_model": _first(wps_model),
        "wps_manuf": _first(wps_manuf),
        "ssid": ssid,
    }


# ==========================================================================
# Aggregation: build the network list, the flood list, and a per-MAC channel
# memory (for auto-locate) from the combined capture stream.
# ==========================================================================

class Aggregator:
    def __init__(self, flood_window=5.0):
        self.flood_window = flood_window
        self.networks = {}        # bssid -> record
        self.deauth_ts = {}       # (freq, src) -> deque[ts]
        self.chan_ts = {}         # freq -> deque[ts]  (all deauths on channel)
        self.deauth_rssi = {}     # (freq, src) -> last rssi
        self.seen_ch = {}         # mac -> freq last transmitted on
        self.clients = {}         # client mac -> record (probe-request view)
        self.freq_ts = {}         # freq -> deque[ts]  (all frames, for adaptive hopping)
        self.tracks = attribution.Tracks()   # per-frame RSSI history for attribution
        self._attrib_cache = {}   # (freq, src, st) -> (computed_at, [Attribution]), 1 s TTL

    def add(self, rec, now=None):
        now = time.time() if now is None else now
        freq = rec["freq"]
        ts = rec.get("ts") or now
        if freq:
            self.freq_ts.setdefault(freq, deque()).append(now)
        # remember where each transmitter was last heard (for MAC auto-locate)
        for who in (rec["sa"], rec["ta"]):
            if who and who != BROADCAST and freq:
                self.seen_ch[who] = freq
        if rec["st"] in (BEACON, PROBE_RESP) and rec["bssid"]:
            self._add_net(rec)
            if rec["st"] == BEACON and freq and rec.get("chains"):
                self.tracks.add_radio(freq, rec["bssid"], rec["ssid"],
                                      attribution.make_sample(ts, rec["chains"], rec.get("seq")))
        elif rec["st"] in (DEAUTH, DISASSOC) and freq:
            src = rec["sa"] or "??"
            key = (freq, src, rec["st"])
            self.deauth_ts.setdefault(key, deque()).append(now)
            self.chan_ts.setdefault(freq, deque()).append(now)
            if rec["rssi"] is not None:
                self.deauth_rssi[key] = rec["rssi"]
            # only a source we have never heard beacon can be spoofed
            if rec.get("chains") and src not in self.tracks.bssids:
                self.tracks.add_source(freq, src, rec["st"],
                                       attribution.make_sample(ts, rec["chains"], rec.get("seq")))
        elif rec["st"] == PROBE_REQ:
            self._add_client(rec, now)

    def _add_client(self, rec, now):
        mac = rec["sa"]
        if not mac or mac == BROADCAST:
            return
        c = self.clients.get(mac)
        if c is None:
            c = self.clients[mac] = {"mac": mac, "freq": rec["freq"],
                                     "rssi": rec["rssi"] if rec["rssi"] is not None
                                     else -99, "ssids": set(), "count": 0,
                                     "has_ht": False, "has_vht": False,
                                     "has_he": False, "streams": 1, "last": now}
        if rec["freq"]:
            c["freq"] = rec["freq"]
        if rec["rssi"] is not None:
            c["rssi"] = rec["rssi"]
        if rec["ssid"]:                       # a named (directed) probe
            c["ssids"].add(rec["ssid"])
        for k in ("has_ht", "has_vht", "has_he"):
            c[k] = c[k] or rec[k]
        c["streams"] = max(c["streams"], rec["streams"])
        c["count"] += 1
        c["last"] = now

    def _add_net(self, rec):
        b = rec["bssid"]
        hidden = (rec["st"] == BEACON) and (not rec["ssid"])
        pwn = (b == device_id.PWNAGOTCHI_BSSID)  # pwnagotchi advertisement beacon
        n = self.networks.get(b)
        if n is None:
            self.networks[b] = {
                "bssid": b, "ssid": rec["ssid"], "hidden": hidden,
                "freq": rec["freq"],
                "rssi": rec["rssi"] if rec["rssi"] is not None else -99,
                "priv": rec["priv"], "pwn": pwn,
                "has_ht": rec["has_ht"], "has_vht": rec["has_vht"],
                "has_he": rec["has_he"], "streams": rec["streams"],
                "wps_name": rec["wps_name"], "wps_model": rec["wps_model"],
                "wps_manuf": rec["wps_manuf"], "count": 1}
        else:
            if rec["ssid"]:
                n["ssid"] = rec["ssid"]
                n["hidden"] = False
            elif hidden and not n["ssid"]:
                n["hidden"] = True
            if rec["freq"]:
                n["freq"] = rec["freq"]
            if rec["rssi"] is not None:
                n["rssi"] = rec["rssi"]
            n["priv"] = rec["priv"] or n["priv"]
            # WPS strings are stable per device - keep the first non-empty seen
            for k in ("wps_name", "wps_model", "wps_manuf"):
                if rec[k] and not n.get(k):
                    n[k] = rec[k]
            # capability IEs: OR presence, keep the highest stream count seen
            for k in ("has_ht", "has_vht", "has_he"):
                n[k] = n.get(k, False) or rec[k]
            n["streams"] = max(n.get("streams", 1), rec["streams"])
            n["count"] += 1

    @staticmethod
    def _trim(dq, now, window):
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def network_rows(self):
        return sorted(self.networks.values(), key=lambda r: r["rssi"], reverse=True)

    def client_rows(self):
        return sorted(self.clients.values(), key=lambda r: r["rssi"], reverse=True)

    def channel_activity(self, now=None, window=6.0):
        """Snapshot of recent frame counts per frequency, for adaptive hopping.

        Returns {freq: count} over the trailing `window` seconds. Called on the
        capture-draining thread; hands the Hopper a fresh plain dict."""
        now = time.time() if now is None else now
        out = {}
        for freq, dq in self.freq_ts.items():
            self._trim(dq, now, window)
            if dq:
                out[freq] = len(dq)
        return out

    def device_rows(self):
        """Networks collapsed into physical devices: BSSIDs sharing the first
        five MAC octets (one radio's block) become one row. Strongest first."""
        groups = {}
        for n in self.networks.values():
            key = device_id.base_mac_key(n["bssid"]) or n["bssid"]
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "base": key, "bssids": set(), "ssids": set(),
                    "rssi": -99, "freq": n["freq"], "priv": n["priv"],
                    "pwn": False, "count": 0, "has_ht": False,
                    "has_vht": False, "has_he": False, "streams": 1,
                    "wps_name": "", "wps_model": "", "wps_manuf": "",
                    "_best": -99}
            g["bssids"].add(n["bssid"])
            if n["ssid"]:
                g["ssids"].add(n["ssid"])
            g["count"] += n["count"]
            g["pwn"] = g["pwn"] or n.get("pwn", False)
            g["priv"] = n["priv"] or g["priv"]
            for k in ("has_ht", "has_vht", "has_he"):
                g[k] = g[k] or n.get(k, False)
            g["streams"] = max(g["streams"], n.get("streams", 1))
            for k in ("wps_name", "wps_model", "wps_manuf"):
                if n.get(k) and not g[k]:
                    g[k] = n[k]
            if n["rssi"] > g["_best"]:          # follow the strongest member
                g["_best"] = g["rssi"] = n["rssi"]
                g["freq"] = n["freq"]
                g["primary_ssid"] = n["ssid"]
                g["strong_bssid"] = n["bssid"]
        for g in groups.values():
            g["n_bssids"] = len(g["bssids"])
        return sorted(groups.values(), key=lambda r: r["rssi"], reverse=True)

    def _attribs(self, freq, src, st, now):
        """attribute() is expensive and flood_rows() is called every render
        tick (twice, in TRACK MAC mode) - cache it for 1 s, like hunt()
        already does for its own attribution line."""
        hit = self._attrib_cache.get((freq, src, st))
        if hit and now - hit[0] < 1.0:
            return hit[1]
        attrs = attribution.attribute(freq, src, st, self.tracks)
        self._attrib_cache[(freq, src, st)] = (now, attrs)
        return attrs

    def flood_rows(self, now=None, rate_threshold=2.0):
        """Rows for the MGMT FLOODS view: an 'all floods on ch N' row per
        active channel, plus a per-source row - or one row per RSSI cluster
        when a spoofed source turns out to be several radios - hottest
        channel first."""
        now = time.time() if now is None else now
        self.tracks.evict(now)
        w = self.flood_window
        chan_rate = {}
        for freq, dq in self.chan_ts.items():
            self._trim(dq, now, w)
            if dq:
                chan_rate[freq] = len(dq) / w
        rows = []
        for freq, rate in chan_rate.items():
            rows.append({"kind": "all", "freq": freq, "src": None, "st": None,
                         "type": "", "rate": rate, "rssi": None,
                         "flood": rate >= rate_threshold, "attrib": None})
        for (freq, src, st), dq in self.deauth_ts.items():
            self._trim(dq, now, w)
            if not dq:
                continue
            rate = len(dq) / w
            flood = rate >= rate_threshold
            base = {"kind": "src", "freq": freq, "src": src, "st": st,
                    "type": attribution.TYPE_NAMES.get(st, str(st)), "flood": flood}
            attrs = self._attribs(freq, src, st, now)
            if not attrs:
                rows.append({**base, "rate": rate,
                             "rssi": self.deauth_rssi.get((freq, src, st)),
                             "attrib": None})
                continue
            total = sum(a.samples for a in attrs) or 1
            for a in attrs:
                rows.append({**base, "rate": rate * a.samples / total,
                             "rssi": int(round(a.rssi_mean)), "attrib": a})
        rows.sort(key=lambda r: (-chan_rate.get(r["freq"], 0.0), r["freq"],
                                 0 if r["kind"] == "all" else 1, -r["rate"]))
        return rows


# ==========================================================================
# Passive device identity (feature slice 1+2+3): vendor + device guess, shown
# as two columns in the lists and folded into the hunt header.
# ==========================================================================

def vendor_cell(mac, oui):
    """VENDOR column: 'rnd' for a randomized MAC, the OUI vendor, or '·'."""
    if device_id.is_randomized(mac):
        return "rnd"
    return device_id.short_vendor(device_id.vendor_for(mac, oui)) or "·"


def device_cell(mac, oui, net=None, role=""):
    """DEVICE column: WPS model/name > device-maker OUI > role > rnd, or '·'."""
    net = net or {}
    return device_id.device_guess(
        mac, oui, net.get("wps_name", ""), net.get("wps_model", ""),
        net.get("wps_manuf", ""), role) or "·"


def device_or_badge(mac, oui, net=None, role="", is_flood=False, is_pwn=False):
    """DEVICE column: a threat badge (pwnagotchi/deauther) if one applies,
    otherwise the plain device guess."""
    return device_id.deauther_badge(mac, oui, is_flood, is_pwn) \
        or device_cell(mac, oui, net, role)


def phy_cell(rec):
    """PHY-capability fingerprint from a network/client record (or '')."""
    rec = rec or {}
    return device_id.phy_fingerprint(
        rec.get("freq"), rec.get("has_ht", False), rec.get("has_vht", False),
        rec.get("has_he", False), rec.get("streams", 1))


def identity_str(mac, oui, net=None, role="", is_flood=False, is_pwn=False):
    """One-line 'Vendor · guess/badge · phy' identity for the hunt header (or '')."""
    vend = "rnd-MAC" if device_id.is_randomized(mac) else \
        device_id.short_vendor(device_id.vendor_for(mac, oui))
    guess = device_or_badge(mac, oui, net, role, is_flood, is_pwn)
    if guess == "·":
        guess = ""
    phy = phy_cell(net)
    seen, out = set(), []
    for p in (vend, guess, phy):
        if p and p not in seen:
            out.append(p)
            seen.add(p)
    return " · ".join(out)


# ==========================================================================
# MGMT FLOODS rendering (module-level so it is testable without curses)
# ==========================================================================

FLOOD_HEADER = (f"    {'GHz':>6} {'ch':>3}  {'TYPE':<8} {'SOURCE':<17} "
                f"{'DEVICE':<14} {'f/s':>6} {'RSSI':>5}  LIKELY SOURCE")


def format_flood_row(r, oui, f2c):
    """One MGMT FLOODS line. VENDOR is folded into DEVICE here (a spoofed
    source has none), which pays for the LIKELY SOURCE column."""
    flag = "⚑" if r["flood"] else " "
    if r["kind"] == "all":
        who, dev, rssi, likely = "ALL floods on ch", "", "   -", attribution.MARK_NA
    else:
        who = r["src"]
        dev = device_or_badge(r["src"], oui, role="attacker", is_flood=r["flood"])
        rssi = f"{r['rssi']:>5}" if r["rssi"] is not None else "   -"
        likely = attribution.short_label(r["attrib"]) if r["attrib"] else attribution.MARK_NA
    return (f"{flag} {fmt_ghz(r['freq']):>6} {f2c.get(r['freq'], '?'):>3}  "
            f"{r['type']:<8.8} {who:<17.17} {dev:<14.14} "
            f"{r['rate']:>6.1f} {rssi:>5}  {likely}")


def resolve_target(t, f2c):
    """Map a selection-screen target dict to
    (display_filter, label, freq, chan, attrib_ctx).

    attrib_ctx is the hunt screen's attribution context - the scan screen's
    tracks, the MACs the meter follows (None = every deauth/disassoc), the
    channel and the source - or None for a network hunt, where the target *is*
    the beacons and attribution is meaningless. When there is a context the
    filter also passes beacons so the attribution keeps learning while parked."""
    freq = t["freq"]
    chan = f2c.get(freq, 0)
    band = fmt_ghz(freq)
    ident = t.get("ident", "")
    who = f" [{ident}]" if ident else ""
    tail = f"(ch{chan} · {band})"
    tracks = t.get("tracks")
    wb = tracks is not None
    ctx = None
    if t["kind"] == "net":
        dfilter, lbl = build_target_filter(bssids=t["bssids"])
        label = f"{lbl}{who}  {tail}"
    elif t["kind"] == "flood_src":
        dfilter, _ = build_target_filter(sa=t["src"], with_beacons=wb)
        label = f"deauth src {t['src']}{who}  {tail}"
        if wb:
            ctx = {"tracks": tracks, "target": {t["src"]}, "freq": freq, "sa": t["src"]}
    elif t["kind"] == "flood_all":
        dfilter = f"wlan.fc.type_subtype=={DEAUTH} || wlan.fc.type_subtype=={DISASSOC}"
        if wb:
            dfilter = f"({dfilter}) || wlan.fc.type_subtype=={BEACON}"
            ctx = {"tracks": tracks, "target": None, "freq": freq, "sa": None}
        label = f"ALL floods  {tail}"
    elif t["kind"] == "mac":
        dfilter, _ = build_target_filter(sa=t["mac"], with_beacons=wb)
        label = f"MAC {t['mac']}{who}  {tail}"
        if wb:
            ctx = {"tracks": tracks, "target": {t["mac"]}, "freq": freq, "sa": t["mac"]}
    else:
        raise ValueError(f"unknown target kind {t['kind']!r}")
    return dfilter, label, freq, chan, ctx


# ==========================================================================
# Tri-mode selection screen
# ==========================================================================

MODE_NET, MODE_FLOOD, MODE_PROBE, MODE_MAC = 0, 1, 2, 3
MODE_NAMES = ["NETWORKS", "MGMT FLOODS", "PROBE CLIENTS", "TRACK MAC"]
N_MODES = len(MODE_NAMES)
MAC_CHARS = set("0123456789abcdefABCDEF:")


def select_screen(stdscr, iface, cap, hopper, f2c, txguard, oui, args):
    """Returns a target dict (see resolve_target) or None if the user quit."""
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(150)
    init_gradient()
    agg = Aggregator(flood_window=args.flood_window)

    mode = MODE_NET
    cur_net = cur_flood = cur_probe = 0
    grouped = True             # NETWORKS: collapse one radio's BSSIDs into a device row
    selected = set()
    mac_input = ""
    mac_error = ""
    locating = None            # MAC we are hopping to find, or None

    while True:
        now = time.time()
        for _ in range(4000):
            try:
                agg.add(cap.q.get_nowait(), now)
            except Exception:
                break

        # feed the hopper the latest per-channel activity for adaptive weighting
        hopper.set_activity(agg.channel_activity(now))

        # auto-locate: as soon as the typed MAC is heard, hunt it
        if locating and locating in agg.seen_ch:
            return {"kind": "mac", "mac": locating, "freq": agg.seen_ch[locating],
                    "ident": identity_str(locating, oui), "tracks": agg.tracks}

        stdscr.erase()
        h, w = stdscr.getmaxyx()
        cur = hopper.current
        curlbl = f"ch{cur[0]} {fmt_ghz(cur[1])}" if cur else "-"
        hopmode = "adaptive" if hopper.adaptive else "uniform"
        stdscr.addnstr(0, 0, f"SNIFFER · mode: {MODE_NAMES[mode]}   "
                       f"hopping {curlbl} ({hopmode})   [S] switch mode  [q] quit",
                       w - 1, curses.A_BOLD)

        # progress bar (gradient) for the channel sweep
        total = hopper.total or 1
        frac = hopper.idx / total
        bar_w = max(10, min(w - 40, 40))
        tail = (f"{hopper.idx}/{total} ch  ✓ {hopper.passes} sweep(s)"
                if hopper.passes else f"{hopper.idx}/{total} ch  (first sweep...)")
        stdscr.addnstr(1, 0, "scan [", w - 1, curses.A_DIM)
        draw_gradient_bar(stdscr, 1, 6, frac, bar_w)
        stdscr.addnstr(1, 6 + bar_w, f"] {tail}", w - 1, curses.A_DIM)

        if mode == MODE_NET:
            view = "devices" if grouped else "SSIDs"
            stdscr.addnstr(3, 0, "UP/DOWN move  SPACE select  ENTER hunt  "
                           f"[g] view: {view}  ({len(selected)} selected)",
                           w - 1, curses.A_DIM)
            colname = "DEVICE (BSSID)" if grouped else "BSSID"
            hdr = (f"  {'SSID':<16} {colname:<17} {'ch':>3} {'GHz':>6} "
                   f"{'RSSI':>5} {'enc':>4} {'VENDOR':<12} {'DEVICE':<14} "
                   f"{'seen':>5}")
            stdscr.addnstr(4, 0, hdr, w - 1, curses.A_UNDERLINE)
            if grouped:
                rows = agg.device_rows()
                cur_net = max(0, min(cur_net, len(rows) - 1)) if rows else 0

                def dev_line(r):
                    name = r.get("primary_ssid") or "<hidden>"
                    if r["n_bssids"] > 1:
                        name = f"{name} +{r['n_bssids'] - 1}"
                    mark = ("x" if r["bssids"] <= selected
                            else "~" if r["bssids"] & selected else " ")
                    b = r["strong_bssid"]
                    return (f"[{mark}] {name:<16.16} {r['base'] + ':**':<17} "
                            f"{f2c.get(r['freq'],'?'):>3} {fmt_ghz(r['freq']):>6} "
                            f"{r['rssi']:>5} "
                            f"{'wpa' if r['priv']=='1' else 'open':>4} "
                            f"{vendor_cell(b, oui):<12.12} "
                            f"{device_or_badge(b, oui, r, role='ap', is_pwn=r['pwn']):<14.14} "
                            f"{r['count']:>5}")
                _draw_list(stdscr, 5, h - 6, rows, cur_net, dev_line,
                           dim=lambda r: not r["ssids"], w=w)
            else:
                rows = agg.network_rows()
                cur_net = max(0, min(cur_net, len(rows) - 1)) if rows else 0
                _draw_list(stdscr, 5, h - 6, rows, cur_net,
                           lambda r: (f"[{'x' if r['bssid'] in selected else ' '}] "
                                      f"{ssid_display(r):<16.16} {r['bssid']:<17} "
                                      f"{f2c.get(r['freq'],'?'):>3} {fmt_ghz(r['freq']):>6} "
                                      f"{r['rssi']:>5} "
                                      f"{'wpa' if r['priv']=='1' else 'open':>4} "
                                      f"{vendor_cell(r['bssid'], oui):<12.12} "
                                      f"{device_or_badge(r['bssid'], oui, r, role='ap', is_pwn=r.get('pwn', False)):<14.14} "
                                      f"{r['count']:>5}"),
                           dim=lambda r: r["hidden"], w=w)

        elif mode == MODE_FLOOD:
            rows = agg.flood_rows(now, args.rate)
            cur_flood = max(0, min(cur_flood, len(rows) - 1)) if rows else 0
            stdscr.addnstr(3, 0, "UP/DOWN move  ENTER hunt  (⚑ = flood; 'all' row "
                           "tracks every deauth/disassoc on that ch; "
                           "✓ ? ✗ = attribution confidence)",
                           w - 1, curses.A_DIM)
            stdscr.addnstr(4, 0, FLOOD_HEADER, w - 1, curses.A_UNDERLINE)
            _draw_list(stdscr, 5, h - 6, rows, cur_flood,
                       lambda r: format_flood_row(r, oui, f2c),
                       dim=lambda r: not r["flood"], w=w)

        elif mode == MODE_PROBE:
            rows = agg.client_rows()
            cur_probe = max(0, min(cur_probe, len(rows) - 1)) if rows else 0
            stdscr.addnstr(3, 0, "UP/DOWN move  ENTER hunt this client  "
                           "(PROBES = networks it's looking for)",
                           w - 1, curses.A_DIM)
            hdr = (f"  {'CLIENT MAC':<17} {'GHz':>6} {'RSSI':>5} "
                   f"{'VENDOR':<12} {'PHY':<11} {'#':>4}  "
                   f"{'PROBES (searched-for SSIDs)'}")
            stdscr.addnstr(4, 0, hdr, w - 1, curses.A_UNDERLINE)

            def client_line(r):
                probes = ", ".join(sorted(r["ssids"])) if r["ssids"] else "—"
                return (f"  {r['mac']:<17} {fmt_ghz(r['freq']):>6} {r['rssi']:>5} "
                        f"{vendor_cell(r['mac'], oui):<12.12} "
                        f"{(phy_cell(r) or '—'):<11.11} {r['count']:>4}  "
                        f"{probes}")
            _draw_list(stdscr, 5, h - 6, rows, cur_probe, client_line,
                       dim=lambda r: not r["ssids"], w=w)

        else:  # MODE_MAC
            if locating:
                cl = f"ch{cur[0]} {fmt_ghz(cur[1])}" if cur else "-"
                stdscr.addnstr(3, 2, f"locating {locating} ...", w - 1, curses.A_BOLD)
                stdscr.addnstr(4, 2, f"hopping {cl}, listening for it to transmit",
                               w - 1, curses.A_DIM)
                stdscr.addnstr(6, 2, "[ESC] cancel", w - 1, curses.A_DIM)
            else:
                stdscr.addnstr(3, 2, "Type the MAC to track, then ENTER:",
                               w - 1, curses.A_NORMAL)
                stdscr.addnstr(4, 2, f"  MAC: {mac_input}▏", w - 1, curses.A_BOLD)
                stdscr.addnstr(5, 2, "  (it will be auto-located by hopping, then "
                               "tracked as a transmitter)", w - 1, curses.A_DIM)
                if mac_error:
                    stdscr.addnstr(7, 2, mac_error, w - 1, curses.A_BOLD)
                m = mac_input.strip().lower()
                if valid_mac(m):
                    hits = [r for r in agg.flood_rows(now, args.rate)
                            if r["kind"] == "src" and r["src"] == m and r["attrib"]]
                    for i, r in enumerate(hits[:3]):
                        stdscr.addnstr(9 + i, 2,
                                       f"flooding on ch{f2c.get(r['freq'], '?')}: "
                                       f"{attribution.short_label(r['attrib'])}",
                                       w - 3, curses.A_BOLD)

        if cap.error:
            stdscr.addnstr(h - 1, 0, f"capture error: {cap.error}", w - 1, curses.A_BOLD)
        else:
            txguard.poll()
            stdscr.addnstr(h - 1, 0, txguard.label(), w - 1, curses.A_DIM)
        stdscr.refresh()

        c = stdscr.getch()
        if c == -1:
            continue

        # ESC cancels an in-progress locate regardless of mode
        if c == 27 and locating:
            locating = None
            continue

        if mode == MODE_MAC and not locating:
            # text entry
            if c in (curses.KEY_ENTER, 10, 13):
                m = mac_input.strip().lower()
                if not valid_mac(m):
                    mac_error = f"not a valid MAC: {mac_input!r}"
                elif m in agg.seen_ch:
                    return {"kind": "mac", "mac": m, "freq": agg.seen_ch[m],
                            "ident": identity_str(m, oui), "tracks": agg.tracks}
                else:
                    locating = m
                    mac_error = ""
            elif c in (curses.KEY_BACKSPACE, 127, 8):
                mac_input = mac_input[:-1]
            elif c == ord("S") or c == ord("s"):
                mode = (mode + 1) % N_MODES
            elif 0 <= c < 256 and chr(c) in MAC_CHARS:
                if len(mac_input) < 17:
                    mac_input += chr(c)
            continue

        if c in (ord("q"), 27):
            return None
        if c in (ord("S"), ord("s")):
            mode = (mode + 1) % N_MODES
        elif c in (ord("g"), ord("G")) and mode == MODE_NET:
            grouped = not grouped
            cur_net = 0
        elif c in (curses.KEY_DOWN, ord("j")):
            if mode == MODE_NET:
                cur_net += 1
            elif mode == MODE_FLOOD:
                cur_flood += 1
            elif mode == MODE_PROBE:
                cur_probe += 1
        elif c in (curses.KEY_UP, ord("k")):
            if mode == MODE_NET:
                cur_net = max(0, cur_net - 1)
            elif mode == MODE_FLOOD:
                cur_flood = max(0, cur_flood - 1)
            elif mode == MODE_PROBE:
                cur_probe = max(0, cur_probe - 1)
        elif c == ord(" ") and mode == MODE_NET:
            if grouped:
                rows = agg.device_rows()
                if rows:
                    members = rows[cur_net]["bssids"]
                    # deselect the whole device if fully selected, else select it
                    if members <= selected:
                        selected.difference_update(members)
                    else:
                        selected.update(members)
            else:
                rows = agg.network_rows()
                if rows:
                    selected.symmetric_difference_update({rows[cur_net]["bssid"]})
        elif c in (curses.KEY_ENTER, 10, 13):
            if mode == MODE_NET:
                rows = agg.network_rows()   # hunt always works on real BSSIDs
                if not rows:
                    continue
                if selected:
                    targets = set(selected)
                elif grouped:
                    devs = agg.device_rows()
                    targets = devs[cur_net]["bssids"] if devs else set()
                else:
                    targets = {rows[cur_net]["bssid"]}
                chosen = [r for r in rows if r["bssid"] in targets]
                if not chosen:
                    continue
                chosen.sort(key=lambda r: r["rssi"], reverse=True)
                strongest = chosen[0]
                return {"kind": "net",
                        "bssids": {r["bssid"] for r in chosen},
                        "freq": strongest["freq"],
                        "ident": identity_str(strongest["bssid"], oui,
                                              strongest, role="ap",
                                              is_pwn=strongest.get("pwn", False))}
            elif mode == MODE_FLOOD:
                rows = agg.flood_rows(now, args.rate)
                if not rows:
                    continue
                r = rows[cur_flood]
                if r["kind"] == "all":
                    return {"kind": "flood_all", "freq": r["freq"], "tracks": agg.tracks}
                return {"kind": "flood_src", "src": r["src"], "freq": r["freq"],
                        "ident": identity_str(r["src"], oui, role="attacker",
                                              is_flood=r["flood"]),
                        "tracks": agg.tracks}
            elif mode == MODE_PROBE:
                rows = agg.client_rows()
                if not rows:
                    continue
                r = rows[cur_probe]
                return {"kind": "mac", "mac": r["mac"], "freq": r["freq"],
                        "ident": identity_str(r["mac"], oui, net=r, role="client"),
                        "tracks": agg.tracks}


def _draw_list(stdscr, top, maxrows, rows, cursor, line_fn, dim, w):
    maxrows = max(1, maxrows)
    start = max(0, cursor - maxrows + 1)
    for i, r in enumerate(rows[start:start + maxrows]):
        idx = start + i
        attr = curses.A_REVERSE if idx == cursor else curses.A_NORMAL
        if dim(r):
            attr |= curses.A_DIM
        try:
            stdscr.addnstr(top + i, 0, line_fn(r), w - 1, attr)
        except curses.error:
            pass


# ==========================================================================
# Main
# ==========================================================================

def main():
    print("ANTENNA: use 2 omni antennas (or at least 1 dual-band omni) to scan "
          "networks/floods across all directions and both bands; then swap to 1 "
          "directional antenna (one jack, other empty) for the closing-in hunt, "
          "since an omni smears the RSSI bearing.", file=sys.stderr)

    p = argparse.ArgumentParser(
        description="All-in-one WiFi DF: pick a network, a deauth flood, or a MAC, then hunt it.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--iface", help="monitor-mode interface (auto-detects mt7921u)")
    p.add_argument("--band", choices=["2.4", "5", "both"], default="both",
                   help="bands to hop while scanning")
    p.add_argument("--dwell", type=float, default=1.2,
                   help="base seconds per channel while scanning")
    p.add_argument("--adaptive", action=argparse.BooleanOptionalAction, default=True,
                   help="weight dwell toward active channels (--no-adaptive for "
                        "uniform hopping)")
    p.add_argument("--min-dwell", type=float, default=0.3,
                   help="shortest dwell for a silent channel (adaptive)")
    p.add_argument("--max-dwell", type=float, default=3.0,
                   help="longest dwell for a flooded channel (adaptive)")
    p.add_argument("--rate", type=float, default=2.0,
                   help="deauths/sec above which a channel is flagged as a flood")
    p.add_argument("--flood-window", type=float, default=5.0,
                   help="rolling window for the deauth rate (s)")
    p.add_argument("--window", type=float, default=2.5, help="hunt rolling average (s)")
    p.add_argument("--beep-window", type=float, default=10.0, help="trend window for beeps (s)")
    p.add_argument("--beep-threshold", type=float, default=1.0,
                   help="dB of smoothed change that triggers a beep")
    p.add_argument("--beep-interval", type=float, default=1.5, help="min seconds between beeps")
    p.add_argument("--geiger", action="store_true",
                   help="continuous rate/pitch-coded beeps instead of up/down")
    p.add_argument("--no-beep", action="store_true", help="disable audio feedback")
    p.add_argument("--test-beep", action="store_true",
                   help="play the warmer/colder/geiger cues and exit (no radio)")
    args = p.parse_args()

    if args.test_beep:
        b = Beeper()
        who = "root->user audio" if b._env else "current user"
        print(f"audio backend: {b.name}  ({who})")
        b.beep(1, freq=1200); time.sleep(0.9)
        b.beep(2, freq=500); time.sleep(1.1)
        for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
            b.beep(1, freq=500 + 1500 * frac, dur=0.06); time.sleep(0.35)
        time.sleep(0.6)
        print("done.")
        return

    if os.geteuid() != 0:
        print("! not root - channel hopping/tuning will fail. Re-run with sudo.",
              file=sys.stderr)

    iface = args.iface or detect_iface()
    if not iface:
        sys.exit("No mt7921u interface found. Run 'sudo ./init-hunt.sh' or pass --iface.")
    if not os.path.exists(f"/sys/class/net/{iface}"):
        sys.exit(f"interface '{iface}' does not exist")
    mode = iface_mode(iface)
    if mode and mode != "monitor":
        sys.exit(f"{iface} is in '{mode}' mode, not monitor. Run: sudo ./init-hunt.sh")
    phy = iface_phy(iface)
    if not phy:
        sys.exit(f"could not find the phy for {iface}")
    chans = list_channels(phy, want_24=args.band in ("2.4", "both"),
                          want_5=args.band in ("5", "both"))
    if not chans:
        sys.exit("no usable channels in the current regulatory domain")
    f2c = freq_to_chan_map(chans)
    txguard = TxGuard(iface)

    # One-time OUI load for vendor/device identification (empty map if absent).
    oui = device_id.load_oui()
    if not oui:
        print("! no IEEE OUI database found (install 'ieee-data' for vendor "
              "names); VENDOR/DEVICE columns will be sparse.", file=sys.stderr)

    # Top-level loop: scan+select, hunt, return to scan.
    while True:
        cap = CaptureThread(iface, COMBINED_FILTER, COMBINED_FIELDS, parse_combined)
        hopper = Hopper(iface, chans, args.dwell, adaptive=args.adaptive,
                        min_dwell=args.min_dwell, max_dwell=args.max_dwell)
        cap.start()
        hopper.start()
        try:
            target = curses.wrapper(select_screen, iface, cap, hopper, f2c, txguard, oui, args)
        finally:
            hopper.stop()
            cap.stop()
        if not target:
            print("done.")
            return

        dfilter, label, freq, chan, attrib = resolve_target(target, f2c)
        if freq:
            set_channel(iface, chan or 0, freq)
        hcap = CaptureThread(iface, dfilter, HUNT_FIELDS, parse_hunt)
        hcap.start()
        directional_reminder()
        try:
            curses.wrapper(hunt, iface, label, hcap, txguard, args, attrib)
        finally:
            hcap.stop()
        # loop back to a fresh scan/select screen


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        main()
    except KeyboardInterrupt:
        pass
