#!/usr/bin/env python3
"""
deauth_sweep.py - band sweeper that finds which channel a deauth flood is on.

Companion to deauth_hunt.py. Before you can direction-find an 802.11
deauthentication attack you have to know which channel it is on. This walks
every 2.4 GHz and 5 GHz channel the radio supports, dwells on each for a few
seconds, counts the deauth (and disassoc) frames it hears, and prints a table
of where the flood is - so you can park the card there and start the hunt.

RECEIVE-ONLY, exactly like the rest of this toolkit. It shells out to tshark
(a libpcap capture handle) and to `iw ... set channel/freq` to retune. Neither
injects, deauthenticates, probes, associates, beacons or ACKs. The interface's
tx_packets counter is read before and after the whole sweep and reported as
proof that nothing was transmitted - a deauth hunt must never become a source.

Changing channel needs CAP_NET_ADMIN, so run this with sudo. Put the card in
monitor mode first with:  sudo ./init-hunt.sh
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from collections import Counter, defaultdict

# The known attacker signature from deauth_hunt.py: a broadcast source with the
# I/G bit cleared. When we see this exact source flooding a channel, that is
# almost certainly the same emitter and worth calling out by name.
KNOWN_SA = "fe:ff:ff:ff:ff:ff"

# Deauthentication is management subtype 12; disassociation is subtype 10. Both
# are used for deauth-style denial of service, so we count and report both but
# headline the deauths.
SUBTYPE_DEAUTH = 12
SUBTYPE_DISASSOC = 10
CAP_FILTER = f"wlan.fc.type_subtype=={SUBTYPE_DEAUTH} || wlan.fc.type_subtype=={SUBTYPE_DISASSOC}"

FIELDS = [
    "frame.time_epoch",
    "wlan.fc.type_subtype",
    "wlan.sa",
    "wlan.da",
    "wlan.fixed.reason_code",
    "radiotap.channel.freq",
    "radiotap.dbm_antsignal",
]

# ANSI, only when writing to a real terminal.
if sys.stdout.isatty():
    RED, GRN, YLW, CYN, DIM, BLD, RST = (
        "\033[31m", "\033[32m", "\033[33m", "\033[36m",
        "\033[2m", "\033[1m", "\033[0m")
else:
    RED = GRN = YLW = CYN = DIM = BLD = RST = ""


# ==========================================================================
# Interface / radio plumbing (mirrors init-hunt.sh and deauth_hunt.py)
# ==========================================================================

def _wifi_ifaces():
    """Every wireless interface (those with an 802.11 phy), name-sorted."""
    base = "/sys/class/net"
    try:
        names = os.listdir(base)
    except OSError:
        return []
    return [n for n in sorted(names)
            if os.path.exists(os.path.join(base, n, "phy80211"))]


def iface_driver(iface):
    """Kernel driver bound to the interface, or None."""
    link = f"/sys/class/net/{iface}/device/driver"
    try:
        if os.path.exists(link):
            return os.path.basename(os.path.realpath(link))
    except OSError:
        pass
    return None


def iface_is_usb(iface):
    """True if the interface is a USB device (a plug-in adapter)."""
    try:
        return "/usb" in os.path.realpath(f"/sys/class/net/{iface}/device")
    except OSError:
        return False


def iface_connected(iface):
    """True if the interface is currently associated with an AP.

    A card carrying a live Wi-Fi link is the operator's normal connection, not
    the spare we want to commandeer for monitor mode.
    """
    try:
        out = subprocess.run(["iw", "dev", iface, "link"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return False
    return "Connected to" in out


def detect_iface():
    """Pick the interface to hunt with, chip-agnostically.

    Order of preference:
      1. $HUNT_IFACE, if it names an existing interface.
      2. An interface bound to $HUNT_DRIVER, if that env var is set (lets you
         pin a specific adapter by driver, e.g. the old mt7921u default).
      3. A wireless interface not currently associated to an AP - i.e. the
         spare adapter dedicated to the hunt rather than the one carrying the
         operator's Wi-Fi. Among candidates, one already in monitor mode wins,
         then a USB adapter, then name order.

    Only falls back to a connected interface if it is the sole radio present.
    """
    forced = os.environ.get("HUNT_IFACE")
    if forced and os.path.exists(f"/sys/class/net/{forced}"):
        return forced

    ifaces = _wifi_ifaces()
    if not ifaces:
        return None

    drv = os.environ.get("HUNT_DRIVER")
    if drv:
        # An explicit pin is strict: match it or fail, never a different card.
        for name in ifaces:
            if iface_driver(name) == drv:
                return name
        return None

    free = [n for n in ifaces if not iface_connected(n)]
    pool = free or ifaces

    def rank(n):
        return (
            0 if iface_mode(n) == "monitor" else 1,
            0 if iface_is_usb(n) else 1,
            n,
        )

    return sorted(pool, key=rank)[0]


def iface_phy(iface):
    try:
        return os.path.basename(os.path.realpath(f"/sys/class/net/{iface}/phy80211"))
    except OSError:
        return None


def iface_mode(iface):
    try:
        out = subprocess.run(["iw", "dev", iface, "info"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        if line.strip().startswith("type "):
            return line.split()[1]
    return ""


def read_tx_packets(iface):
    try:
        with open(f"/sys/class/net/{iface}/statistics/tx_packets") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def list_channels(phy, want_24=True, want_5=True):
    """Parse `iw phy <phy> info` for usable channels.

    Returns a list of (channel_number, freq_mhz, band_label), skipping any
    frequency the regulatory domain marks 'disabled' (we cannot even receive on
    those). DFS / 'no IR' channels are kept - we never transmit, so receiving on
    them is fine.
    """
    try:
        out = subprocess.run(["iw", "phy", phy, "info"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        sys.exit(f"could not read channel list from iw: {e}")

    # e.g. "* 2412.0 MHz [1] (20.0 dBm)"  /  "* 5600.0 MHz [120] (disabled)"
    pat = re.compile(r"\*\s+(\d+)(?:\.\d+)?\s+MHz\s+\[(\d+)\]\s*(.*)")
    chans = []
    seen = set()
    for line in out.splitlines():
        m = pat.search(line)
        if not m:
            continue
        freq = int(m.group(1))
        chan = int(m.group(2))
        flags = m.group(3).lower()
        if "disabled" in flags:
            continue
        if 2400 <= freq < 2500:
            band = "2.4"
            if not want_24:
                continue
        elif 5000 <= freq < 5900:
            band = "5"
            if not want_5:
                continue
        else:
            continue  # ignore 6 GHz / anything exotic
        if chan in seen:
            continue
        seen.add(chan)
        chans.append((chan, freq, band))
    chans.sort(key=lambda c: c[1])
    return chans


def set_channel(iface, chan, freq):
    """Tune the radio. Try channel form, fall back to freq form (as init-hunt.sh
    does). Returns True on success."""
    for cmd in (["iw", "dev", iface, "set", "channel", str(chan)],
                ["iw", "dev", iface, "set", "freq", str(freq)]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception:
            continue
        if r.returncode == 0:
            return True
    return False


# ==========================================================================
# Per-channel capture
# ==========================================================================

def capture_channel(iface, secs):
    """Capture deauth/disassoc frames on the current channel for `secs` seconds.

    Returns a list of dicts: {ts, subtype, sa, da, reason, freq, rssi}.
    """
    cmd = ["tshark", "-i", iface, "-l", "-n", "-Q",
           "-a", f"duration:{secs}",
           "-Y", CAP_FILTER,
           "-T", "fields", "-E", "separator=|", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=secs + 8)
    except FileNotFoundError:
        sys.exit("tshark not found - install wireshark/tshark.")
    except subprocess.TimeoutExpired:
        return []

    recs = []
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < len(FIELDS):
            continue
        ts, subtype, sa, da, reason, freq, sig = parts[:7]
        try:
            ts = float(ts)
        except ValueError:
            continue

        def first_int(v):
            for tok in str(v).split(","):
                tok = tok.strip()
                if tok:
                    try:
                        return int(tok, 0) if tok.lower().startswith("0x") else int(tok)
                    except ValueError:
                        return None
            return None

        recs.append({
            "ts": ts,
            "subtype": first_int(subtype),
            "sa": sa.split(",")[0].strip().lower(),
            "da": da.split(",")[0].strip().lower(),
            "reason": first_int(reason),
            "freq": first_int(freq),
            "rssi": first_int(sig),
        })
    return recs


def summarise(chan, freq, band, secs, recs):
    """Reduce raw frames on one channel to a report row."""
    deauth = [r for r in recs if r["subtype"] == SUBTYPE_DEAUTH]
    disassoc = [r for r in recs if r["subtype"] == SUBTYPE_DISASSOC]
    sources = Counter(r["sa"] for r in deauth if r["sa"])
    rssis = [r["rssi"] for r in deauth if r["rssi"] is not None]
    reasons = Counter(r["reason"] for r in deauth if r["reason"] is not None)
    top_sa, top_n = (sources.most_common(1)[0] if sources else ("", 0))
    return {
        "chan": chan, "freq": freq, "band": band,
        "deauth": len(deauth), "disassoc": len(disassoc),
        "rate": len(deauth) / secs if secs else 0.0,
        "top_sa": top_sa, "top_n": top_n,
        "n_sources": len(sources),
        "max_rssi": max(rssis) if rssis else None,
        "signature": sources.get(KNOWN_SA, 0),
        "reasons": reasons,
    }


# ==========================================================================
# Main
# ==========================================================================

def main():
    print("ANTENNA: use 2 omni antennas (or at least 1 dual-band omni) - this "
          "sweeps every direction and both bands to detect a flood from an unknown "
          "source; a directional can miss an off-axis or wrong-band attacker.")
    p = argparse.ArgumentParser(
        description="Sweep 2.4/5 GHz channels and report where deauth attacks are.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--iface", help="monitor-mode interface (default: the spare "
                                    "Wi-Fi card not carrying your connection)")
    p.add_argument("--dwell", type=float, default=3.0,
                   help="seconds to listen on each channel")
    p.add_argument("--rate", type=float, default=2.0,
                   help="deauths/sec above which a channel is flagged as under attack")
    p.add_argument("--passes", type=int, default=1,
                   help="how many full sweeps to run (results are accumulated)")
    p.add_argument("--band", choices=["2.4", "5", "both"], default="both",
                   help="which band(s) to sweep")
    p.add_argument("--only-hits", action="store_true",
                   help="in the final table, show only channels with deauths")
    args = p.parse_args()

    if os.geteuid() != 0:
        print(f"{YLW}! not running as root - `iw set channel` will likely fail. "
              f"Re-run with sudo.{RST}", file=sys.stderr)

    iface = args.iface or detect_iface()
    if not iface:
        sys.exit("No spare wireless interface found. Plug the adapter in and run "
                 "'sudo ./init-hunt.sh' first, or pass --iface (or set $HUNT_IFACE).")
    if not os.path.exists(f"/sys/class/net/{iface}"):
        sys.exit(f"interface '{iface}' does not exist")

    mode = iface_mode(iface)
    if mode and mode != "monitor":
        sys.exit(f"{iface} is in '{mode}' mode, not monitor.\n"
                 f"Run:  sudo ./init-hunt.sh")

    phy = iface_phy(iface)
    if not phy:
        sys.exit(f"could not find the phy for {iface}")

    chans = list_channels(phy, want_24=args.band in ("2.4", "both"),
                          want_5=args.band in ("5", "both"))
    if not chans:
        sys.exit("no usable channels found in the current regulatory domain")

    total_secs = len(chans) * args.dwell * args.passes
    print(f"{BLD}Deauth channel sweep{RST}  "
          f"iface {BLD}{iface}{RST} (phy {phy}), {len(chans)} channels, "
          f"{args.dwell:g}s dwell x {args.passes} pass(es)")
    print(f"{DIM}receive-only: capturing '{CAP_FILTER}', retuning with iw, "
          f"never transmitting. ~{total_secs/60:.1f} min total.{RST}\n")

    tx_before = read_tx_packets(iface)

    # accumulate summaries across passes, keyed by channel number
    acc = {}
    interrupted = False

    def merge(dst, src):
        if dst is None:
            return src
        dst["deauth"] += src["deauth"]
        dst["disassoc"] += src["disassoc"]
        dst["signature"] += src["signature"]
        dst["reasons"].update(src["reasons"])
        if src["max_rssi"] is not None:
            dst["max_rssi"] = (src["max_rssi"] if dst["max_rssi"] is None
                               else max(dst["max_rssi"], src["max_rssi"]))
        # keep the strongest single source seen
        if src["top_n"] > dst["top_n"]:
            dst["top_sa"], dst["top_n"] = src["top_sa"], src["top_n"]
        return dst

    try:
        for p_i in range(1, args.passes + 1):
            for chan, freq, band in chans:
                if not set_channel(iface, chan, freq):
                    print(f"  ch{chan:<3} {freq} MHz  {YLW}skip (could not tune){RST}")
                    continue
                time.sleep(0.15)  # let the radio settle before listening
                recs = capture_channel(iface, args.dwell)
                s = summarise(chan, freq, band, args.dwell, recs)
                acc[chan] = merge(acc.get(chan), s)

                a = acc[chan]
                rate = a["deauth"] / (args.dwell * p_i)
                hit = rate >= args.rate
                sig = a["signature"] > 0
                if sig:
                    tag = f"{RED}{BLD}ATTACK (known sig){RST}"
                elif hit:
                    tag = f"{RED}ATTACK{RST}"
                elif a["deauth"] > 0:
                    tag = f"{YLW}deauths seen{RST}"
                else:
                    tag = f"{DIM}clear{RST}"
                src = f"  src {a['top_sa']} x{a['top_n']}" if a["top_sa"] else ""
                rssi = f"  {a['max_rssi']} dBm" if a["max_rssi"] is not None else ""
                print(f"  ch{chan:<3} {freq} MHz ({band}GHz)  "
                      f"deauth {a['deauth']:4d}  disassoc {a['disassoc']:4d}  "
                      f"{tag}{src}{rssi}")
            if args.passes > 1:
                print(f"{DIM}--- pass {p_i}/{args.passes} done ---{RST}")
    except KeyboardInterrupt:
        interrupted = True
        print(f"\n{YLW}interrupted - reporting what was gathered so far.{RST}")

    tx_after = read_tx_packets(iface)

    # ---------------------------------------------------------------- report
    rows = sorted(acc.values(), key=lambda r: (-r["deauth"], r["freq"]))
    if args.only_hits:
        rows = [r for r in rows if r["deauth"] > 0]

    print(f"\n{BLD}=== Summary (worst first) ==={RST}")
    if not rows:
        print(f"  {GRN}No deauth or disassoc frames on any channel swept.{RST}")
    else:
        print(f"  {'ch':>3} {'freq':>5} {'band':>4} {'deauth':>7} {'/s':>6} "
              f"{'disas':>6} {'srcs':>4} {'top source':>17} {'rssi':>5}  verdict")
        swept_secs = args.dwell * args.passes
        for r in rows:
            rate = r["deauth"] / swept_secs if swept_secs else 0
            if r["signature"] > 0:
                verdict = f"{RED}{BLD}ATTACK - known signature{RST}"
            elif rate >= args.rate:
                verdict = f"{RED}ATTACK{RST}"
            elif r["deauth"] > 0:
                verdict = f"{YLW}some deauths (may be legit){RST}"
            else:
                verdict = f"{DIM}clear{RST}"
            top = f"{r['top_sa']} x{r['top_n']}" if r["top_sa"] else "-"
            rssi = f"{r['max_rssi']}" if r["max_rssi"] is not None else "-"
            print(f"  {r['chan']:>3} {r['freq']:>5} {r['band']:>4} "
                  f"{r['deauth']:>7} {rate:>6.1f} {r['disassoc']:>6} "
                  f"{r['n_sources']:>4} {top:>17} {rssi:>5}  {verdict}")

    # ---------------------------------------------------- passivity proof
    print(f"\n{BLD}TX guard:{RST}", end=" ")
    if tx_before is None or tx_after is None:
        print(f"{DIM}tx_packets counter unavailable{RST}")
    elif tx_after == tx_before:
        print(f"{GRN}0 packets transmitted during the sweep - verifiably passive.{RST}")
    else:
        print(f"{RED}*** interface transmitted {tx_after - tx_before} packets - "
              f"NOT passive, investigate.{RST}")

    # ------------------------------------------------- recommendation
    attacked = [r for r in rows if r["deauth"] > 0
                and (r["signature"] > 0
                     or r["deauth"] / (args.dwell * args.passes) >= args.rate)]
    print(f"\n{BLD}Next step:{RST}")
    if not attacked:
        print("  No channel is under a deauth flood right now. If you expected one,")
        print("  raise --dwell (a bursty flood can fall between short dwells), run")
        print("  more --passes, or you may simply be out of range of the emitter.")
    else:
        best = max(attacked, key=lambda r: (r["signature"], r["deauth"]))
        print(f"  The flood is on {BLD}channel {best['chan']} ({best['freq']} MHz, "
              f"{best['band']} GHz){RST}"
              f"{'  [matches the known attacker signature]' if best['signature'] else ''}.")
        print(f"  Park the card there, then start the direction-finding hunt:\n")
        print(f"    {CYN}sudo iw dev {iface} set freq {best['freq']}{RST}")
        print(f"    {CYN}./deauth_hunt.py --iface {iface} --channel {best['chan']}"
              f"{'' if best['signature'] else ' --any-deauth'}{RST}\n")
        print(f"  Or retune persistently via init-hunt.sh:")
        print(f"    {DIM}sudo HUNT_CHANNEL={best['chan']} HUNT_FREQ={best['freq']} "
              f"./init-hunt.sh{RST}")
        if len(attacked) > 1:
            others = ", ".join(f"ch{r['chan']}" for r in attacked if r is not best)
            print(f"\n  Deauths were also flagged on: {others}")

    return 0 if not interrupted else 130


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    sys.exit(main())
