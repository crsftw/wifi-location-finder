#!/usr/bin/env python3
"""
router_hunt.py - discover WiFi networks (hidden ones included), pick one, and
direction-find the router that transmits it.

Companion to deauth_hunt.py. Where deauth_hunt tracks a known attacker signature,
this one lets you choose any access point you can hear - or any source MAC you
type in - and turns its RSSI into a live warmer/colder meter plus audio cues, so
you can walk it down with a directional antenna without staring at the screen.

Flow:
  1. Discovery: channel-hops 2.4/5 GHz, collecting beacons and probe responses.
     Hidden networks (empty SSID) are listed by BSSID as <hidden>.
  2. Selection: arrow keys move, SPACE toggles a network (select/deselect).
     Selecting several BSSIDs at once tracks them as one signal - handy for a
     router that broadcasts multiple BSSIDs from the same radio.
  3. Hunt: parks on the target's channel and shows a big RSSI readout, rolling
     average, peak-hold and a sparkline. It beeps as you get warmer/colder.

Audio (see the design note in the header of the hunt screen):
  * one short beep  = signal rose  > threshold over the beep window
  * two short beeps = signal fell  > threshold over the beep window
  1 dB of raw RSSI is below the indoor noise floor, so the trend is measured on
  the MEDIAN of a recent sub-window vs an earlier one, with a minimum gap between
  beeps. --geiger gives continuous rate-coded feedback instead.

RECEIVE-ONLY, like the rest of this toolkit: it only captures (tshark) and
retunes (iw set channel/freq). It never injects, deauthenticates, probes,
associates, beacons or ACKs, and the tx_packets counter is shown as proof.

Channel hopping needs CAP_NET_ADMIN, so run with sudo. Put the card in monitor
mode first:  sudo ./init-hunt.sh
"""

import argparse
import curses
import os
import queue
import re
import signal
import statistics
import subprocess
import sys
import threading
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Reuse the vetted helpers rather than reimplementing them.
from deauth_hunt import (big_digits, SPARK, RSSI_FLOOR, RSSI_CEIL, TxGuard,
                         init_gradient, draw_gradient_bar)
from deauth_sweep import (detect_iface, iface_phy, iface_mode,
                          read_tx_packets, list_channels, set_channel)

BEACON = 8
PROBE_RESP = 5


def first_int(v):
    """First integer in a possibly comma-joined, possibly hex tshark field."""
    for tok in str(v).split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            return int(tok, 0) if tok.lower().startswith("0x") else int(tok)
        except ValueError:
            return None
    return None


# ==========================================================================
# Generic capture thread (tshark -> parsed dicts on a queue)
# ==========================================================================

class CaptureThread(threading.Thread):
    daemon = True

    def __init__(self, iface, dfilter, fields, parse):
        super().__init__()
        self.iface = iface
        self.dfilter = dfilter
        self.fields = fields
        self.parse = parse
        self.q = queue.Queue(maxsize=20000)
        self.stop_flag = threading.Event()
        self.proc = None
        self.error = None
        self.lines = 0

    def run(self):
        cmd = ["tshark", "-i", self.iface, "-l", "-n", "-Q",
               "-Y", self.dfilter, "-T", "fields",
               "-E", "separator=|", "-E", "occurrence=a"]
        for f in self.fields:
            cmd += ["-e", f]
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True, bufsize=1)
        except FileNotFoundError:
            self.error = "tshark not found"
            return
        for line in self.proc.stdout:
            if self.stop_flag.is_set():
                break
            self.lines += 1
            rec = self.parse(line.rstrip("\n"))
            if rec is None:
                continue
            try:
                self.q.put_nowait(rec)
            except queue.Full:
                pass
        if self.proc.poll() not in (0, None) and not self.stop_flag.is_set():
            err = (self.proc.stderr.read() or "").strip()
            self.error = err.splitlines()[-1] if err else f"tshark exited {self.proc.poll()}"

    def stop(self):
        self.stop_flag.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass


# ---- discovery: beacons + probe responses ----
# SSID is placed LAST because an SSID may itself contain the '|' separator; we
# reassemble everything after the fixed fields back into the SSID.
DISC_FIELDS = ["wlan.fc.type_subtype", "wlan.bssid",
               "radiotap.channel.freq", "radiotap.dbm_antsignal",
               "wlan.fixed.capabilities.privacy", "wlan.ssid"]
DISC_FILTER = f"wlan.fc.type_subtype=={BEACON} || wlan.fc.type_subtype=={PROBE_RESP}"


def decode_ssid(raw):
    """Turn a tshark wlan.ssid field into readable text.

    tshark 4.x emits the SSID as a hex byte string (e.g. '486f6d654e6574' for
    'HomeNet'), and a zero-length (hidden) SSID as '<MISSING>'. Older builds emit
    the string directly. Decode only when the value is genuinely all-hex so a
    plain-text SSID that happens to look hex-ish is left untouched.
    """
    raw = (raw or "").strip()
    if not raw or raw == "<MISSING>":
        return ""
    if len(raw) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", raw):
        try:
            return bytes.fromhex(raw).decode("utf-8", "replace").rstrip("\x00")
        except ValueError:
            return raw
    return raw


def norm_priv(raw):
    return "1" if (raw or "").strip() in ("1", "True", "true") else "0"


def parse_disc(line):
    parts = line.split("|")
    if len(parts) < len(DISC_FIELDS):
        return None
    st, bssid, freq, sig, priv = parts[:5]
    ssid = decode_ssid("|".join(parts[5:]))  # rejoin any '|' in a text SSID, then decode
    bssid = bssid.split(",")[0].strip().lower()
    if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
        return None
    return {"st": first_int(st), "bssid": bssid, "freq": first_int(freq),
            "rssi": first_int(sig), "priv": norm_priv(priv), "ssid": ssid}


# ---- hunt: frames transmitted BY the target ----
HUNT_FIELDS = ["frame.time_epoch", "wlan.sa", "wlan.ta",
               "radiotap.channel.freq", "radiotap.dbm_antsignal"]


def parse_hunt(line):
    parts = line.split("|")
    if len(parts) < len(HUNT_FIELDS):
        return None
    ts, sa, ta, freq, sig = parts[:5]
    try:
        ts = float(ts)
    except ValueError:
        return None
    rssi = first_int(sig)
    if rssi is None:
        return None
    return {"ts": ts, "rssi": rssi,
            "sa": sa.split(",")[0].strip().lower(),
            "ta": ta.split(",")[0].strip().lower(),
            "freq": first_int(freq)}


# ==========================================================================
# Channel hopper (discovery only)
# ==========================================================================

# ==========================================================================
# Adaptive (weighted) channel hopping
# ==========================================================================
# The receiver can only listen to one channel at a time, so uniform hopping
# gives every channel the same slice regardless of whether anything is there.
# Adaptive hopping keeps visiting *every* channel each sweep (so nothing is
# starved), but scales the dwell to recent activity: a flooded channel gets the
# most time, an active one the base dwell, and a silent one the minimum - which
# shortens sweeps and densifies the frame stream on the channels that matter.

PRIMARY_24 = {1, 6, 11}   # kept warm even when momentarily quiet


def channel_dwell(score, base, lo, hi, priority=False, hot=15):
    """Dwell (seconds) for a channel given its recent activity score.

    Tiers: flood-level activity (score >= hot) -> hi; any activity -> base;
    a quiet 2.4GHz primary -> base (kept warm); otherwise -> lo.
    """
    if score >= hot:
        return hi
    if score > 0:
        return base
    if priority:
        return base
    return lo


def weighted_schedule(chans, activity, base, lo, hi, hot=15):
    """Next sweep as a list of (chan, freq, band, dwell).

    Every channel is included, in the given order (no starvation, bounded
    latency); only the per-channel dwell varies with `activity` (a {freq: count}
    snapshot of frames heard recently).
    """
    sched = []
    for chan, freq, band in chans:
        score = activity.get(freq, 0)
        d = channel_dwell(score, base, lo, hi, priority=chan in PRIMARY_24, hot=hot)
        sched.append((chan, freq, band, d))
    return sched


class Hopper(threading.Thread):
    daemon = True

    def __init__(self, iface, chans, dwell, adaptive=False,
                 min_dwell=0.3, max_dwell=3.0, hot=50):
        super().__init__()
        self.iface = iface
        self.chans = chans
        self.dwell = dwell            # base dwell (also the uniform dwell)
        self.adaptive = adaptive
        self.min_dwell = min(min_dwell, dwell)
        self.max_dwell = max(max_dwell, dwell)
        self.hot = hot
        self._activity = {}           # freq -> recent frame count (set externally)
        self.stop_flag = threading.Event()
        self.current = None
        self.total = len(chans)   # channels in one full sweep of all bands
        self.idx = 0              # 1-based position in the current sweep
        self.passes = 0           # completed full sweeps

    def set_activity(self, activity):
        """Update the per-channel activity snapshot used for weighting.

        Called from the capture-draining loop; a plain dict reference swap is
        the only shared state, so no lock is needed.
        """
        self._activity = activity or {}

    def _sweep(self):
        if self.adaptive:
            return weighted_schedule(self.chans, self._activity, self.dwell,
                                     self.min_dwell, self.max_dwell, self.hot)
        return [(c, f, b, self.dwell) for c, f, b in self.chans]

    def run(self):
        while not self.stop_flag.is_set():
            for i, (chan, freq, band, dwell) in enumerate(self._sweep()):
                if self.stop_flag.is_set():
                    return
                self.idx = i + 1
                if set_channel(self.iface, chan, freq):
                    self.current = (chan, freq)
                self.stop_flag.wait(dwell)
            self.passes += 1

    def stop(self):
        self.stop_flag.set()


# ==========================================================================
# Beeper - runs bells in a helper thread so the UI never stalls
# ==========================================================================

import math
import shutil
import struct
import tempfile
import wave

_WAV_CACHE = {}


def _gen_wav(freq, dur, rate=44100):
    """Synthesise a short sine tone WAV (cached) for file-based players."""
    key = (int(freq), round(dur, 3))
    if key in _WAV_CACHE:
        return _WAV_CACHE[key]
    path = os.path.join(tempfile.gettempdir(), f"rh_tone_{key[0]}_{int(dur*1000)}.wav")
    if not os.path.exists(path):
        n = int(rate * dur)
        edge = max(1, int(rate * 0.005))  # 5ms fade to avoid clicks
        with wave.open(path, "w") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(rate)
            for i in range(n):
                env = min(1.0, i / edge, (n - i) / edge)
                val = int(32767 * 0.4 * env * math.sin(2 * math.pi * freq * i / rate))
                w.writeframesraw(struct.pack("<h", val))
    _WAV_CACHE[key] = path
    return path


def _audio_as_user():
    """When running under sudo, audio players started as root cannot reach the
    invoking user's PipeWire/Pulse session. Return (env, preexec) that runs the
    player as that user with their runtime dir, or (None, None) if not needed.
    """
    if os.geteuid() != 0:
        return None, None
    uid = os.environ.get("SUDO_UID")
    if not uid:
        return None, None
    uid = int(uid)
    gid = int(os.environ.get("SUDO_GID", uid))
    user = os.environ.get("SUDO_USER", "")
    runtime = f"/run/user/{uid}"
    env = dict(os.environ)
    env["XDG_RUNTIME_DIR"] = runtime
    env.setdefault("PULSE_SERVER", f"unix:{runtime}/pulse/native")
    if user:
        env["HOME"] = os.path.expanduser(f"~{user}")

    def preexec():
        os.setgid(gid)
        os.setuid(uid)

    return env, preexec


class Beeper:
    """Audible feedback. Prefers a real sound backend (the terminal bell is
    usually muted, and rapid geiger bells get coalesced), falling back to the
    bell only when no audio tool is present. Runs the player as the invoking
    user so it still works under sudo."""

    def __init__(self, enabled=True):
        self.enabled = enabled
        self._lock = threading.Lock()
        self.backend, self.name = self._pick_backend()
        self._env, self._preexec = _audio_as_user()

    @staticmethod
    def _pick_backend():
        if shutil.which("play"):
            return "sox", "sox"
        for player in ("pw-play", "paplay", "aplay"):
            if shutil.which(player):
                return player, player
        return "bell", "bell"

    def _emit(self, freq, dur):
        try:
            if self.backend == "sox":
                cmd = ["play", "-qn", "synth", f"{dur:.3f}", "sine", str(int(freq))]
            elif self.backend != "bell":
                wav = _gen_wav(freq, dur)
                cmd = ([self.backend, "-q", wav] if self.backend == "aplay"
                       else [self.backend, wav])
            else:
                cmd = None
            if cmd:
                subprocess.run(cmd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=dur + 1.5,
                               env=self._env, preexec_fn=self._preexec)
                return
        except Exception:
            pass
        # last resort: terminal bell straight to the tty (unbuffered)
        try:
            fd = os.open("/dev/tty", os.O_WRONLY)
            os.write(fd, b"\a")
            os.close(fd)
        except Exception:
            try:
                curses.beep()
            except Exception:
                pass

    def _play(self, n, gap, freq, dur):
        with self._lock:
            for i in range(n):
                self._emit(freq, dur)
                if i < n - 1:
                    time.sleep(gap)

    def beep(self, n=1, gap=0.12, freq=880, dur=0.07):
        if not self.enabled:
            return
        threading.Thread(target=self._play, args=(n, gap, freq, dur), daemon=True).start()


# ==========================================================================
# RSSI trend tracker (drives the warmer/colder beeps)
# ==========================================================================

class Trend:
    """Holds (ts, rssi) samples and reports a smoothed trend over a window.

    The trend is median(recent sub-window) - median(earlier sub-window), which
    is what makes a sub-noise-floor threshold like 1 dB meaningful instead of
    firing on jitter.
    """

    def __init__(self, window=10.0, sub=3.0):
        self.window = window
        self.sub = sub
        self.samples = deque()

    def add(self, ts, rssi):
        self.samples.append((ts, rssi))
        cutoff = ts - self.window
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def delta(self, now):
        if len(self.samples) < 6:
            return None
        recent = [r for t, r in self.samples if t >= now - self.sub]
        earlier = [r for t, r in self.samples if t <= now - (self.window - self.sub)]
        if len(recent) < 3 or len(earlier) < 3:
            return None
        return statistics.median(recent) - statistics.median(earlier)


# ==========================================================================
# Discovery + selection screen
# ==========================================================================

def freq_to_chan_map(chans):
    return {freq: chan for chan, freq, band in chans}


def ssid_display(net):
    if net["hidden"]:
        return "<hidden>"
    return net["ssid"] if net["ssid"] else "<hidden>"


def discover_select(stdscr, iface, cap, hopper, f2c, txguard):
    """Populate a live network list and let the operator pick target BSSIDs.

    Returns (selected_bssids, freq, chan) or None if the user quit.
    """
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(150)
    init_gradient()           # colour pairs for the scan progress bar
    nets = {}                 # bssid -> record
    selected = set()          # bssids toggled on
    cursor = 0

    while True:
        # drain capture queue
        for _ in range(2000):
            try:
                rec = cap.q.get_nowait()
            except queue.Empty:
                break
            b = rec["bssid"]
            n = nets.get(b)
            hidden = (rec["st"] == BEACON) and (not rec["ssid"])
            if n is None:
                nets[b] = {"bssid": b, "ssid": rec["ssid"], "hidden": hidden,
                           "freq": rec["freq"], "rssi": rec["rssi"] or -99,
                           "priv": rec["priv"], "count": 1,
                           "last": time.time()}
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
                n["count"] += 1
                n["last"] = time.time()

        rows = sorted(nets.values(), key=lambda r: r["rssi"], reverse=True)
        cursor = max(0, min(cursor, len(rows) - 1)) if rows else 0

        stdscr.erase()
        h, w = stdscr.getmaxyx()
        cur = hopper.current
        curlbl = f"ch{cur[0]} {cur[1]}MHz" if cur else "-"
        stdscr.addnstr(0, 0, "ROUTER HUNT - discovery   "
                       f"hopping {curlbl}   {len(rows)} networks   "
                       f"{len(selected)} selected", w - 1, curses.A_BOLD)
        stdscr.addnstr(1, 0, "UP/DOWN move   SPACE select/deselect   "
                       "ENTER hunt selected   q quit", w - 1, curses.A_DIM)

        # progress bar: how far through a full sweep of all bands we are
        total = hopper.total or 1
        frac = hopper.idx / total
        bar_w = max(10, min(w - 34, 44))
        if hopper.passes:
            tail = f"{hopper.idx}/{total} ch  ✓ {hopper.passes} full sweep(s)"
            battr = curses.A_BOLD
        else:
            tail = f"{hopper.idx}/{total} ch  (first sweep...)"
            battr = curses.A_NORMAL
        stdscr.addnstr(2, 0, "scan [", w - 1, battr)
        draw_gradient_bar(stdscr, 2, 6, frac, bar_w)   # red->green across width
        stdscr.addnstr(2, 6 + bar_w, f"] {tail}", w - 1, battr)

        hdr = f"  {'SSID':<22} {'BSSID':<18} {'ch':>3} {'RSSI':>5} {'enc':>4} {'seen':>5}"
        stdscr.addnstr(3, 0, hdr, w - 1, curses.A_UNDERLINE)

        top = 4
        maxrows = h - top - 2
        start = max(0, cursor - maxrows + 1)
        for i, r in enumerate(rows[start:start + maxrows]):
            idx = start + i
            chan = f2c.get(r["freq"], "?")
            enc = "wpa" if r["priv"] == "1" else "open"
            mark = "x" if r["bssid"] in selected else " "
            line = (f"[{mark}] {ssid_display(r):<22.22} {r['bssid']:<18} "
                    f"{str(chan):>3} {r['rssi']:>5} {enc:>4} {r['count']:>5}")
            attr = curses.A_REVERSE if idx == cursor else curses.A_NORMAL
            if r["hidden"]:
                attr |= curses.A_DIM
            stdscr.addnstr(top + i, 0, line, w - 1, attr)

        if cap.error:
            stdscr.addnstr(h - 1, 0, f"capture error: {cap.error}", w - 1, curses.A_BOLD)
        else:
            txguard.poll()
            stdscr.addnstr(h - 1, 0, txguard.label(), w - 1, curses.A_DIM)
        stdscr.refresh()

        c = stdscr.getch()
        if c == -1:
            continue
        if c in (ord("q"), 27):
            return None
        if c in (curses.KEY_DOWN, ord("j")):
            cursor = min(cursor + 1, max(0, len(rows) - 1))
        elif c in (curses.KEY_UP, ord("k")):
            cursor = max(cursor - 1, 0)
        elif c == ord(" "):
            if rows:
                b = rows[cursor]["bssid"]
                selected.symmetric_difference_update({b})
        elif c in (curses.KEY_ENTER, 10, 13):
            targets = selected or ({rows[cursor]["bssid"]} if rows else set())
            if not targets:
                continue
            # Park on the channel of the strongest selected network; other
            # selected BSSIDs on the same channel are still tracked, ones on
            # other channels simply won't be heard (one radio, one channel).
            chosen = [r for r in rows if r["bssid"] in targets]
            chosen.sort(key=lambda r: r["rssi"], reverse=True)
            freq = chosen[0]["freq"]
            chan = f2c.get(freq, 0)
            return (set(r["bssid"] for r in chosen), freq, chan)


# ==========================================================================
# Hunt screen
# ==========================================================================

def hunt(stdscr, iface, label, cap, txguard, args):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(120)
    init_gradient()           # colour pairs for the RSSI gradient bar

    beeper = Beeper(enabled=not args.no_beep)
    trend = Trend(window=args.beep_window, sub=min(3.0, args.beep_window / 3))
    roll = deque()            # (ts, rssi) for the display rolling average
    spark = deque(maxlen=120)  # smoothed values for the sparkline
    peak = None
    last_rssi = None
    last_beep = 0.0
    last_dir = "→"
    last_geiger = 0.0
    frames = deque()          # ts of recent frames for frames/sec

    while True:
        now = time.time()
        for _ in range(4000):
            try:
                rec = cap.q.get_nowait()
            except queue.Empty:
                break
            r = rec["rssi"]
            roll.append((rec["ts"], r))
            trend.add(rec["ts"], r)
            frames.append(rec["ts"])
            last_rssi = r

        # trim rolling window / frame-rate window
        cut = now - args.window
        while roll and roll[0][0] < cut:
            roll.popleft()
        while frames and frames[0] < now - 3:
            frames.popleft()

        avg = statistics.mean(r for _, r in roll) if roll else None
        if avg is not None:
            spark.append(avg)
            if peak is None or avg > peak:
                peak = avg
        fps = len(frames) / 3.0

        # ---- trend -> beeps ----
        d = trend.delta(now)
        if d is not None:
            if d >= args.beep_threshold:
                last_dir = "↑"
            elif d <= -args.beep_threshold:
                last_dir = "↓"
            else:
                last_dir = "→"
        if not args.geiger:
            if d is not None and (now - last_beep) >= args.beep_interval:
                if d >= args.beep_threshold:
                    beeper.beep(1, freq=1200)          # warmer: high single beep
                    last_beep = now
                elif d <= -args.beep_threshold:
                    beeper.beep(2, freq=500)           # colder: low double beep
                    last_beep = now
        else:
            # geiger mode: beep faster AND higher-pitched the stronger the signal
            if avg is not None:
                frac = (avg - RSSI_FLOOR) / (RSSI_CEIL - RSSI_FLOOR)
                frac = max(0.0, min(1.0, frac))
                interval = 1.2 - 1.0 * frac            # 1.2s (weak) .. 0.2s (strong)
                if (now - last_geiger) >= interval:
                    beeper.beep(1, freq=500 + 1500 * frac, dur=0.05)
                    last_geiger = now

        # ---- draw ----
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        stdscr.addnstr(0, 0, f"ROUTER HUNT   target: {label}", w - 1, curses.A_BOLD)
        mode = "geiger" if args.geiger else f"±{args.beep_threshold:g}dB/{args.beep_window:g}s"
        audio = "off" if args.no_beep else f"{mode} [{beeper.name}]"
        stdscr.addnstr(1, 0, f"beep {audio}   "
                       f"p reset-peak   b beep on/off   q quit",
                       w - 1, curses.A_DIM)

        shown = f"{avg:.0f}" if avg is not None else "--"
        for i, rowtext in enumerate(big_digits(shown, scale=2)):
            stdscr.addnstr(3 + i, 2, rowtext, w - 3)
        stdscr.addnstr(3, 40, "dBm (avg)", w - 41)
        stdscr.addnstr(4, 40, f"now  {last_rssi if last_rssi is not None else '--'}", w - 41)
        stdscr.addnstr(5, 40, f"peak {peak:.0f}" if peak is not None else "peak --", w - 41)
        arrow_attr = curses.A_BOLD | (curses.A_REVERSE if last_dir != "→" else 0)
        stdscr.addnstr(6, 40, f"trend {last_dir}  ({d:+.1f} dB)" if d is not None
                       else "trend →  (settling)", w - 41, arrow_attr)
        stdscr.addnstr(7, 40, f"frames/s {fps:.0f}", w - 41)

        bw = min(w - 6, 60)
        bfrac = 0.0 if avg is None else (avg - RSSI_FLOOR) / (RSSI_CEIL - RSSI_FLOOR)
        try:
            stdscr.addstr(9, 2, "[")
            draw_gradient_bar(stdscr, 9, 3, bfrac, bw)   # weak(red)->strong(green)
            stdscr.addstr(9, 3 + bw, "]")
        except curses.error:
            pass
        if spark:
            lo, hi = min(spark), max(spark)
            rng = (hi - lo) or 1
            s = "".join(SPARK[min(len(SPARK) - 1,
                        int((v - lo) / rng * (len(SPARK) - 1)))] for v in spark)
            stdscr.addnstr(11, 2, f"last {args.window:g}s→ {s[-(w-14):]}", w - 3)

        if cap.error:
            stdscr.addnstr(h - 1, 0, f"capture error: {cap.error}", w - 1, curses.A_BOLD)
        else:
            txguard.poll()
            stdscr.addnstr(h - 1, 0, txguard.label(), w - 1, curses.A_DIM)
        stdscr.refresh()

        c = stdscr.getch()
        if c == -1:
            continue
        if c in (ord("q"), 27):
            return
        if c == ord("p"):
            peak = avg
        elif c == ord("b"):
            args.no_beep = not args.no_beep
            beeper.enabled = not args.no_beep


# ==========================================================================
# Main
# ==========================================================================

def build_target_filter(bssids=None, sa=None):
    if sa:
        m = sa.lower()
        return f"wlan.sa=={m} || wlan.ta=={m}", sa
    terms = []
    for b in bssids:
        terms.append(f"wlan.sa=={b}")
        terms.append(f"wlan.ta=={b}")
    label = ", ".join(sorted(bssids))
    return " || ".join(terms), label


def valid_mac(s):
    return bool(re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", s or ""))


def directional_reminder():
    """Shown at the moment the hunt starts - direction finding needs the
    directional antenna, not the omnis used for discovery."""
    print("\n>>> Recommended that you use the directional antenna. <<<\n",
          file=sys.stderr)
    time.sleep(1.8)


def main():
    print("ANTENNA: use 2 omni antennas (or at least 1 dual-band omni) to discover "
          "networks across all directions and both bands; then swap to 1 directional "
          "antenna (one jack, other empty) for the closing-in hunt, since an omni "
          "smears the RSSI bearing.", file=sys.stderr)

    p = argparse.ArgumentParser(
        description="Discover WiFi networks (hidden included), pick one, and direction-find it.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--iface", help="monitor-mode interface (auto-detects mt7921u)")
    p.add_argument("--sa", help="skip discovery and follow this source MAC directly")
    p.add_argument("--bssid", help="preselect this BSSID (still discovers to find its channel)")
    p.add_argument("--channel", type=int, help="channel to park on for --sa (else current)")
    p.add_argument("--band", choices=["2.4", "5", "both"], default="both",
                   help="bands to hop during discovery")
    p.add_argument("--dwell", type=float, default=1.2, help="seconds per channel while discovering")
    p.add_argument("--window", type=float, default=2.5, help="rolling average / sparkline seconds")
    p.add_argument("--beep-window", type=float, default=10.0, help="trend window for beeps (s)")
    p.add_argument("--beep-threshold", type=float, default=1.0,
                   help="dB of smoothed change that triggers a beep")
    p.add_argument("--beep-interval", type=float, default=1.5,
                   help="minimum seconds between beeps")
    p.add_argument("--geiger", action="store_true",
                   help="continuous rate-coded beeps (faster = stronger) instead of up/down")
    p.add_argument("--no-beep", action="store_true", help="silent (visual trend only)")
    p.add_argument("--test-beep", action="store_true",
                   help="play the warmer/colder/geiger cues and exit (no radio needed)")
    args = p.parse_args()

    if args.test_beep:
        b = Beeper()
        who = "root->user audio" if b._env else "current user"
        print(f"audio backend: {b.name}  ({who})")
        print("warmer (high single 1200 Hz)...");  b.beep(1, freq=1200); time.sleep(0.9)
        print("colder (low double 500 Hz)...");     b.beep(2, freq=500);  time.sleep(1.1)
        print("geiger sweep (rising pitch)...")
        for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
            b.beep(1, freq=500 + 1500 * frac, dur=0.06); time.sleep(0.35)
        time.sleep(0.6)
        print("done. If you heard nothing, tell me the backend line above.")
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

    if args.sa and not valid_mac(args.sa):
        sys.exit(f"--sa is not a valid MAC: {args.sa}")

    # -------- direct follow of a source MAC: skip discovery --------
    if args.sa:
        if args.channel:
            freq = next((f for c, f, b in chans if c == args.channel), None)
            if freq:
                set_channel(iface, args.channel, freq)
            else:
                print(f"! channel {args.channel} not available; staying on current", file=sys.stderr)
        dfilter, label = build_target_filter(sa=args.sa)
        cap = CaptureThread(iface, dfilter, HUNT_FIELDS, parse_hunt)
        cap.start()
        directional_reminder()
        try:
            curses.wrapper(hunt, iface, f"src {label}", cap, txguard, args)
        finally:
            cap.stop()
        return

    # -------- discovery + selection --------
    cap = CaptureThread(iface, DISC_FILTER, DISC_FIELDS, parse_disc)
    hopper = Hopper(iface, chans, args.dwell)
    cap.start()
    hopper.start()
    try:
        result = curses.wrapper(discover_select, iface, cap, hopper, f2c, txguard)
    finally:
        hopper.stop()
        cap.stop()
    if not result:
        print("no network selected.")
        return
    bssids, freq, chan = result

    # park on the target channel for the hunt
    if freq:
        set_channel(iface, chan or 0, freq)
    dfilter, label = build_target_filter(bssids=bssids)
    label = f"{label}  (ch{chan} {freq}MHz)"
    cap2 = CaptureThread(iface, dfilter, HUNT_FIELDS, parse_hunt)
    cap2.start()
    directional_reminder()
    try:
        curses.wrapper(hunt, iface, label, cap2, txguard, args)
    finally:
        cap2.stop()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        main()
    except KeyboardInterrupt:
        pass
