#!/usr/bin/env python3
"""
deauth_hunt.py - live RSSI meter + per-floor waypoint recorder for tracking
down the source of an 802.11 deauthentication flood with a directional antenna.

Built for a single stationary emitter on a known channel. It does not attempt
triangulation maths: with one fixed transmitter, a responsive warmer/colder
needle plus a peak-hold you sweep the antenna against is what actually finds it.

Terminal UI for walking the building; a web view on localhost for reviewing
what each floor looked like afterwards. Everything lands in SQLite.

RECEIVE-ONLY. There is no transmit path anywhere in this tool: it shells out to
tshark, which opens a libpcap capture handle and nothing else. It never injects,
never deauthenticates, never probes, never associates. The interface's
tx_packets counter is watched continuously and the UI shows a running proof that
it has not moved - a deauth hunt must never become a deauth source.

Capture needs no root if you are in the 'wireshark' group (dumpcap has
cap_net_raw). Run init-hunt.sh with sudo first to set up monitor mode.
"""

import argparse
import curses
import json
import math
import os
import queue
import signal
import sqlite3
import statistics
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import wave
from collections import Counter, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# The attack signature, from forensic analysis of the PEEKREMOTE capture:
#   src fe:ff:ff:ff:ff:ff (broadcast with the I/G bit cleared), reason code 7,
#   deauth aimed at the AP (dst == BSSID), 12 Mbps OFDM on channel 64.
# --------------------------------------------------------------------------
DEFAULT_SA = "fe:ff:ff:ff:ff:ff"
DEFAULT_CHANNEL = 64
DEFAULT_FREQ = 5320

RSSI_FLOOR = -95   # bar scale bottom
RSSI_CEIL = -30    # bar scale top

FIELDS = [
    "frame.time_epoch",
    "radiotap.dbm_antsignal",
    "wlan.sa",
    "wlan.da",
    "wlan.seq",
    "wlan.fixed.reason_code",
    "radiotap.channel.freq",
    "radiotap.datarate",
]

BIGFONT = {
    "0": ["███", "█ █", "█ █", "█ █", "███"],
    "1": ["  █", "  █", "  █", "  █", "  █"],
    "2": ["███", "  █", "███", "█  ", "███"],
    "3": ["███", "  █", "███", "  █", "███"],
    "4": ["█ █", "█ █", "███", "  █", "  █"],
    "5": ["███", "█  ", "███", "  █", "███"],
    "6": ["███", "█  ", "███", "█ █", "███"],
    "7": ["███", "  █", "  █", "  █", "  █"],
    "8": ["███", "█ █", "███", "█ █", "███"],
    "9": ["███", "█ █", "███", "  █", "███"],
    "-": ["   ", "   ", "███", "   ", "   "],
    ".": ["   ", "   ", "   ", "   ", "  █"],
    " ": ["   ", "   ", "   ", "   ", "   "],
    "?": ["███", "  █", " ██", "   ", " █ "],
}
SPARK = "▁▂▃▄▅▆▇█"


def big_digits(text, scale=2):
    """Render text as 5-row block digits, horizontally scaled."""
    rows = []
    for r in range(5):
        parts = []
        for ch in text:
            glyph = BIGFONT.get(ch, BIGFONT["?"])[r]
            parts.append("".join(c * scale for c in glyph))
        rows.append("  ".join(parts))
    return rows


# ==========================================================================
# Gradient bar colouring (shared with router_hunt.py)
# ==========================================================================
# Palette: 0% red -> orange -> yellow -> light green -> 100% green.
GRADIENT_STOPS = [
    (0.00, (215, 45, 45)),    # red
    (0.25, (240, 140, 30)),   # orange
    (0.50, (235, 210, 45)),   # yellow
    (0.75, (150, 215, 75)),   # light green
    (1.00, (40, 185, 70)),    # green
]

_GRAD_PAIRS = []
_GRAD_MODE = "none"           # "full" (256-colour), "basic" (8-colour), "none"


def grad_rgb(frac):
    """Interpolate the palette at fraction 0..1 -> (r, g, b) 0..255."""
    frac = max(0.0, min(1.0, frac))
    stops = GRADIENT_STOPS
    for i in range(len(stops) - 1):
        p0, c0 = stops[i]
        p1, c1 = stops[i + 1]
        if frac <= p1:
            t = 0.0 if p1 == p0 else (frac - p0) / (p1 - p0)
            return tuple(int(round(c0[j] + (c1[j] - c0[j]) * t)) for j in range(3))
    return stops[-1][1]


def _rgb_to_xterm256(r, g, b):
    """Nearest index in the xterm 6x6x6 colour cube (16..231)."""
    levels = (0, 95, 135, 175, 215, 255)

    def nearest(v):
        return min(range(6), key=lambda i: abs(levels[i] - v))

    return 16 + 36 * nearest(r) + 6 * nearest(g) + nearest(b)


def init_gradient(levels=32, base=20):
    """Allocate curses colour pairs for the gradient. Call once after the
    screen is up; safe to call again. Falls back to 3 colours on an 8-colour
    terminal, or no colour if the terminal has none."""
    global _GRAD_PAIRS, _GRAD_MODE
    _GRAD_PAIRS = []
    if not curses.has_colors():
        _GRAD_MODE = "none"
        return
    try:
        curses.start_color()
        curses.use_default_colors()
    except curses.error:
        pass
    if curses.COLORS >= 256:
        _GRAD_MODE = "full"
        for i in range(levels):
            r, g, b = grad_rgb(i / (levels - 1))
            try:
                curses.init_pair(base + i, _rgb_to_xterm256(r, g, b), -1)
                _GRAD_PAIRS.append(base + i)
            except curses.error:
                break
    if _GRAD_MODE != "full" or not _GRAD_PAIRS:
        _GRAD_MODE = "basic"
        _GRAD_PAIRS = []
        for off, col in enumerate((curses.COLOR_RED, curses.COLOR_YELLOW,
                                   curses.COLOR_GREEN)):
            try:
                curses.init_pair(base + off, col, -1)
                _GRAD_PAIRS.append(base + off)
            except curses.error:
                pass
        if not _GRAD_PAIRS:
            _GRAD_MODE = "none"


def grad_pair(frac):
    """curses attribute for fraction 0..1 along the gradient (0 if no colour)."""
    if _GRAD_MODE == "none" or not _GRAD_PAIRS:
        return 0
    frac = max(0.0, min(1.0, frac))
    if _GRAD_MODE == "full":
        idx = int(frac * (len(_GRAD_PAIRS) - 1))
    else:
        idx = 0 if frac < 0.34 else (1 if frac < 0.67 else 2)
        idx = min(idx, len(_GRAD_PAIRS) - 1)
    return curses.color_pair(_GRAD_PAIRS[idx])


def draw_gradient_bar(win, y, x, frac_filled, width, fill="█", empty="·"):
    """Draw a horizontal bar whose filled cells are coloured by their position
    along the gradient (left = 0%, right = 100%); empty cells are dim."""
    frac_filled = max(0.0, min(1.0, frac_filled))
    filled = int(round(frac_filled * width))
    for i in range(width):
        cell = i / max(1, width - 1)
        if i < filled:
            attr = grad_pair(cell) | curses.A_BOLD
            ch = fill
        else:
            attr = curses.A_DIM
            ch = empty
        try:
            win.addstr(y, x + i, ch, attr)
        except curses.error:
            pass


# ==========================================================================
# Audio feedback + RSSI trend  (ported from router_hunt.py)
# ==========================================================================
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
# Capture
# ==========================================================================

class Capture(threading.Thread):
    """Runs tshark and pushes parsed frames onto a queue."""

    daemon = True

    def __init__(self, iface=None, replay=None, display_filter=None, paced=True):
        super().__init__()
        self.iface = iface
        self.replay = replay
        self.filter = display_filter
        self.paced = paced
        self.q = queue.Queue(maxsize=20000)
        self.stop_flag = threading.Event()
        self.proc = None
        self.error = None
        self.started_at = None
        self.raw_lines = 0

    def build_cmd(self):
        cmd = ["tshark", "-l", "-n", "-Q"]
        if self.replay:
            cmd += ["-r", self.replay]
        else:
            cmd += ["-i", self.iface]
        if self.filter:
            cmd += ["-Y", self.filter]
        cmd += ["-T", "fields", "-E", "separator=|", "-E", "occurrence=a"]
        for f in FIELDS:
            cmd += ["-e", f]
        return cmd

    def run(self):
        cmd = self.build_cmd()
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            self.error = "tshark not found"
            return

        self.started_at = time.time()
        first_ts = None
        wall_start = time.time()

        for line in self.proc.stdout:
            if self.stop_flag.is_set():
                break
            self.raw_lines += 1
            rec = self.parse(line.rstrip("\n"))
            if rec is None:
                continue

            # When replaying a file, pace playback to the original timing so the
            # meter behaves the way it will on-site.
            if self.replay:
                if self.paced:
                    if first_ts is None:
                        first_ts = rec["ts"]
                    delay = wall_start + (rec["ts"] - first_ts) - time.time()
                    if delay > 0:
                        time.sleep(min(delay, 2.0))
                # Rebase onto wall-clock either way: the rolling window compares
                # sample times against time.time(), so stale file timestamps
                # would be trimmed the instant they arrive.
                rec["ts"] = time.time()

            try:
                self.q.put_nowait(rec)
            except queue.Full:
                pass

        if self.proc.poll() not in (0, None) and not self.stop_flag.is_set():
            err = (self.proc.stderr.read() or "").strip()
            self.error = err.splitlines()[-1] if err else f"tshark exited {self.proc.poll()}"

    @staticmethod
    def parse(line):
        parts = line.split("|")
        if len(parts) < len(FIELDS):
            return None
        ts, sig, sa, da, seq, reason, freq, rate = parts[:8]
        try:
            ts = float(ts)
        except ValueError:
            return None

        # Multiple radiotap antenna-signal fields arrive comma-joined (one per
        # RX chain). The first is the combined figure the driver reports.
        chains = []
        for tok in sig.split(","):
            tok = tok.strip()
            if tok:
                try:
                    chains.append(int(tok))
                except ValueError:
                    pass
        if not chains:
            return None

        def as_int(v):
            try:
                return int(v.split(",")[0])
            except (ValueError, AttributeError):
                return None

        return {
            "ts": ts,
            "rssi": chains[0],
            "chains": chains,
            "sa": sa.split(",")[0],
            "da": da.split(",")[0],
            "seq": as_int(seq),
            "reason": as_int(reason),
            "freq": as_int(freq),
            "rate": rate.split(",")[0],
        }

    def stop(self):
        self.stop_flag.set()
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass


# ==========================================================================
# Rolling statistics
# ==========================================================================

class TxGuard:
    """Watches the interface's transmit counter and proves it never moves.

    Monitor mode does not associate, scan, beacon or ACK, so tx_packets must
    stay flat for the whole session. If it ever climbs, something else has taken
    hold of the radio and the operator needs to know at once - the whole point
    of this exercise is to find a deauth source, not become one.
    """

    def __init__(self, iface):
        self.iface = iface
        self.path = f"/sys/class/net/{iface}/statistics/tx_packets" if iface else None
        self.baseline = self._read()
        self.current = self.baseline
        self.available = self.baseline is not None

    def _read(self):
        try:
            with open(self.path) as fh:
                return int(fh.read().strip())
        except (OSError, TypeError, ValueError):
            return None

    def poll(self):
        v = self._read()
        if v is not None:
            self.current = v
        return self.delta

    @property
    def delta(self):
        if not self.available or self.current is None:
            return None
        return self.current - self.baseline

    @property
    def clean(self):
        return (self.delta or 0) == 0

    def label(self):
        d = self.delta
        if d is None:
            return "TX-GUARD  unavailable (replay or no counter)"
        if d == 0:
            return f"TX-GUARD  0 packets transmitted since start - verifiably passive"
        return f"*** INTERFACE TRANSMITTED {d} PACKETS - NOT PASSIVE ***"


class Meter:
    def __init__(self, window_s=3.0, spark_s=30.0):
        self.window_s = window_s
        self.spark_s = spark_s
        self.samples = deque()          # (ts, rssi)
        self.spark = deque()            # (ts, rssi)
        self.targets = Counter()
        self.total = 0
        self.max_hold = None
        self.max_hold_ts = time.time()
        self.last_seq = None
        self.seq_gaps = 0
        self.last_frame_ts = None
        self.lock = threading.Lock()

    def add(self, rec):
        now = rec["ts"]
        with self.lock:
            self.samples.append((now, rec["rssi"]))
            self.spark.append((now, rec["rssi"]))
            self.total += 1
            self.last_frame_ts = time.time()
            if rec["da"]:
                self.targets[rec["da"][:14]] += 1
            if self.max_hold is None or rec["rssi"] > self.max_hold:
                self.max_hold = rec["rssi"]
                self.max_hold_ts = time.time()
            if rec["seq"] is not None:
                if self.last_seq is not None:
                    d = (rec["seq"] - self.last_seq) & 0xFFF
                    if 1 < d < 100:
                        self.seq_gaps += d - 1
                self.last_seq = rec["seq"]
            self._trim(now)

    def _trim(self, now):
        while self.samples and now - self.samples[0][0] > self.window_s:
            self.samples.popleft()
        while self.spark and now - self.spark[0][0] > self.spark_s:
            self.spark.popleft()

    def stats(self):
        with self.lock:
            self._trim(time.time())
            vals = [v for _, v in self.samples]
            if not vals:
                return None
            span = max(self.samples[-1][0] - self.samples[0][0], 1e-6)
            return {
                "mean": statistics.fmean(vals),
                "min": min(vals),
                "max": max(vals),
                "stdev": statistics.pstdev(vals) if len(vals) > 1 else 0.0,
                "count": len(vals),
                "fps": len(vals) / span if len(vals) > 1 else 0.0,
                "window_s": span,
            }

    def sparkline(self, width):
        with self.lock:
            pts = list(self.spark)
        if not pts or width < 4:
            return " " * max(width, 0)
        now = time.time()
        buckets = [[] for _ in range(width)]
        for ts, v in pts:
            age = now - ts
            idx = width - 1 - int(age / self.spark_s * width)
            if 0 <= idx < width:
                buckets[idx].append(v)
        lo, hi = RSSI_FLOOR, RSSI_CEIL
        allv = [v for b in buckets if b for v in b]
        if allv:
            lo = min(allv) - 2
            hi = max(allv) + 2
            if hi - lo < 6:
                mid = (hi + lo) / 2
                lo, hi = mid - 3, mid + 3
        out = []
        for b in buckets:
            if not b:
                out.append(" ")
            else:
                frac = (max(b) - lo) / max(hi - lo, 1e-6)
                out.append(SPARK[min(len(SPARK) - 1, max(0, int(frac * len(SPARK))))])
        return "".join(out)

    def reset_hold(self):
        with self.lock:
            self.max_hold = None
            self.max_hold_ts = time.time()

    def clear(self):
        with self.lock:
            self.samples.clear()
            self.spark.clear()
            self.targets.clear()
            self.max_hold = None
            self.max_hold_ts = time.time()
            self.seq_gaps = 0
            self.last_seq = None


# ==========================================================================
# Storage
# ==========================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS session (
    id INTEGER PRIMARY KEY, started TEXT, iface TEXT, channel INTEGER,
    filter TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS sample (
    id INTEGER PRIMARY KEY, session_id INTEGER, ts REAL, rssi INTEGER,
    chains TEXT, sa TEXT, da TEXT, seq INTEGER, reason INTEGER, floor TEXT);
CREATE TABLE IF NOT EXISTS waypoint (
    id INTEGER PRIMARY KEY, session_id INTEGER, ts REAL, floor TEXT,
    label TEXT, heading TEXT, rssi_mean REAL, rssi_max INTEGER,
    rssi_min INTEGER, rssi_stdev REAL, samples INTEGER, window_s REAL,
    fps REAL, peak_hold INTEGER, note TEXT);
CREATE INDEX IF NOT EXISTS ix_sample_ts ON sample(ts);
CREATE INDEX IF NOT EXISTS ix_sample_floor ON sample(floor);
CREATE INDEX IF NOT EXISTS ix_wp_floor ON waypoint(floor);
"""


class Store:
    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.Lock()
        self.session_id = None
        self.pending = []

    def start_session(self, iface, channel, filt):
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO session(started, iface, channel, filter) VALUES(?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 iface, channel, filt),
            )
            self.conn.commit()
            self.session_id = cur.lastrowid
        return self.session_id

    def queue_sample(self, rec, floor):
        self.pending.append((
            self.session_id, rec["ts"], rec["rssi"],
            ",".join(str(c) for c in rec["chains"]),
            rec["sa"], rec["da"], rec["seq"], rec["reason"], floor,
        ))

    def flush(self):
        if not self.pending:
            return 0
        batch, self.pending = self.pending, []
        with self.lock:
            self.conn.executemany(
                "INSERT INTO sample(session_id,ts,rssi,chains,sa,da,seq,reason,floor)"
                " VALUES(?,?,?,?,?,?,?,?,?)", batch)
            self.conn.commit()
        return len(batch)

    def add_waypoint(self, floor, label, heading, st, peak, note=""):
        with self.lock:
            self.conn.execute(
                "INSERT INTO waypoint(session_id,ts,floor,label,heading,rssi_mean,"
                "rssi_max,rssi_min,rssi_stdev,samples,window_s,fps,peak_hold,note)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.session_id, time.time(), floor, label, heading,
                 st["mean"], st["max"], st["min"], st["stdev"], st["count"],
                 st["window_s"], st["fps"], peak, note))
            self.conn.commit()

    def waypoints(self):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM waypoint ORDER BY floor, rssi_max DESC, ts")]

    def floor_summary(self):
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT floor, COUNT(*) n, MAX(rssi_max) best, AVG(rssi_mean) avg,"
                " MIN(rssi_min) worst FROM waypoint GROUP BY floor ORDER BY best DESC")]

    def close(self):
        self.flush()
        with self.lock:
            self.conn.close()


# ==========================================================================
# Web view
# ==========================================================================

DASHBOARD_HTML = r"""<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Deauth Hunt</title>
<style>
:root{color-scheme:light dark;--bg:#fbfaf8;--fg:#1c1b19;--dim:#6b6862;--card:#fff;
--line:#e5e1da;--hot:#c0392b;--warm:#e08e0b;--cool:#3d7d54;--accent:#2f6fa8}
@media(prefers-color-scheme:dark){:root{--bg:#16171a;--fg:#e8e6e3;--dim:#8d8a84;
--card:#1e2024;--line:#2c2f34;--hot:#e05c4a;--warm:#e0a83c;--cool:#5aab77;--accent:#5b9bd5}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px 20px 60px}
h1{font-size:19px;margin:0 0 2px;letter-spacing:-.01em}
.sub{color:var(--dim);font-size:12.5px;margin-bottom:22px}
.live{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px 22px;margin-bottom:26px;display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.big{font:600 54px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:-.02em}
.unit{font-size:16px;color:var(--dim);font-weight:400}
.kv{display:flex;gap:26px;flex-wrap:wrap}
.kv div{min-width:74px}
.kv b{display:block;font:600 17px/1.3 ui-monospace,Menlo,monospace}
.kv span{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--dim);
margin:26px 0 9px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:10px;overflow:hidden}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;
color:var(--dim);padding:9px 12px;border-bottom:1px solid var(--line);font-weight:600}
td{padding:9px 12px;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:none}
td.n{font-family:ui-monospace,Menlo,monospace;text-align:right;white-space:nowrap}
.bar{height:7px;border-radius:4px;background:var(--line);overflow:hidden;min-width:90px}
.bar i{display:block;height:100%;border-radius:4px}
.hot{color:var(--hot)}.warm{color:var(--warm)}.cool{color:var(--cool)}
.tag{display:inline-block;padding:1px 7px;border-radius:20px;font-size:11px;
background:var(--line);color:var(--dim)}
.empty{color:var(--dim);padding:26px;text-align:center;background:var(--card);
border:1px solid var(--line);border-radius:10px}
.tw{overflow-x:auto}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px}
</style>
<div class="wrap">
<h1>Deauth Hunt <span class="tag" id="txg">receive-only</span></h1>
<div class="sub" id="sub">connecting…</div>
<div class="live">
  <div><div class="big" id="rssi">--<span class="unit"> dBm</span></div>
       <div class="sub" style="margin:4px 0 0" id="win">no signal</div></div>
  <div class="kv">
    <div><b id="peak">--</b><span>peak hold</span></div>
    <div><b id="fps">--</b><span>frames/s</span></div>
    <div><b id="tot">--</b><span>total</span></div>
    <div><b id="floor">--</b><span>floor</span></div>
  </div>
</div>
<div id="floors"></div>
</div>
<script>
const S=-95,C=-30;
function pct(v){return Math.max(0,Math.min(100,(v-S)/(C-S)*100))}
function cls(v){return v>=-55?'hot':v>=-70?'warm':'cool'}
function col(v){return getComputedStyle(document.documentElement)
  .getPropertyValue('--'+cls(v))||'#888'}
async function tick(){
 let s;
 try{s=await (await fetch('api/state')).json()}
 catch(e){document.getElementById('sub').textContent='disconnected';return}
 document.getElementById('sub').textContent=
   s.iface+' · channel '+s.channel+' · '+s.filter;
 const r=document.getElementById('rssi');
 if(s.live&&s.live.mean!=null){
   r.innerHTML=s.live.mean.toFixed(1)+'<span class="unit"> dBm</span>';
   r.className='big '+cls(s.live.mean);
   document.getElementById('win').textContent=
     s.live.count+' frames in '+s.live.window_s.toFixed(1)+'s · σ '+s.live.stdev.toFixed(2)+' dB';
 }else{r.innerHTML='--<span class="unit"> dBm</span>';r.className='big';
   document.getElementById('win').textContent='no signal in window';}
 document.getElementById('peak').textContent=s.peak!=null?s.peak+' dBm':'--';
 document.getElementById('fps').textContent=s.live?s.live.fps.toFixed(1):'0.0';
 document.getElementById('tot').textContent=s.total;
 document.getElementById('floor').textContent=s.floor||'—';
 const tg=document.getElementById('txg');
 if(s.tx_delta==null){tg.textContent='receive-only';tg.style.color='';}
 else if(s.tx_clean){tg.textContent='receive-only · 0 packets TX';
   tg.style.color='var(--cool)';}
 else {tg.textContent='WARNING: '+s.tx_delta+' packets transmitted';
   tg.style.color='var(--hot)';tg.style.fontWeight='700';}

 const wps=await (await fetch('api/waypoints')).json();
 const box=document.getElementById('floors');
 if(!wps.length){box.innerHTML='<div class="empty">No waypoints marked yet.<br>'+
   'Press <b>m</b> in the terminal to record one.</div>';return}
 const by={};
 for(const w of wps){(by[w.floor||'unset']??=[]).push(w)}
 const order=Object.keys(by).sort((a,b)=>
   Math.max(...by[b].map(x=>x.rssi_max))-Math.max(...by[a].map(x=>x.rssi_max)));
 let h='';
 for(const f of order){
   const rows=by[f].sort((a,b)=>b.rssi_max-a.rssi_max);
   const best=rows[0].rssi_max;
   h+='<h2><span class="dot" style="background:'+col(best)+'"></span>Floor '+f+
      ' <span class="tag">'+rows.length+' points · best '+best+' dBm</span></h2>';
   h+='<div class="tw"><table><tr><th>Point</th><th>Heading</th><th>Strength</th>'+
      '<th class="n">Peak</th><th class="n">Mean</th><th class="n">σ</th>'+
      '<th class="n">Frames</th><th class="n">Time</th></tr>';
   for(const w of rows){
     h+='<tr><td>'+esc(w.label||'—')+'</td><td>'+esc(w.heading||'—')+'</td>'+
        '<td><div class="bar"><i style="width:'+pct(w.rssi_max).toFixed(1)+
        '%;background:'+col(w.rssi_max)+'"></i></div></td>'+
        '<td class="n '+cls(w.rssi_max)+'"><b>'+w.rssi_max+'</b></td>'+
        '<td class="n">'+w.rssi_mean.toFixed(1)+'</td>'+
        '<td class="n">'+w.rssi_stdev.toFixed(2)+'</td>'+
        '<td class="n">'+w.samples+'</td>'+
        '<td class="n">'+new Date(w.ts*1000).toLocaleTimeString()+'</td></tr>';
   }
   h+='</table></div>';
 }
 box.innerHTML=h;
}
function esc(s){const d=document.createElement('div');d.textContent=s??'';return d.innerHTML}
tick();setInterval(tick,1500);
</script>
"""


def make_web_server(port, state_fn, store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, ctype):
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?")[0].rstrip("/") or "/"
            try:
                if path in ("/", "/index.html"):
                    self._send(DASHBOARD_HTML, "text/html; charset=utf-8")
                elif path == "/api/state":
                    self._send(json.dumps(state_fn()), "application/json")
                elif path == "/api/waypoints":
                    self._send(json.dumps(store.waypoints()), "application/json")
                elif path == "/api/floors":
                    self._send(json.dumps(store.floor_summary()), "application/json")
                else:
                    self.send_error(404)
            except BrokenPipeError:
                pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ==========================================================================
# Terminal UI
# ==========================================================================

class UI:
    def __init__(self, stdscr, app):
        self.s = stdscr
        self.app = app
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(120)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_RED, -1)      # hot
            curses.init_pair(2, curses.COLOR_YELLOW, -1)   # warm
            curses.init_pair(3, curses.COLOR_GREEN, -1)    # cool
            curses.init_pair(4, curses.COLOR_CYAN, -1)     # chrome
            curses.init_pair(5, curses.COLOR_WHITE, -1)
            curses.init_pair(6, curses.COLOR_MAGENTA, -1)
            init_gradient()   # colour pairs for the gradient meter bars

    @staticmethod
    def heat(v):
        if v is None:
            return curses.color_pair(5)
        if v >= -55:
            return curses.color_pair(1) | curses.A_BOLD
        if v >= -70:
            return curses.color_pair(2) | curses.A_BOLD
        return curses.color_pair(3)

    def put(self, y, x, text, attr=0):
        h, w = self.s.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        self.s.addnstr(y, x, text, max(0, w - x - 1), attr)

    def bar(self, value, width):
        if value is None:
            return "░" * width
        frac = (value - RSSI_FLOOR) / (RSSI_CEIL - RSSI_FLOOR)
        fill = max(0, min(width, int(round(frac * width))))
        return "█" * fill + "░" * (width - fill)

    def grad_bar(self, y, x, value, width):
        """RSSI bar with a red->green gradient across its width (weak->strong)."""
        frac = 0.0 if value is None else (value - RSSI_FLOOR) / (RSSI_CEIL - RSSI_FLOOR)
        draw_gradient_bar(self.s, y, x, frac, width)

    def prompt(self, label, default=""):
        h, w = self.s.getmaxyx()
        self.s.nodelay(False)
        curses.echo()
        curses.curs_set(1)
        y = h - 2
        self.s.move(y, 0)
        self.s.clrtoeol()
        self.put(y, 2, label, curses.color_pair(4) | curses.A_BOLD)
        try:
            raw = self.s.getstr(y, 2 + len(label) + 1, 60)
            val = raw.decode("utf-8", "replace").strip()
        except Exception:
            val = ""
        curses.noecho()
        curses.curs_set(0)
        self.s.nodelay(True)
        self.s.timeout(120)
        return val or default

    def draw(self):
        app = self.app
        self.s.erase()
        h, w = self.s.getmaxyx()
        if h < 20 or w < 62:
            self.put(0, 0, "Terminal too small - need at least 62x20", curses.A_BOLD)
            self.s.refresh()
            return

        st = app.meter.stats()
        mean = st["mean"] if st else None
        peak = app.meter.max_hold

        # ---- header
        title = " DEAUTH HUNT "
        self.put(0, 0, "─" * (w - 1), curses.color_pair(4))
        self.put(0, 2, title, curses.color_pair(4) | curses.A_BOLD | curses.A_REVERSE)
        src = f"replay:{os.path.basename(app.args.replay)}" if app.args.replay else app.args.iface
        hdr = f"{src}  ch{app.args.channel}  floor {app.floor or '—'}"
        self.put(0, max(len(title) + 4, w - len(hdr) - 3), hdr, curses.color_pair(4))

        # ---- big readout
        txt = f"{mean:.1f}" if mean is not None else "--.-"
        scale = 2 if w >= 78 else 1
        rows = big_digits(txt, scale)
        top = 2
        for i, r in enumerate(rows):
            self.put(top + i, 3, r, self.heat(mean))
        gw = len(rows[0])
        self.put(top + 1, 5 + gw, "dBm", curses.A_BOLD)
        if st:
            self.put(top + 3, 5 + gw, f"{st['count']} frames / {st['window_s']:.1f}s")
            self.put(top + 4, 5 + gw, f"σ {st['stdev']:.2f} dB")
        else:
            self.put(top + 3, 5 + gw, "no signal", curses.color_pair(2))

        y = top + 6
        bw = max(16, min(40, w - 34))

        # ---- meters
        self.put(y, 3, "SIGNAL ", curses.A_DIM)
        self.grad_bar(y, 11, mean, bw)
        self.put(y, 13 + bw, f"{mean:6.1f} dBm" if mean is not None else "   -- dBm",
                 self.heat(mean))
        y += 1

        age = time.time() - app.meter.max_hold_ts
        self.put(y, 3, "PEAK   ", curses.A_DIM)
        self.grad_bar(y, 11, peak, bw)
        self.put(y, 13 + bw, f"{peak:6d} dBm" if peak is not None else "   -- dBm",
                 self.heat(peak) | curses.A_BOLD)
        self.put(y, 24 + bw, f"{age:.0f}s ago", curses.A_DIM)
        y += 2

        # ---- sparkline
        self.put(y, 3, f"LAST {int(app.meter.spark_s)}s", curses.A_DIM)
        self.put(y, 14, app.meter.sparkline(max(10, w - 20)), curses.color_pair(6))
        y += 2

        # ---- rate / integrity
        fps = st["fps"] if st else 0.0
        stale = ""
        if app.meter.last_frame_ts:
            gap = time.time() - app.meter.last_frame_ts
            if gap > 3:
                stale = f"  ⚠ nothing for {gap:.0f}s"
        self.put(y, 3, f"rate {fps:5.1f} fps   total {app.meter.total:<7d}"
                       f"seq-gaps {app.meter.seq_gaps:<5d}"
                       f"logged {app.written}{stale}",
                 curses.color_pair(2) if stale else 0)
        y += 1

        # ---- transmit guard: continuous proof we are not the problem
        if app.tx.delta is None:
            self.put(y, 3, "TX-GUARD  n/a (replay)", curses.A_DIM)
        elif app.tx.clean:
            self.put(y, 3, f"TX-GUARD  {app.tx.delta} packets transmitted  ",
                     curses.color_pair(3))
            self.put(y, 34, "PASSIVE", curses.color_pair(3) | curses.A_BOLD)
        else:
            self.put(y, 3, f" TRANSMITTED {app.tx.delta} PACKETS - NOT PASSIVE ",
                     curses.color_pair(1) | curses.A_BOLD | curses.A_REVERSE)
        y += 2

        # ---- targets
        if app.meter.targets:
            self.put(y, 3, "TARGET APs", curses.A_DIM)
            y += 1
            tot = sum(app.meter.targets.values())
            for mac, n in app.meter.targets.most_common(4):
                pctg = 100 * n / tot
                self.put(y, 5, f"{mac}x  {n:5d}  {pctg:5.1f}%  "
                               f"{'▍' * max(1, int(pctg / 4))}")
                y += 1
            y += 1

        # ---- waypoints on this floor
        wps = [x for x in app.store.waypoints() if (x["floor"] or "") == (app.floor or "")]
        self.put(y, 3, f"FLOOR {app.floor or '—'} · {len(wps)} waypoints", curses.A_DIM)
        y += 1
        for wp in sorted(wps, key=lambda r: -r["rssi_max"])[:min(5, h - y - 4)]:
            self.put(y, 5, f"{wp['rssi_max']:4d} dBm  {(wp['label'] or '')[:22]:<22} "
                           f"{(wp['heading'] or ''):<8}", self.heat(wp["rssi_max"]))
            y += 1

        # ---- footer
        if app.message and time.time() - app.message_ts < 4:
            self.put(h - 3, 3, app.message[:w - 5], curses.color_pair(3) | curses.A_BOLD)
        if app.capture.error:
            self.put(h - 3, 3, f"tshark: {app.capture.error}"[:w - 5],
                     curses.color_pair(1) | curses.A_BOLD)
        keys = " m mark   f floor   r reset peak   c clear   p pause-log   q quit "
        self.put(h - 1, 0, "─" * (w - 1), curses.color_pair(4))
        self.put(h - 1, 2, keys, curses.color_pair(4) | curses.A_BOLD)
        if app.web_port:
            u = f" http://127.0.0.1:{app.web_port} "
            self.put(h - 1, max(len(keys) + 4, w - len(u) - 3), u, curses.color_pair(4))
        self.s.refresh()


# ==========================================================================
# Application
# ==========================================================================

class App:
    def __init__(self, args):
        self.args = args
        self.floor = args.floor
        self.meter = Meter(window_s=args.window, spark_s=args.spark)
        self.store = Store(args.db)
        self.message = ""
        self.message_ts = 0
        self.written = 0
        self.logging = not args.no_log
        self.web_port = args.web_port
        self.running = True
        self.tx = TxGuard(args.iface if not args.replay else None)

        # audio warmer/colder feedback (same logic as router_hunt.py)
        self.beeper = Beeper(enabled=not args.no_beep)
        self.trend = Trend(window=args.beep_window,
                           sub=min(3.0, args.beep_window / 3))
        self.last_beep = 0.0
        self.last_geiger = 0.0
        self.last_dir = "→"

        if args.any_deauth:
            filt = "wlan.fc.type_subtype==12"
        else:
            filt = f"wlan.fc.type_subtype==12 && wlan.sa=={args.sa}"
        if args.filter:
            filt = args.filter
        self.filter = filt

        self.capture = Capture(iface=args.iface, replay=args.replay,
                               display_filter=filt, paced=not args.fast)
        self.store.start_session(args.iface or args.replay, args.channel, filt)

    def state(self):
        st = self.meter.stats()
        return {
            "iface": self.args.iface or f"replay:{os.path.basename(self.args.replay or '')}",
            "channel": self.args.channel,
            "filter": self.filter,
            "floor": self.floor,
            "total": self.meter.total,
            "peak": self.meter.max_hold,
            "logged": self.written,
            "live": st,
            "tx_delta": self.tx.delta,
            "tx_clean": self.tx.clean,
        }

    def note(self, msg):
        self.message = msg
        self.message_ts = time.time()

    def drain(self):
        n = 0
        while n < 4000:
            try:
                rec = self.capture.q.get_nowait()
            except queue.Empty:
                break
            self.meter.add(rec)
            self.trend.add(rec["ts"], rec["rssi"])
            if self.logging:
                self.store.queue_sample(rec, self.floor)
            n += 1
        return n

    def update_beeps(self):
        """Drive the warmer/colder (or geiger) audio cue from the RSSI trend.

        Called every UI tick. The trend is a smoothed median-vs-median delta so
        a sub-noise-floor threshold like 1 dB is meaningful; geiger mode codes
        absolute strength as both beep rate and pitch.
        """
        now = time.time()
        st = self.meter.stats()
        avg = st["mean"] if st else None
        d = self.trend.delta(now)
        if d is not None:
            if d >= self.args.beep_threshold:
                self.last_dir = "↑"
            elif d <= -self.args.beep_threshold:
                self.last_dir = "↓"
            else:
                self.last_dir = "→"
        if not self.beeper.enabled:
            return
        if not self.args.geiger:
            if d is not None and (now - self.last_beep) >= self.args.beep_interval:
                if d >= self.args.beep_threshold:
                    self.beeper.beep(1, freq=1200)      # warmer: high single
                    self.last_beep = now
                elif d <= -self.args.beep_threshold:
                    self.beeper.beep(2, freq=500)       # colder: low double
                    self.last_beep = now
        else:
            if avg is not None:
                frac = (avg - RSSI_FLOOR) / (RSSI_CEIL - RSSI_FLOOR)
                frac = max(0.0, min(1.0, frac))
                interval = 1.2 - 1.0 * frac              # 1.2s weak .. 0.2s strong
                if (now - self.last_geiger) >= interval:
                    self.beeper.beep(1, freq=500 + 1500 * frac, dur=0.05)
                    self.last_geiger = now

    def mark(self, ui):
        st = self.meter.stats()
        if not st:
            self.note("nothing to mark - no frames in the current window")
            return
        label = ui.prompt("label for this spot:")
        if not label:
            self.note("cancelled")
            return
        heading = ui.prompt("heading/bearing (optional):")
        self.store.add_waypoint(self.floor, label, heading, st, self.meter.max_hold)
        self.note(f"marked '{label}' on floor {self.floor or '—'} "
                  f"— mean {st['mean']:.1f} peak {self.meter.max_hold} dBm")

    def run(self, stdscr):
        ui = UI(stdscr, self)
        self.capture.start()
        last_flush = time.time()
        while self.running:
            self.drain()
            self.update_beeps()
            if time.time() - last_flush > 1.0:
                self.written += self.store.flush()
                self.tx.poll()
                last_flush = time.time()
            ui.draw()
            try:
                key = stdscr.getch()
            except curses.error:
                key = -1
            if key == -1:
                continue
            ch = chr(key) if 0 <= key < 256 else ""
            if ch in ("q", "Q"):
                self.running = False
            elif ch in ("m", "M"):
                self.mark(ui)
            elif ch in ("f", "F"):
                self.floor = ui.prompt("floor:", self.floor) or self.floor
                self.note(f"floor set to {self.floor}")
            elif ch in ("r", "R"):
                self.meter.reset_hold()
                self.note("peak hold reset")
            elif ch in ("c", "C"):
                self.meter.clear()
                self.note("rolling window cleared")
            elif ch in ("p", "P"):
                self.logging = not self.logging
                self.note(f"sample logging {'ON' if self.logging else 'PAUSED'}")
            elif ch in ("b", "B"):
                self.beeper.enabled = not self.beeper.enabled
                mode = "geiger" if self.args.geiger else "warmer/colder"
                self.note(f"beep {mode} {'ON ('+self.beeper.name+')' if self.beeper.enabled else 'OFF'}")

    def shutdown(self):
        self.capture.stop()
        self.written += self.store.flush()
        self.store.close()


def run_selftest(app, seconds):
    """Headless capture check - no curses. Confirms the card is actually hearing
    the attack (and that RSSI is present) before you commit to the full UI."""
    src = app.args.iface or f"replay:{app.args.replay}"
    print(f"Self-test: {seconds:.0f}s on {src}")
    print(f"Filter   : {app.filter}\n")
    app.capture.start()
    t0 = last = time.time()
    while time.time() - t0 < seconds:
        app.drain()
        app.written += app.store.flush()
        now = time.time()
        if now - last >= 1.0:
            st = app.meter.stats()
            if st:
                width = 34
                frac = (st["mean"] - RSSI_FLOOR) / (RSSI_CEIL - RSSI_FLOOR)
                fill = max(0, min(width, int(frac * width)))
                bar = "#" * fill + "." * (width - fill)
                print(f"  {now - t0:5.1f}s  {st['mean']:7.1f} dBm  [{bar}]  "
                      f"peak {app.meter.max_hold:4d}  {st['fps']:5.1f} fps  n={app.meter.total}")
            else:
                print(f"  {now - t0:5.1f}s  -- no frames in window --")
            last = now
        if app.capture.error:
            break
        if app.args.replay and not app.capture.is_alive() and app.capture.q.empty():
            break
        time.sleep(0.05)

    app.drain()
    app.written += app.store.flush()

    print("\n" + "-" * 58)
    ok = True
    if app.capture.error:
        print(f"  FAIL  tshark: {app.capture.error}")
        ok = False
    if app.meter.total == 0:
        print("  FAIL  no matching frames captured")
        print("        wrong channel, wrong signature, or nothing on air")
        ok = False
    else:
        vals = [v for _, v in app.meter.spark] or [0]
        print(f"  frames matched   : {app.meter.total}")
        print(f"  sequence gaps    : {app.meter.seq_gaps}")
        print(f"  RSSI range       : {min(vals)} .. {max(vals)} dBm")
        print(f"  distinct targets : {len(app.meter.targets)}")
        print(f"  samples logged   : {app.written}")
        for mac, n in app.meter.targets.most_common(5):
            print(f"      {mac}x  {n}")

    app.tx.poll()
    if app.tx.delta is None:
        print("  packets TX'd     : n/a (replay - no live interface)")
    elif app.tx.clean:
        print("  packets TX'd     : 0  - verifiably passive")
    else:
        print(f"  packets TX'd     : {app.tx.delta}  *** NOT PASSIVE ***")
        ok = False
    print("-" * 58)
    print("  PASS - capture path works" if ok else "  FAILED")
    return 0 if ok else 1


def detect_iface(driver=None):
    """Pick the interface to hunt with, chip-agnostically.

    Preference: $HUNT_IFACE -> an interface bound to `driver`/$HUNT_DRIVER if
    given -> a wireless interface not currently associated to an AP (the spare
    card, not the one carrying the operator's Wi-Fi), favouring monitor mode
    then USB. Pass driver= (or set $HUNT_DRIVER) to pin a specific chipset.
    """
    base = "/sys/class/net"

    forced = os.environ.get("HUNT_IFACE")
    if forced and os.path.exists(os.path.join(base, forced)):
        return forced

    try:
        names = sorted(os.listdir(base))
    except OSError:
        return None
    ifaces = [n for n in names if os.path.exists(os.path.join(base, n, "phy80211"))]
    if not ifaces:
        return None

    def drv_of(name):
        link = os.path.join(base, name, "device", "driver")
        try:
            return os.path.basename(os.path.realpath(link)) if os.path.exists(link) else None
        except OSError:
            return None

    drv = driver or os.environ.get("HUNT_DRIVER")
    if drv:
        # An explicit pin is strict: match it or fail, never a different card.
        for name in ifaces:
            if drv_of(name) == drv:
                return name
        return None

    def connected(name):
        try:
            out = subprocess.run(["iw", "dev", name, "link"],
                                 capture_output=True, text=True, timeout=5).stdout
        except Exception:
            return False
        return "Connected to" in out

    def is_monitor(name):
        try:
            out = subprocess.run(["iw", "dev", name, "info"],
                                 capture_output=True, text=True, timeout=5).stdout
        except Exception:
            return False
        return any(l.strip().startswith("type ") and l.split()[1] == "monitor"
                   for l in out.splitlines())

    def is_usb(name):
        try:
            return "/usb" in os.path.realpath(os.path.join(base, name, "device"))
        except OSError:
            return False

    free = [n for n in ifaces if not connected(n)]
    pool = free or ifaces
    return sorted(pool, key=lambda n: (0 if is_monitor(n) else 1,
                                       0 if is_usb(n) else 1, n))[0]


def main():
    print("ANTENNA: use 1 directional antenna (one jack, leave the other empty) - "
          "this script direction-finds the emitter by RSSI; a second/omni antenna "
          "pollutes the bearing.", file=sys.stderr)
    p = argparse.ArgumentParser(
        description="Live RSSI meter and per-floor waypoint recorder for deauth direction finding.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--iface", help="monitor-mode interface (default: the spare "
                                    "Wi-Fi card not carrying your connection)")
    p.add_argument("--replay", help="read from a pcap instead of live capture")
    p.add_argument("--fast", action="store_true", help="replay as fast as possible")
    p.add_argument("--channel", type=int, default=DEFAULT_CHANNEL)
    p.add_argument("--sa", default=DEFAULT_SA, help="attacker source MAC to track")
    p.add_argument("--any-deauth", action="store_true",
                   help="track every deauth, not just the known signature")
    p.add_argument("--filter", help="override the tshark display filter entirely")
    p.add_argument("--db", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "hunt.db"))
    p.add_argument("--floor", default="", help="starting floor label")
    p.add_argument("--window", type=float, default=3.0, help="rolling window seconds")
    p.add_argument("--spark", type=float, default=30.0, help="sparkline span seconds")
    p.add_argument("--web-port", type=int, default=8777, help="0 disables the web view")
    p.add_argument("--no-log", action="store_true", help="do not log every sample to SQLite")
    p.add_argument("--selftest", type=float, metavar="SECS",
                   help="headless capture check for N seconds, then exit")
    p.add_argument("--beep-window", type=float, default=10.0,
                   help="trend window for warmer/colder beeps (s)")
    p.add_argument("--beep-threshold", type=float, default=1.0,
                   help="dB of smoothed change that triggers a beep")
    p.add_argument("--beep-interval", type=float, default=1.5,
                   help="minimum seconds between beeps")
    p.add_argument("--geiger", action="store_true",
                   help="continuous rate/pitch-coded beeps instead of up/down")
    p.add_argument("--no-beep", action="store_true", help="disable audio feedback")
    p.add_argument("--test-beep", action="store_true",
                   help="play the warmer/colder/geiger cues and exit (no radio needed)")
    args = p.parse_args()

    if args.test_beep:
        b = Beeper()
        who = "root->user audio" if b._env else "current user"
        print(f"audio backend: {b.name}  ({who})")
        print("warmer (high single 1200 Hz)..."); b.beep(1, freq=1200); time.sleep(0.9)
        print("colder (low double 500 Hz)...");    b.beep(2, freq=500);  time.sleep(1.1)
        print("geiger sweep (rising pitch)...")
        for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
            b.beep(1, freq=500 + 1500 * frac, dur=0.06); time.sleep(0.35)
        time.sleep(0.6)
        print("done. If you heard nothing, tell me the backend line above.")
        return

    if not args.replay and not args.iface:
        args.iface = detect_iface()
        if not args.iface:
            sys.exit("No spare wireless interface found. Plug the adapter in and run "
                     "'sudo ./init-hunt.sh' first, or pass --iface (or set $HUNT_IFACE).")

    if not args.replay:
        mode = ""
        try:
            out = subprocess.run(["iw", "dev", args.iface, "info"],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if line.strip().startswith("type "):
                    mode = line.split()[1]
        except Exception:
            pass
        if mode and mode != "monitor":
            sys.exit(f"{args.iface} is in '{mode}' mode, not monitor.\n"
                     f"Run:  sudo ./init-hunt.sh")

    app = App(args)

    if args.selftest:
        try:
            rc = run_selftest(app, args.selftest)
        finally:
            app.shutdown()
        sys.exit(rc)

    if args.web_port:
        try:
            make_web_server(args.web_port, app.state, app.store)
        except OSError as e:
            app.web_port = None
            print(f"web view disabled: {e}", file=sys.stderr)
            time.sleep(1)

    signal.signal(signal.SIGINT, lambda *_: setattr(app, "running", False))
    try:
        curses.wrapper(app.run)
    finally:
        app.shutdown()
        st = app.store
        print(f"\nSession saved to {args.db}")
        print(f"  {app.meter.total} frames seen, {app.written} samples logged")
        conn = sqlite3.connect(args.db)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT floor, COUNT(*) n, MAX(rssi_max) best FROM waypoint "
            "GROUP BY floor ORDER BY best DESC").fetchall()
        if rows:
            print("\n  Strongest reading per floor:")
            for r in rows:
                print(f"    floor {r['floor'] or '—':<8} {r['n']:2d} points   best {r['best']} dBm")
        conn.close()


if __name__ == "__main__":
    main()
