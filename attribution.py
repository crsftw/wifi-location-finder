#!/usr/bin/env python3
"""
attribution.py - which beaconing radio is behind a spoofed-source flood?

A deauth/disassoc flood carries a forged source address, so the address says
nothing about the transmitter. The signal does. This module keeps a short
rolling history of per-frame RSSI (combined + per RX chain) and sequence
numbers for every spoofed-source flood and every beaconing radio, then applies
the four techniques from the floor-6 offline analysis:

  1. cluster       - split one spoofed source into the radios behind it, by RSSI
  2. match         - mean [combined, chainA, chainB] vs every radio's beacons
  3. fading_r      - do the flood and the candidate's beacons fade together?
  4. seq_continuity- one sequence counter -> one transmit queue (descriptive)

and turns them into a marked verdict: ✓ confident, ? possible, ✗ no beaconing
AP matches (a separate device), – no beacons on that channel yet.

Pure logic: stdlib + device_id only. No radio, no curses. `--pcap FILE` runs
the same engine over a capture (tshark -r), which is how it is validated.
"""

import argparse
import decimal
import math
import re
import statistics
import subprocess
import sys
from collections import Counter, defaultdict, deque, namedtuple
from dataclasses import dataclass

# ---- thresholds (from the floor-6 numbers: matches 0.02-0.23 dB, runner-ups
# ---- 1.12-10.5 dB, fading r 0.64-0.99) ------------------------------------
WINDOW_S = 60.0           # rolling history kept per track
BIN_S = 5.0               # fading-correlation bin width
MIN_BINS = 4              # fewer shared bins -> r is None
VALLEY_DB = 5             # empty dB run that splits two clusters
VALLEY_FRAC = 0.10        # "empty" = fewer than this fraction of the peak bin
DIST_OK = 1.0             # vector distance for a confident match
MARGIN_OK = 1.1           # runner-up must be this much further away
R_OK = 0.6                # fading correlation for a confident match
DIST_NONE = 6.0           # beyond this, no beaconing AP matches at all
MIN_SAMPLES_NO_R = 30     # ✓ without r needs at least this many frames

BEACON = 8
DISASSOC = 10
DEAUTH = 12
TYPE_NAMES = {DEAUTH: "deauth", DISASSOC: "disassoc"}
SEQ_MOD = 4096

Sample = namedtuple("Sample", "ts combined chain_a chain_b seq")


def parse_chains(field):
    """All ints in a comma-joined tshark radiotap.dbm_antsignal field.
    The driver reports the combined figure first, then one value per chain."""
    out = []
    for tok in str(field or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(int(tok))
        except ValueError:
            pass
    return out


def make_sample(ts, chains, seq):
    if not chains:
        return None
    a = chains[1] if len(chains) > 1 else None
    b = chains[2] if len(chains) > 2 else None
    return Sample(ts, chains[0], a, b, seq)


_MAC = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")


def radio_key(mac):
    """One physical radio's address block: the last five octets, keeping
    only the high nibble of the final one, e.g. '00:5e:00:0a:c'. A vendor
    that enumerates virtual BSSIDs in the low nibble of the last octet is
    absorbed by that truncation; hardware seen in the wild instead
    randomizes the *first* octet per SSID (locally-administered bit set)
    while keeping the trailing block fixed - dropping the first octet
    handles both without misreading noise on it as a different radio."""
    m = (mac or "").lower().replace("-", ":")
    if not _MAC.match(m):
        return None
    return m[3:16]


class RadioTrack:
    def __init__(self, key):
        self.key = key
        self.samples = deque()
        self.bssids = set()
        self.ssids = Counter()

    def name(self):
        """Display name as the NETWORKS device view names it: most-seen SSID
        (or <hidden>), then +N for the radio's other BSSIDs."""
        base = self.ssids.most_common(1)[0][0] if self.ssids else "<hidden>"
        extra = len(self.bssids) - 1
        return f"{base} +{extra}" if extra > 0 else base


class Tracks:
    """Rolling per-frame history: spoofed-source floods and beaconing radios,
    both keyed by frequency so a radio is only ever matched against floods on
    its own channel."""

    def __init__(self, window=WINDOW_S):
        self.window = window
        self.sources = {}      # (freq, sa, subtype) -> deque[Sample]
        self.radios = {}       # (freq, radio_key)   -> RadioTrack
        self.bssids = set()    # every BSSID ever heard beaconing (any channel)

    def _evict(self, dq, now):
        cutoff = now - self.window
        while dq and dq[0].ts < cutoff:
            dq.popleft()

    def add_source(self, freq, sa, subtype, sample):
        dq = self.sources.setdefault((freq, sa, subtype), deque())
        dq.append(sample)
        self._evict(dq, sample.ts)

    def add_radio(self, freq, bssid, ssid, sample):
        key = radio_key(bssid)
        if key is None:
            return
        r = self.radios.get((freq, key))
        if r is None:
            r = self.radios[(freq, key)] = RadioTrack(key)
        r.samples.append(sample)
        self._evict(r.samples, sample.ts)
        r.bssids.add(bssid.lower())
        if ssid:
            r.ssids[ssid] += 1
        self.bssids.add(bssid.lower())

    def source(self, freq, sa, subtype):
        return list(self.sources.get((freq, sa, subtype), ()))

    def source_keys(self, freq):
        return [k for k in self.sources if k[0] == freq and self.sources[k]]

    def radios_on(self, freq):
        return [r for (f, _), r in self.radios.items() if f == freq]


# ==========================================================================
# 1. Clustering: one spoofed source address may be several radios
# ==========================================================================

def cluster(samples):
    """Split samples on combined RSSI. Walk a 1 dB histogram from the
    strongest bin down; a run of >= VALLEY_DB bins each holding < VALLEY_FRAC
    of the current cluster's peak, followed by a bin that is not, starts a
    new cluster. Weak tails under the fraction are absorbed, not split.
    Returns clusters strongest first."""
    if not samples:
        return []
    hist = Counter(int(round(s.combined)) for s in samples)
    lo, hi = min(hist), max(hist)
    cuts = []            # descending dB values; a cut's bin and below start a new cluster
    peak = 0
    valley = 0
    for db in range(hi, lo - 1, -1):
        c = hist.get(db, 0)
        if c and c >= VALLEY_FRAC * peak:
            if valley >= VALLEY_DB:
                cuts.append(db)
                peak = 0
            peak = max(peak, c)
            valley = 0
        else:
            valley += 1
    groups = [[] for _ in range(len(cuts) + 1)]
    for s in samples:
        v = int(round(s.combined))
        idx = sum(1 for cut in cuts if v <= cut)
        groups[idx].append(s)
    return [g for g in groups if g]


# ==========================================================================
# 2. Vector matching: [combined, chain A, chain B] vs each radio's beacons
# ==========================================================================

Candidate = namedtuple("Candidate", "radio dist one_chain")


def _vec(samples):
    """Mean signal vector. Three values when every sample carries both chains,
    otherwise just the combined mean (single-chain drivers, or mixed data)."""
    comb = statistics.fmean(s.combined for s in samples)
    if all(s.chain_a is not None and s.chain_b is not None for s in samples):
        return (comb,
                statistics.fmean(s.chain_a for s in samples),
                statistics.fmean(s.chain_b for s in samples))
    return (comb,)


def match(cluster, radios):
    """Every radio ranked by Euclidean distance (dB) between the cluster's
    mean vector and the radio's mean beacon vector. Two RX chains give a
    coarse bearing signature that one combined value cannot."""
    cv = _vec(cluster)
    out = []
    for r in radios:
        if not r.samples:
            continue
        rv = _vec(r.samples)
        n = min(len(cv), len(rv))
        d = math.sqrt(sum((cv[i] - rv[i]) ** 2 for i in range(n)))
        out.append(Candidate(r, d, n == 1))
    out.sort(key=lambda c: c.dist)
    return out


# ==========================================================================
# 3. Fading correlation: a transmitter and its own beacons share one path
# ==========================================================================

def _bin_means(samples, bin_s):
    bins = defaultdict(list)
    for s in samples:
        bins[int(s.ts // bin_s)].append(s.combined)
    return {k: statistics.fmean(v) for k, v in bins.items() if len(v) >= 2}


def fading_r(cluster, radio, bin_s=BIN_S):
    """Pearson r between per-bin mean RSSI of the cluster and of the radio's
    beacons, over bins where both have >= 2 samples. (None, n) when fewer
    than MIN_BINS bins are shared or either side is flat."""
    a = _bin_means(cluster, bin_s)
    b = _bin_means(radio.samples, bin_s)
    keys = sorted(set(a) & set(b))
    if len(keys) < MIN_BINS:
        return None, len(keys)
    xs = [a[k] for k in keys]
    ys = [b[k] for k in keys]
    try:
        return statistics.correlation(xs, ys), len(keys)
    except statistics.StatisticsError:      # zero variance on one side
        return None, len(keys)


# ==========================================================================
# 4. Sequence continuity: one counter -> one transmit queue (descriptive)
# ==========================================================================

def seq_continuity(cluster):
    """Fraction of time-ordered consecutive frames whose sequence number
    advances by exactly +1 (mod 4096). Repeated frames (same seq) are skipped.
    None with fewer than two sequenced frames."""
    seqs = [s.seq for s in sorted(cluster, key=lambda s: s.ts) if s.seq is not None]
    pairs = [(p, q) for p, q in zip(seqs, seqs[1:]) if q != p]
    if not pairs:
        return None
    hits = sum(1 for p, q in pairs if (q - p) % SEQ_MOD == 1)
    return hits / len(pairs)


# ==========================================================================
# 5. Verdict
# ==========================================================================

MARK_OK, MARK_MAYBE, MARK_NONE, MARK_NA = "✓", "?", "✗", "–"


@dataclass
class Attribution:
    freq: int
    sa: str
    subtype: int
    samples: int
    rssi_mean: float
    marker: str
    radio: object            # RadioTrack or None
    dist: float
    margin: float            # None when the radio is the only candidate
    runner_up: object        # RadioTrack or None
    runner_dist: float
    fading_r: float
    bins: int
    seq_pct: float
    one_chain: bool

    @property
    def type_name(self):
        return TYPE_NAMES.get(self.subtype, str(self.subtype))


def verdict(a):
    """✓ confident, ? some threshold fails, ✗ nothing beacons within
    DIST_NONE (a separate device), – no beacons on the channel at all."""
    if a.dist is None:
        return MARK_NA
    if a.dist > DIST_NONE:
        return MARK_NONE
    ok_dist = a.dist <= DIST_OK
    ok_margin = a.margin is None or a.margin >= MARGIN_OK
    if a.fading_r is not None:
        ok_r = a.fading_r >= R_OK
    else:
        ok_r = a.samples >= MIN_SAMPLES_NO_R
    return MARK_OK if (ok_dist and ok_margin and ok_r) else MARK_MAYBE


def attribute(freq, sa, subtype, tracks):
    """One Attribution per RSSI cluster of this spoofed source, strongest first."""
    samples = tracks.source(freq, sa, subtype)
    radios = [r for r in tracks.radios_on(freq) if r.samples]
    out = []
    for cl in cluster(samples):
        a = Attribution(freq=freq, sa=sa, subtype=subtype, samples=len(cl),
                        rssi_mean=statistics.fmean(s.combined for s in cl),
                        marker=MARK_NA, radio=None, dist=None, margin=None,
                        runner_up=None, runner_dist=None, fading_r=None, bins=0,
                        seq_pct=seq_continuity(cl), one_chain=False)
        cands = match(cl, radios)
        if cands:
            best = cands[0]
            a.radio, a.dist, a.one_chain = best.radio, best.dist, best.one_chain
            if len(cands) > 1:
                a.runner_up, a.runner_dist = cands[1].radio, cands[1].dist
                a.margin = cands[1].dist - best.dist
            a.fading_r, a.bins = fading_r(cl, best.radio)
        a.marker = verdict(a)
        out.append(a)
    return out


def attribute_channel(freq, tracks, sa=None):
    """Attributions for every spoofed source on a channel (or only `sa`)."""
    out = []
    for (f, s, st) in sorted(tracks.source_keys(freq)):
        if sa is not None and s != sa:
            continue
        out.extend(attribute(f, s, st, tracks))
    return out


# ==========================================================================
# 6. Display strings (shared by the list column and the hunt screen)
# ==========================================================================

def key_tail(radio):
    """'…00:0a:c*' — the last two octets and the block nibble of a radio key."""
    return f"…{radio.key[-7:]}*"


def _name(radio):
    return f"{radio.name()} ({key_tail(radio)})"


def short_label(a):
    """The LIKELY SOURCE cell: marker, radio, and the margin when confident."""
    if a.marker == MARK_NA:
        return MARK_NA
    if a.marker == MARK_NONE:
        return f"{MARK_NONE} no AP match — separate device?"
    s = f"{a.marker} {_name(a.radio)}"
    if a.marker == MARK_OK:
        if a.margin is not None:
            margin_rounded = float(decimal.Decimal(str(a.margin)).quantize(
                decimal.Decimal('0.1'), rounding=decimal.ROUND_HALF_UP))
            s += f"  {margin_rounded:.1f}dB"
        else:
            s += "  only AP on ch"
    return s


def hunt_line(a):
    """One line for the hunt screen, with every number behind the verdict."""
    if a.marker == MARK_NA:
        return f"ATTRIBUTION   {MARK_NA} no beacons heard on this channel yet"
    if a.marker == MARK_NONE:
        near = f" (nearest {a.radio.name()} at {a.dist:.1f}dB)" if a.radio else ""
        return (f"ATTRIBUTION   {MARK_NONE} no beaconing AP within {DIST_NONE:.0f}dB"
                f"{near} — likely a separate device")
    chain = "  (1-chain: combined only)" if a.one_chain else ""
    margin = f"{a.margin:.2f}dB" if a.margin is not None else "only AP on ch"
    r = f"{a.fading_r:+.2f}" if a.fading_r is not None else "–"
    seq = f"{a.seq_pct * 100:.0f}%" if a.seq_pct is not None else "–"
    ru = f"   runner-up {_name(a.runner_up)}" if a.runner_up else ""
    return (f"ATTRIBUTION   {a.marker} {_name(a.radio)}  dist {a.dist:.2f}dB{chain}  "
            f"margin {margin}  fading r={r} ({a.bins} bins)  seq +1: {seq}{ru}")


# ==========================================================================
# 7. Offline: the same engine over a capture file
# ==========================================================================

PCAP_FIELDS = ["frame.time_epoch", "wlan.fc.type_subtype", "wlan.sa", "wlan.bssid",
               "radiotap.channel.freq", "radiotap.dbm_antsignal", "wlan.seq",
               "wlan.ssid"]                     # ssid last: it may contain '|'
_N_PCAP_FIXED = len(PCAP_FIELDS) - 1
_PCAP_FILTER = (f"wlan.fc.type_subtype=={BEACON} || wlan.fc.type_subtype=={DEAUTH}"
                f" || wlan.fc.type_subtype=={DISASSOC}")


def _first_int(v):
    for tok in str(v or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            return int(tok, 0) if tok.lower().startswith("0x") else int(tok)
        except ValueError:
            return None
    return None


def _decode_ssid(raw):
    """tshark 4.x emits SSIDs as hex; hidden ones as '<MISSING>' or empty."""
    raw = (raw or "").strip()
    if not raw or raw == "<MISSING>":
        return ""
    if len(raw) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", raw):
        try:
            return bytes.fromhex(raw).decode("utf-8", "replace").rstrip("\x00")
        except ValueError:
            return raw
    return raw


def parse_pcap_line(line):
    parts = line.split("|")
    if len(parts) < len(PCAP_FIELDS):
        return None
    ts, st, sa, bssid, freq, sig, seq = parts[:_N_PCAP_FIXED]
    try:
        ts = float(ts)
    except ValueError:
        return None
    return {"ts": ts, "st": _first_int(st),
            "sa": sa.split(",")[0].strip().lower(),
            "bssid": bssid.split(",")[0].strip().lower(),
            "freq": _first_int(freq), "chains": parse_chains(sig),
            "seq": _first_int(seq),
            "ssid": _decode_ssid("|".join(parts[_N_PCAP_FIXED:]))}


def analyse_pcap(path, subtype=None):
    """Run the engine over a capture. Beacons are read first so every BSSID
    is known before deciding which deauth/disassoc sources are spoofed.
    Receive-only by construction: this reads a file."""
    cmd = ["tshark", "-r", path, "-n", "-Q", "-Y", _PCAP_FILTER,
           "-T", "fields", "-E", "separator=|", "-E", "occurrence=a"]
    for f in PCAP_FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    tracks = Tracks(window=float("inf"))
    floods = []
    for line in out.splitlines():
        rec = parse_pcap_line(line)
        if rec is None or not rec["freq"] or not rec["chains"]:
            continue
        sample = make_sample(rec["ts"], rec["chains"], rec["seq"])
        if rec["st"] == BEACON and rec["bssid"]:
            tracks.add_radio(rec["freq"], rec["bssid"], rec["ssid"], sample)
        elif rec["st"] in (DEAUTH, DISASSOC):
            floods.append((rec, sample))
    for rec, sample in floods:
        if rec["sa"] in tracks.bssids:      # a real AP deauthing its client
            continue
        tracks.add_source(rec["freq"], rec["sa"], rec["st"], sample)
    results = []
    for freq in sorted({k[0] for k in tracks.sources}):
        for a in attribute_channel(freq, tracks):
            if subtype is None or a.subtype == subtype:
                results.append(a)
    return results


def main():
    p = argparse.ArgumentParser(
        description="Attribute spoofed-source deauth/disassoc floods in a capture "
                    "to the beaconing radio behind them (reads a file; no radio).")
    p.add_argument("--pcap", required=True, help="pcap/pcapng to analyse")
    p.add_argument("--type", choices=["deauth", "disassoc"],
                   help="only this flood type (default: both)")
    args = p.parse_args()
    st = {"deauth": DEAUTH, "disassoc": DISASSOC}.get(args.type)
    try:
        results = analyse_pcap(args.pcap, subtype=st)
    except subprocess.CalledProcessError as e:
        sys.exit(f"tshark failed: {(e.stderr or '').strip()}")
    except FileNotFoundError:
        sys.exit("tshark not found (install wireshark-common)")
    if not results:
        print("no spoofed-source floods in this capture")
        return
    print(f"{'freq':>5} {'type':<8} {'source':<17} {'frames':>6} {'RSSI':>6}  verdict")
    for a in results:
        print(f"{a.freq:>5} {a.type_name:<8} {a.sa:<17} {a.samples:>6} "
              f"{a.rssi_mean:>6.1f}  {hunt_line(a)[len('ATTRIBUTION   '):]}")


if __name__ == "__main__":
    main()
