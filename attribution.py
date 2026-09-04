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
import math
import re
import statistics
import subprocess
import sys
from collections import Counter, defaultdict, deque, namedtuple
from dataclasses import dataclass

# ---- thresholds (from the floor-6 numbers: matches 0.02-0.17 dB, runner-ups
# ---- 1.15-10.5 dB, fading r 0.69-0.99) ------------------------------------
WINDOW_S = 60.0           # rolling history kept per track
BIN_S = 5.0               # fading-correlation bin width
MIN_BINS = 4              # fewer shared bins -> r is None
VALLEY_DB = 5             # empty dB run that splits two clusters
VALLEY_FRAC = 0.10        # "empty" = fewer than this fraction of the peak bin
DIST_OK = 1.0             # vector distance for a confident match
MARGIN_OK = 2.0           # runner-up must be this much further away
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
    """One physical radio's address block: first five octets plus the high
    nibble of the sixth, e.g. '02:00:5e:00:0a:c'. Multi-BSSID radios hand out
    their virtual BSSIDs inside one such 16-address block, and two radios of
    the same model can share the five-octet prefix on one channel."""
    m = (mac or "").lower().replace("-", ":")
    if not _MAC.match(m):
        return None
    return m[:16]


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
