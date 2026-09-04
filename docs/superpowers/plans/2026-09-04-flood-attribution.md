# Flood Attribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Name the physical beaconing radio behind a spoofed-source deauth/disassoc flood, live in `sniffer.py` and offline over a pcap.

**Architecture:** A new pure-logic module `attribution.py` (stdlib + `device_id` only, no radio, no curses) holds rolling per-frame signal tracks and the four techniques from the floor-6 analysis — RSSI clustering, 3-vector matching with runner-up margin, 5-s-bin fading correlation, sequence continuity — and turns them into a marked `Attribution`. `sniffer.py` starts keeping per-chain RSSI, timestamps and sequence numbers, feeds the tracks, and shows a `LIKELY SOURCE` column; `router_hunt.py`'s hunt screen widens its capture to include beacons and prints a refined line. The engine's offline `--pcap` mode is validated against real floor-6 captures whose answer is already known.

**Tech Stack:** Python 3.13 (needs ≥ 3.10 for `statistics.correlation`), tshark, curses, pytest.

**Spec:** `docs/superpowers/specs/2026-09-04-flood-attribution-design.md`

## Global Constraints

- **Receive-only.** The only new external command is `tshark -r <file>` in offline mode. No new `iw` calls, nothing on the TX path. Live captures change only display filters and `-e` fields.
- **No live identifiers in the repo.** Synthetic tests use `02:00:5e:…` placeholders. Ground-truth tests against real captures assert at most a five-hex-character radio-key tail and are `skipif` the capture is absent. `pcaps/` and `hunt.db` stay gitignored.
- **`attribution.py` imports only stdlib and `device_id`.** `router_hunt.py` and `sniffer.py` import `attribution`; the reverse would be circular.
- **Thresholds are the module constants named in the spec** (`DIST_OK=1.0`, `MARGIN_OK=2.0`, `R_OK=0.6`, `DIST_NONE=6.0`, `MIN_SAMPLES_NO_R=30`, `WINDOW_S=60`, `BIN_S=5`, `VALLEY_DB=5`). Loosening any to pass a ground-truth test is stated in that commit's message with the number.
- **One deviation from the spec, decided here:** radios are keyed by the first five octets **plus the high nibble of the sixth** (`radio_key`, e.g. `02:00:5e:00:0a:c`), not `device_id.base_mac_key`. Reason: the floor-6 channel 44 has two physical radios (`…f1:8a:c0` and `…f1:8a:60`) in the same five-octet block beaconing on one channel; a five-octet key would merge their beacon vectors and break the match. `device_id.base_mac_key` and the NETWORKS view are untouched. Task 13 records this in the spec.
- **Every test in `pytest` stays green after every task.** The existing 62 tests must pass unchanged except where a task explicitly edits a helper.
- **Commit trailer**, every commit:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
  ```
- Run tests from the repo root: `cd /home/cristi/deauth-hunt && python3 -m pytest -q`.

---

## File Structure

| File | Responsibility |
|---|---|
| `attribution.py` *(new)* | `Sample`, `parse_chains`, `radio_key`, `RadioTrack`, `Tracks`; `cluster`, `match`, `fading_r`, `seq_continuity`; `Attribution`, `verdict`, `attribute`, `attribute_channel`; `short_label`, `hunt_line`; `analyse_pcap` + CLI |
| `test_attribution.py` *(new)* | Unit tests per technique, verdict table, display strings, ground-truth tests over real captures (skipped when absent) |
| `sniffer.py` | Capture disassoc, `frame.time_epoch`, `wlan.seq`, chains; `Aggregator.tracks`; flood rows with `type`/`attrib`; `MGMT FLOODS` view; `format_flood_row`; TRACK MAC line; hand `tracks` to the hunt |
| `router_hunt.py` | `parse_hunt` keeps `st`/`bssid`/`ssid`/`chains`/`seq`; `build_target_filter(with_beacons=)`; `feed_tracks`; `hunt(attrib=)` routing + attribution line |
| `test_sniffer.py` | `line()` gains `ts`/`seq`; new tests for disassoc rows, attribution rows, `format_flood_row`, `parse_hunt`, `build_target_filter`, `feed_tracks` |
| `README.md` | Column, markers, offline CLI, technique summary |

---

### Task 1: `attribution.py` — samples, radio key, tracks

**Files:**
- Create: `attribution.py`
- Create: `test_attribution.py`

**Interfaces:**
- Produces:
  - `Sample(ts: float, combined: int, chain_a: int|None, chain_b: int|None, seq: int|None)` namedtuple
  - `parse_chains(field: str) -> list[int]` — all ints in a comma-joined tshark field, combined first
  - `make_sample(ts, chains: list[int], seq) -> Sample | None`
  - `radio_key(mac: str) -> str | None` — `"02:00:5e:00:0a:c"` style, lowercase; `None` if not a MAC
  - `class RadioTrack` with `.key`, `.samples: deque[Sample]`, `.bssids: set`, `.ssids: Counter`, `.name() -> str`
  - `class Tracks(window=WINDOW_S)` with `.bssids: set`, `add_source(freq, sa, subtype, sample)`, `add_radio(freq, bssid, ssid, sample)`, `source(freq, sa, subtype) -> list[Sample]`, `source_keys(freq) -> list[(freq, sa, subtype)]`, `radios_on(freq) -> list[RadioTrack]`
  - constants `DEAUTH=12`, `DISASSOC=10`, `BEACON=8`, `TYPE_NAMES={12:"deauth",10:"disassoc"}`, and every threshold constant

- [ ] **Step 1: Write the failing tests**

```python
# test_attribution.py
"""Unit tests for attribution.py — pure logic, no radio. Run: pytest test_attribution.py"""
import os
import math
import pytest

import attribution as A


# ---- samples / keys / tracks ----

def test_parse_chains_reads_all_values_combined_first():
    assert A.parse_chains("-59,-62,-61") == [-59, -62, -61]
    assert A.parse_chains("-59") == [-59]
    assert A.parse_chains("") == []
    assert A.parse_chains(" -70 , x ,-71 ") == [-70, -71]


def test_make_sample_fills_missing_chains_with_none():
    s = A.make_sample(1.0, [-59, -62, -61], 686)
    assert s == A.Sample(1.0, -59, -62, -61, 686)
    s1 = A.make_sample(1.0, [-59], None)
    assert s1.chain_a is None and s1.chain_b is None
    assert A.make_sample(1.0, [], 1) is None


def test_radio_key_is_five_octets_plus_high_nibble():
    assert A.radio_key("02:00:5E:00:0A:C0") == "02:00:5e:00:0a:c"
    assert A.radio_key("02:00:5e:00:0a:c3") == "02:00:5e:00:0a:c"
    assert A.radio_key("02:00:5e:00:0a:60") == "02:00:5e:00:0a:6"
    assert A.radio_key("not-a-mac") is None
    assert A.radio_key("") is None


def test_tracks_key_deauth_and_disassoc_separately():
    t = A.Tracks()
    t.add_source(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH, A.Sample(1.0, -60, None, None, 1))
    t.add_source(5540, "ff:ff:ff:ff:ff:ff", A.DISASSOC, A.Sample(1.0, -60, None, None, 2))
    assert len(t.source(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH)) == 1
    assert len(t.source(5540, "ff:ff:ff:ff:ff:ff", A.DISASSOC)) == 1
    assert sorted(t.source_keys(5540)) == [(5540, "ff:ff:ff:ff:ff:ff", A.DISASSOC),
                                           (5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH)]
    assert t.source_keys(2437) == []


def test_tracks_evict_samples_older_than_window():
    t = A.Tracks(window=60.0)
    t.add_source(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH, A.Sample(0.0, -60, None, None, 1))
    t.add_source(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH, A.Sample(30.0, -60, None, None, 2))
    t.add_source(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH, A.Sample(61.0, -60, None, None, 3))
    seqs = [s.seq for s in t.source(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH)]
    assert seqs == [2, 3]          # ts=0 fell out of the 60 s window ending at 61


def test_tracks_group_beacons_per_radio_and_remember_bssids():
    t = A.Tracks()
    for last, ssid in (("c0", "Corp"), ("c1", "Guest"), ("c2", ""), ("c1", "Guest")):
        t.add_radio(5220, f"02:00:5e:00:01:{last}", ssid, A.Sample(1.0, -61, -63, -62, None))
    t.add_radio(5220, "02:00:5e:00:01:60", "Corp", A.Sample(1.0, -91, -93, -92, None))
    radios = t.radios_on(5220)
    assert {r.key for r in radios} == {"02:00:5e:00:01:c", "02:00:5e:00:01:6"}
    rc = next(r for r in radios if r.key.endswith(":c"))
    assert rc.bssids == {"02:00:5e:00:01:c0", "02:00:5e:00:01:c1", "02:00:5e:00:01:c2"}
    assert len(rc.samples) == 4
    assert rc.name() == "Guest +2"          # most-seen SSID, +N other BSSIDs
    assert t.bssids >= {"02:00:5e:00:01:c0", "02:00:5e:00:01:60"}
    assert t.radios_on(2437) == []


def test_radio_name_hidden_when_no_ssid_seen():
    t = A.Tracks()
    t.add_radio(2437, "02:00:5e:00:02:a0", "", A.Sample(1.0, -50, None, None, None))
    assert t.radios_on(2437)[0].name() == "<hidden>"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_attribution.py -q`
Expected: FAIL / ERROR with `ModuleNotFoundError: No module named 'attribution'`

- [ ] **Step 3: Write the module skeleton**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest test_attribution.py -q`
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add attribution.py test_attribution.py
git commit -F - <<'EOF'
attribution: samples, radio keys and rolling tracks

Foundation for attributing a spoofed-source flood to a beaconing radio.
Radios are keyed by five octets plus the high nibble of the sixth, because
the floor-6 channel 44 had two physical radios in one five-octet block on
the same channel.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 2: `cluster()` — split a source by RSSI

**Files:**
- Modify: `attribution.py` (append after `Tracks`)
- Modify: `test_attribution.py`

**Interfaces:**
- Consumes: `Sample`, `VALLEY_DB`, `VALLEY_FRAC`
- Produces: `cluster(samples: list[Sample]) -> list[list[Sample]]`, strongest cluster first

- [ ] **Step 1: Write the failing tests**

```python
# ---- 1. clustering ----

def _s(combined, ts=0.0, a=None, b=None, seq=None):
    return A.Sample(ts, combined, a, b, seq)


def test_cluster_one_tight_group_is_one_cluster():
    samples = [_s(-60 + (i % 3)) for i in range(50)]      # -60/-59/-58
    assert len(A.cluster(samples)) == 1


def test_cluster_two_groups_30db_apart_split_strongest_first():
    samples = [_s(-60) for _ in range(50)] + [_s(-90) for _ in range(50)]
    cl = A.cluster(samples)
    assert len(cl) == 2
    assert all(s.combined == -60 for s in cl[0])
    assert all(s.combined == -90 for s in cl[1])


def test_cluster_two_groups_3db_apart_stay_together():
    samples = [_s(-60) for _ in range(50)] + [_s(-63) for _ in range(50)]
    assert len(A.cluster(samples)) == 1


def test_cluster_sparse_tail_does_not_split():
    # 5 stray frames at -75 are <10% of the -60 peak: not a second radio
    samples = [_s(-60) for _ in range(100)] + [_s(-75) for _ in range(5)]
    assert len(A.cluster(samples)) == 1


def test_cluster_empty():
    assert A.cluster([]) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_attribution.py -q -k cluster`
Expected: FAIL with `AttributeError: module 'attribution' has no attribute 'cluster'`

- [ ] **Step 3: Implement**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest test_attribution.py -q`
Expected: 12 passed

- [ ] **Step 5: Commit**

```bash
git add attribution.py test_attribution.py
git commit -F - <<'EOF'
attribution: cluster a spoofed source by RSSI

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 3: `match()` — signal-vector distance to each radio

**Files:**
- Modify: `attribution.py`
- Modify: `test_attribution.py`

**Interfaces:**
- Consumes: `Sample`, `RadioTrack`
- Produces: `Candidate(radio: RadioTrack, dist: float, one_chain: bool)` namedtuple; `match(cluster: list[Sample], radios: list[RadioTrack]) -> list[Candidate]` sorted by `dist` ascending; `_vec(samples) -> tuple[float, ...]` (length 3, or 1 when any chain is missing)

- [ ] **Step 1: Write the failing tests**

```python
# ---- 2. vector matching ----

def _radio(key, combined, a, b, n=20, ts0=0.0):
    r = A.RadioTrack(key)
    for i in range(n):
        r.samples.append(A.Sample(ts0 + i, combined, a, b, None))
    return r


def test_vec_is_three_values_when_chains_present():
    assert A._vec([_s(-59, a=-62, b=-61), _s(-61, a=-64, b=-63)]) == (-60.0, -63.0, -62.0)


def test_vec_falls_back_to_combined_only_if_any_chain_missing():
    assert A._vec([_s(-59, a=-62, b=-61), _s(-61)]) == (-60.0,)


def test_match_picks_closest_radio_and_orders_by_distance():
    cl = [_s(-59, a=-62, b=-61) for _ in range(10)]
    radios = [_radio("02:00:5e:00:01:c", -59, -62, -61),      # 0.0 dB
              _radio("02:00:5e:00:02:a", -61, -62, -61),      # 2.0 dB
              _radio("02:00:5e:00:03:0", -80, -83, -82)]      # ~36 dB
    cands = A.match(cl, radios)
    assert [c.radio.key for c in cands] == ["02:00:5e:00:01:c", "02:00:5e:00:02:a",
                                            "02:00:5e:00:03:0"]
    assert cands[0].dist == pytest.approx(0.0)
    assert cands[1].dist == pytest.approx(2.0)
    assert cands[0].one_chain is False


def test_match_two_chains_separate_radios_a_single_value_cannot():
    # same combined RSSI, opposite chain imbalance -> different bearings
    cl = [_s(-60, a=-58, b=-64) for _ in range(10)]
    radios = [_radio("02:00:5e:00:01:c", -60, -64, -58),
              _radio("02:00:5e:00:02:a", -60, -58, -64)]
    assert A.match(cl, radios)[0].radio.key == "02:00:5e:00:02:a"


def test_match_flags_one_chain_when_either_side_lacks_chains():
    cl = [_s(-60) for _ in range(10)]
    cands = A.match(cl, [_radio("02:00:5e:00:01:c", -60, -62, -61)])
    assert cands[0].one_chain is True
    assert cands[0].dist == pytest.approx(0.0)


def test_match_skips_radios_with_no_samples():
    empty = A.RadioTrack("02:00:5e:00:09:0")
    assert A.match([_s(-60)], [empty]) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_attribution.py -q -k "vec or match"`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Implement**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest test_attribution.py -q`
Expected: 18 passed

- [ ] **Step 5: Commit**

```bash
git add attribution.py test_attribution.py
git commit -F - <<'EOF'
attribution: rank radios by signal-vector distance

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 4: `fading_r()` and `seq_continuity()`

**Files:**
- Modify: `attribution.py`
- Modify: `test_attribution.py`

**Interfaces:**
- Produces: `fading_r(cluster, radio, bin_s=BIN_S) -> (r: float|None, bins: int)`; `seq_continuity(cluster) -> float|None` (0.0–1.0)

- [ ] **Step 1: Write the failing tests**

```python
# ---- 3. fading correlation ----

def _drift(t):
    return 4.0 * math.sin(t / 7.0)      # slow multipath-like wander, ±4 dB


def _track_with_drift(key, base, seed, n=120, dt=0.5):
    import random
    rnd = random.Random(seed)
    r = A.RadioTrack(key)
    for i in range(n):
        t = i * dt
        v = base + _drift(t) + rnd.gauss(0, 0.5)
        r.samples.append(A.Sample(t, v, v - 3, v - 2, None))
    return r


def _cluster_with_drift(base, seed, n=120, dt=0.5, drift=_drift):
    import random
    rnd = random.Random(seed)
    return [A.Sample(i * dt, base + drift(i * dt) + rnd.gauss(0, 0.5), None, None, None)
            for i in range(n)]


def test_fading_r_high_when_flood_and_beacons_share_the_path():
    cl = _cluster_with_drift(-60, seed=1)
    radio = _track_with_drift("02:00:5e:00:01:c", -62, seed=2)
    r, bins = A.fading_r(cl, radio)
    assert bins >= 10
    assert r > 0.9


def test_fading_r_low_for_independent_drift():
    cl = _cluster_with_drift(-60, seed=1, drift=lambda t: 4.0 * math.cos(t / 3.0))
    radio = _track_with_drift("02:00:5e:00:01:c", -62, seed=2)
    r, _ = A.fading_r(cl, radio)
    assert abs(r) < 0.4


def test_fading_r_none_with_fewer_than_four_shared_bins():
    cl = [_s(-60, ts=t) for t in (0, 1, 5, 6, 10, 11)]          # 3 bins
    radio = _radio("02:00:5e:00:01:c", -60, -62, -61, n=20)     # ts 0..19 -> 4 bins
    r, bins = A.fading_r(cl, radio)
    assert r is None and bins == 3


def test_fading_r_none_when_one_side_has_zero_variance():
    cl = [_s(-60, ts=t) for t in range(40)]                     # flat
    radio = _track_with_drift("02:00:5e:00:01:c", -62, seed=3)
    r, bins = A.fading_r(cl, radio)
    assert r is None and bins >= 4


# ---- 4. sequence continuity ----

def test_seq_continuity_perfect_run():
    cl = [_s(-60, ts=i, seq=100 + i) for i in range(20)]
    assert A.seq_continuity(cl) == pytest.approx(1.0)


def test_seq_continuity_every_other_frame_lost():
    cl = [_s(-60, ts=i, seq=100 + 2 * i) for i in range(20)]
    assert A.seq_continuity(cl) == pytest.approx(0.0)


def test_seq_continuity_wraps_at_4096():
    cl = [_s(-60, ts=0, seq=4094), _s(-60, ts=1, seq=4095), _s(-60, ts=2, seq=0)]
    assert A.seq_continuity(cl) == pytest.approx(1.0)


def test_seq_continuity_ignores_duplicate_frames_and_orders_by_time():
    # the sniffer sees each frame twice on this driver; a repeat is neither hit nor miss
    cl = [_s(-60, ts=2, seq=12), _s(-60, ts=0, seq=10), _s(-60, ts=1, seq=11),
          _s(-60, ts=1.1, seq=11)]
    assert A.seq_continuity(cl) == pytest.approx(1.0)


def test_seq_continuity_none_without_two_sequenced_frames():
    assert A.seq_continuity([_s(-60, seq=5)]) is None
    assert A.seq_continuity([_s(-60), _s(-60)]) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_attribution.py -q -k "fading or seq"`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Implement**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest test_attribution.py -q`
Expected: 27 passed

- [ ] **Step 5: Commit**

```bash
git add attribution.py test_attribution.py
git commit -F - <<'EOF'
attribution: fading correlation and sequence continuity

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 5: `Attribution`, `verdict()`, `attribute()`, `attribute_channel()`

**Files:**
- Modify: `attribution.py`
- Modify: `test_attribution.py`

**Interfaces:**
- Consumes: `cluster`, `match`, `fading_r`, `seq_continuity`, `Tracks`
- Produces:
  - `@dataclass Attribution(freq, sa, subtype, samples, rssi_mean, marker, radio, dist, margin, runner_up, runner_dist, fading_r, bins, seq_pct, one_chain)`
  - `verdict(a: Attribution) -> str` one of `"✓" "?" "✗" "–"`
  - `attribute(freq, sa, subtype, tracks) -> list[Attribution]` (one per cluster, strongest first)
  - `attribute_channel(freq, tracks, sa=None) -> list[Attribution]` (every source key on the channel, or only `sa`)
  - `MARK_OK="✓" MARK_MAYBE="?" MARK_NONE="✗" MARK_NA="–"`

- [ ] **Step 1: Write the failing tests**

```python
# ---- 5. verdict + attribute ----

def _attr(**kw):
    base = dict(freq=5540, sa="ff:ff:ff:ff:ff:ff", subtype=A.DEAUTH, samples=100,
                rssi_mean=-60.0, marker=A.MARK_NA, radio=None, dist=None, margin=None,
                runner_up=None, runner_dist=None, fading_r=None, bins=0,
                seq_pct=None, one_chain=False)
    base.update(kw)
    return A.Attribution(**base)


def test_verdict_na_without_any_candidate():
    assert A.verdict(_attr(dist=None)) == A.MARK_NA


def test_verdict_confident_when_all_thresholds_pass():
    r = A.RadioTrack("02:00:5e:00:01:c")
    assert A.verdict(_attr(radio=r, dist=0.5, margin=3.0, fading_r=0.8, bins=6)) == A.MARK_OK


def test_verdict_confident_without_r_if_enough_samples():
    r = A.RadioTrack("02:00:5e:00:01:c")
    assert A.verdict(_attr(radio=r, dist=0.5, margin=3.0, fading_r=None, samples=30)) == A.MARK_OK
    assert A.verdict(_attr(radio=r, dist=0.5, margin=3.0, fading_r=None, samples=29)) == A.MARK_MAYBE


def test_verdict_confident_when_only_radio_on_channel():
    r = A.RadioTrack("02:00:5e:00:01:c")
    assert A.verdict(_attr(radio=r, dist=0.5, margin=None, fading_r=0.9, bins=5)) == A.MARK_OK


def test_verdict_maybe_when_any_threshold_fails():
    r = A.RadioTrack("02:00:5e:00:01:c")
    assert A.verdict(_attr(radio=r, dist=1.5, margin=3.0, fading_r=0.8)) == A.MARK_MAYBE   # dist
    assert A.verdict(_attr(radio=r, dist=0.5, margin=1.0, fading_r=0.8)) == A.MARK_MAYBE   # margin
    assert A.verdict(_attr(radio=r, dist=0.5, margin=3.0, fading_r=0.3)) == A.MARK_MAYBE   # r


def test_verdict_none_beyond_dist_none():
    r = A.RadioTrack("02:00:5e:00:01:c")
    assert A.verdict(_attr(radio=r, dist=6.1, margin=10.0, fading_r=0.9)) == A.MARK_NONE
    assert A.verdict(_attr(radio=r, dist=6.0, margin=1.0, fading_r=0.9)) == A.MARK_MAYBE


def _scene():
    """Channel 5540: a flood at -59/-62/-61 matching radio C, radio A 8 dB off,
    both radios and the flood fading together over 60 s."""
    t = A.Tracks()
    for i in range(120):
        ts = i * 0.5
        d = _drift(ts)
        t.add_source(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH,
                     A.Sample(ts, -59 + d, -62 + d, -61 + d, 600 + i))
        t.add_radio(5540, "02:00:5e:00:01:c0", "Corp", A.Sample(ts, -59 + d, -62 + d, -61 + d, None))
        t.add_radio(5540, "02:00:5e:00:01:c1", "Guest", A.Sample(ts, -59 + d, -62 + d, -61 + d, None))
        t.add_radio(5540, "02:00:5e:00:02:a0", "Other", A.Sample(ts, -67 + d, -70 + d, -69 + d, None))
    return t


def test_attribute_names_matching_radio_with_numbers():
    t = _scene()
    out = A.attribute(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH, t)
    assert len(out) == 1
    a = out[0]
    assert a.marker == A.MARK_OK
    assert a.radio.key == "02:00:5e:00:01:c"
    assert a.radio.name() == "Corp +1"
    assert a.dist == pytest.approx(0.0, abs=1e-6)
    assert a.runner_up.key == "02:00:5e:00:02:a"
    assert a.margin == pytest.approx(math.sqrt(3 * 64), abs=1e-6)
    assert a.fading_r > 0.99 and a.bins >= 10
    assert a.seq_pct == pytest.approx(1.0)
    assert a.samples == 120 and a.rssi_mean == pytest.approx(-59, abs=3)
    assert a.one_chain is False


def test_attribute_returns_one_result_per_cluster():
    t = _scene()
    for i in range(60):                       # a second, weak radio spoofing the same address
        t.add_source(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH,
                     A.Sample(i, -91, -93, -92, 900 + i))
    t.add_radio(5540, "02:00:5e:00:03:60", "Far", A.Sample(1.0, -91, -93, -92, None))
    t.add_radio(5540, "02:00:5e:00:03:60", "Far", A.Sample(2.0, -91, -93, -92, None))
    out = A.attribute(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH, t)
    assert [a.radio.key for a in out] == ["02:00:5e:00:01:c", "02:00:5e:00:03:6"]
    assert out[0].rssi_mean > out[1].rssi_mean


def test_attribute_na_when_no_beacons_on_channel():
    t = A.Tracks()
    for i in range(40):
        t.add_source(5320, "fe:ff:ff:ff:ff:ff", A.DEAUTH, A.Sample(i, -66, -68, -67, i))
    out = A.attribute(5320, "fe:ff:ff:ff:ff:ff", A.DEAUTH, t)
    assert len(out) == 1 and out[0].marker == A.MARK_NA and out[0].radio is None


def test_attribute_none_when_nearest_radio_is_far():
    t = A.Tracks()
    for i in range(40):
        t.add_source(5320, "fe:ff:ff:ff:ff:ff", A.DEAUTH, A.Sample(i, -66, -68, -67, i))
        t.add_radio(5320, "02:00:5e:00:01:c0", "Corp", A.Sample(i, -80, -82, -81, None))
    a = A.attribute(5320, "fe:ff:ff:ff:ff:ff", A.DEAUTH, t)[0]
    assert a.marker == A.MARK_NONE
    assert a.radio.key == "02:00:5e:00:01:c"       # nearest is still reported
    assert a.dist > A.DIST_NONE


def test_attribute_empty_source_gives_nothing():
    assert A.attribute(5540, "ff:ff:ff:ff:ff:ff", A.DEAUTH, A.Tracks()) == []


def test_attribute_channel_covers_every_source_or_just_one():
    t = _scene()
    for i in range(40):
        t.add_source(5540, "fe:ff:ff:ff:ff:ff", A.DISASSOC, A.Sample(i, -67, -70, -69, i))
    allk = A.attribute_channel(5540, t)
    assert {(a.sa, a.subtype) for a in allk} == {("ff:ff:ff:ff:ff:ff", A.DEAUTH),
                                                  ("fe:ff:ff:ff:ff:ff", A.DISASSOC)}
    one = A.attribute_channel(5540, t, sa="fe:ff:ff:ff:ff:ff")
    assert len(one) == 1 and one[0].radio.key == "02:00:5e:00:02:a"
    assert A.attribute_channel(2437, t) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_attribution.py -q -k "verdict or attribute"`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Implement**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest test_attribution.py -q`
Expected: 39 passed

- [ ] **Step 5: Commit**

```bash
git add attribution.py test_attribution.py
git commit -F - <<'EOF'
attribution: verdict and the attribute() entry point

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 6: display strings — `short_label()` and `hunt_line()`

**Files:**
- Modify: `attribution.py`
- Modify: `test_attribution.py`

**Interfaces:**
- Consumes: `Attribution`
- Produces: `short_label(a) -> str` (list column), `hunt_line(a) -> str` (one hunt-screen line, starts with `ATTRIBUTION`), `key_tail(radio) -> str` (`"…00:0a:c*"`)

- [ ] **Step 1: Write the failing tests**

```python
# ---- 6. display ----

def _named_radio(key, ssid, n_bssids=1):
    r = A.RadioTrack(key)
    r.ssids[ssid] += 1
    for i in range(n_bssids):
        r.bssids.add(f"{key}{i:x}")
    return r


def test_key_tail():
    assert A.key_tail(A.RadioTrack("02:00:5e:00:0a:c")) == "…00:0a:c*"


def test_short_label_ok_shows_name_tail_and_margin():
    r = _named_radio("02:00:5e:00:01:c", "Corp", 4)
    a = _attr(marker=A.MARK_OK, radio=r, dist=0.02, margin=1.15)
    assert A.short_label(a) == "✓ Corp +3 (…00:01:c*)  1.2dB"


def test_short_label_ok_only_radio_on_channel():
    r = _named_radio("02:00:5e:00:01:c", "Corp")
    a = _attr(marker=A.MARK_OK, radio=r, dist=0.02, margin=None)
    assert A.short_label(a) == "✓ Corp (…00:01:c*)  only AP on ch"


def test_short_label_maybe_has_no_margin():
    r = _named_radio("02:00:5e:00:01:c", "Corp")
    a = _attr(marker=A.MARK_MAYBE, radio=r, dist=0.5, margin=0.8)
    assert A.short_label(a) == "? Corp (…00:01:c*)"


def test_short_label_none_and_na():
    r = _named_radio("02:00:5e:00:01:c", "Corp")
    assert A.short_label(_attr(marker=A.MARK_NONE, radio=r, dist=9.4)) == \
        "✗ no AP match — separate device?"
    assert A.short_label(_attr(marker=A.MARK_NA)) == "–"


def test_hunt_line_ok_carries_every_number():
    r = _named_radio("02:00:5e:00:01:c", "Corp", 4)
    ru = _named_radio("02:00:5e:00:02:a", "Walkin")
    a = _attr(marker=A.MARK_OK, radio=r, dist=0.02, margin=1.15, runner_up=ru,
              runner_dist=1.17, fading_r=0.985, bins=11, seq_pct=0.91)
    assert A.hunt_line(a) == (
        "ATTRIBUTION   ✓ Corp +3 (…00:01:c*)  dist 0.02dB  margin 1.15dB  "
        "fading r=+0.98 (11 bins)  seq +1: 91%   runner-up Walkin (…00:02:a*)")


def test_hunt_line_maybe_with_missing_r_and_one_chain():
    r = _named_radio("02:00:5e:00:01:c", "Corp")
    a = _attr(marker=A.MARK_MAYBE, radio=r, dist=0.40, margin=None, fading_r=None,
              bins=2, seq_pct=None, one_chain=True)
    assert A.hunt_line(a) == (
        "ATTRIBUTION   ? Corp (…00:01:c*)  dist 0.40dB  (1-chain: combined only)  "
        "margin only AP on ch  fading r=– (2 bins)  seq +1: –")


def test_hunt_line_none_names_nearest():
    r = _named_radio("02:00:5e:00:02:a", "Walkin")
    a = _attr(marker=A.MARK_NONE, radio=r, dist=9.4)
    assert A.hunt_line(a) == ("ATTRIBUTION   ✗ no beaconing AP within 6dB "
                              "(nearest Walkin at 9.4dB) — likely a separate device")


def test_hunt_line_na():
    assert A.hunt_line(_attr(marker=A.MARK_NA)) == \
        "ATTRIBUTION   – no beacons heard on this channel yet"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_attribution.py -q -k "label or hunt_line or key_tail"`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Implement**

```python
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
        s += f"  {a.margin:.1f}dB" if a.margin is not None else "  only AP on ch"
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest test_attribution.py -q`
Expected: 48 passed

- [ ] **Step 5: Commit**

```bash
git add attribution.py test_attribution.py
git commit -F - <<'EOF'
attribution: list-column and hunt-line display strings

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 7: offline mode — `analyse_pcap()`, CLI, ground-truth tests

**Files:**
- Modify: `attribution.py`
- Modify: `test_attribution.py`

**Interfaces:**
- Produces: `PCAP_FIELDS`, `parse_pcap_line(line) -> dict|None` with keys `ts st sa bssid freq chains seq ssid`, `analyse_pcap(path, subtype=None) -> list[Attribution]`, `main()` / `if __name__ == "__main__"`

- [ ] **Step 1: Write the failing tests**

```python
# ---- 7. offline ----

def test_parse_pcap_line_fields_and_hex_ssid():
    line = "|".join(["1756000000.5", "0x0008", "02:00:5e:00:01:c0", "02:00:5e:00:01:c0",
                     "5540", "-59,-62,-61", "686", "436f7270"])
    rec = A.parse_pcap_line(line)
    assert rec == {"ts": 1756000000.5, "st": 8, "sa": "02:00:5e:00:01:c0",
                   "bssid": "02:00:5e:00:01:c0", "freq": 5540,
                   "chains": [-59, -62, -61], "seq": 686, "ssid": "Corp"}


def test_parse_pcap_line_rejoins_pipe_in_ssid_and_handles_missing():
    line = "|".join(["1.0", "8", "02:00:5e:00:01:c0", "02:00:5e:00:01:c0", "2437",
                     "-50", "", "a|b"])
    rec = A.parse_pcap_line(line)
    assert rec["ssid"] == "a|b" and rec["seq"] is None
    assert A.parse_pcap_line("too|short") is None
    assert A.parse_pcap_line("|".join(["x", "8", "", "", "", "", "", ""])) is None


PCAPS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps", "floor6")
CH108 = os.path.join(PCAPS, "floor_6_channel_108.pcapng")
CH44 = os.path.join(PCAPS, "floor_6_channel_44.pcapng")


@pytest.mark.skipif(not os.path.exists(CH108), reason="local capture not present")
def test_floor6_ch108_attributes_to_the_known_radio():
    out = A.analyse_pcap(CH108, subtype=A.DEAUTH)
    spoofed = [a for a in out if a.sa == "ff:ff:ff:ff:ff:ff"]
    assert spoofed, "no spoofed-source deauths found on ch 108"
    best = max(spoofed, key=lambda a: a.samples)
    assert best.marker == A.MARK_OK, A.hunt_line(best)
    assert best.radio.key.endswith("f1:79:4"), A.hunt_line(best)
    assert best.margin is None or best.margin > 1.0
    assert best.fading_r is not None and best.fading_r > 0.9
    assert best.one_chain is False


@pytest.mark.skipif(not os.path.exists(CH44), reason="local capture not present")
def test_floor6_ch44_splits_into_two_radios():
    out = A.analyse_pcap(CH44, subtype=A.DEAUTH)
    spoofed = [a for a in out if a.sa == "ff:ff:ff:ff:ff:ff"]
    assert len(spoofed) == 2, [A.hunt_line(a) for a in spoofed]
    strong, weak = spoofed                     # strongest first
    assert strong.rssi_mean > weak.rssi_mean
    assert strong.radio.key.endswith("f1:8a:c"), A.hunt_line(strong)
    assert weak.radio.key.endswith("f1:8a:6"), A.hunt_line(weak)
    assert strong.marker == A.MARK_OK, A.hunt_line(strong)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_attribution.py -q -k "pcap or floor6"`
Expected: FAIL with `AttributeError` on the parse tests; the two `floor6` tests error the same way (or skip on a machine without `pcaps/`)

- [ ] **Step 3: Implement**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest test_attribution.py -q`
Expected: 52 passed (50 passed + 2 skipped on a machine without `pcaps/floor6/`)

If a `floor6` test fails, run `./attribution.py --pcap pcaps/floor6/floor_6_channel_108.pcapng` and read the numbers. Fix a genuine bug first; only if the engine is right and a threshold is what fails, loosen that constant and put the old and new value in the commit message.

- [ ] **Step 5: Run the CLI by hand and check it against the write-up**

Run: `chmod +x attribution.py && ./attribution.py --pcap pcaps/floor6/floor_6_channel_108.pcapng`
Expected: one row, `✓`, radio tail `…f1:79:4*`, `dist` ≈ 0.02, `margin` ≈ 1.1–1.3, `r` ≈ +0.98, seq `+1` ≈ 80–95 %.

Run: `./attribution.py --pcap pcaps/floor6/floor_6_channel_44.pcapng`
Expected: two rows, `…00:0a:c*` strong and `…f1:8a:6*` weak.

- [ ] **Step 6: Commit**

```bash
git add attribution.py test_attribution.py
git commit -F - <<'EOF'
attribution: offline --pcap mode with ground-truth tests

Runs the engine over a capture via tshark -r. Two tests replay the floor-6
channel 108 and 44 captures (skipped when the gitignored pcaps are absent)
and assert the radios the offline analysis named.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 8: `sniffer.py` capture — disassoc, timestamps, sequence, chains

**Files:**
- Modify: `sniffer.py:49-77` (constants, `COMBINED_FILTER`, `COMBINED_FIELDS`, `_N_FIXED`)
- Modify: `sniffer.py:93-123` (`parse_combined`)
- Modify: `test_sniffer.py:13-18` (`line()` helper)

**Interfaces:**
- Consumes: `attribution.parse_chains`
- Produces: `sniffer.DISASSOC = 10`; `parse_combined` records gain `ts: float|None`, `seq: int|None`, `chains: list[int]`; `_N_FIXED = 18`; `test_sniffer.line(..., ts="", seq="")`

- [ ] **Step 1: Write the failing tests** (append to `test_sniffer.py`)

```python
# ---- capture fields for attribution ----

def test_parse_combined_keeps_chains_ts_and_seq():
    rec = sniffer.parse_combined(line(12, "ff:ff:ff:ff:ff:ff", "02:00:5e:00:01:8c", 5540,
                                      sig="-59,-62,-61", ts="1756000000.25", seq="686"))
    assert rec["rssi"] == -59
    assert rec["chains"] == [-59, -62, -61]
    assert rec["ts"] == 1756000000.25
    assert rec["seq"] == 686


def test_parse_combined_missing_ts_and_seq_are_none():
    rec = sniffer.parse_combined(line(8, "02:00:5e:00:01:80", "02:00:5e:00:01:80", 2437))
    assert rec["chains"] == [-50] and rec["ts"] is None and rec["seq"] is None


def test_combined_capture_includes_disassoc_and_new_fields():
    assert "wlan.fc.type_subtype==10" in sniffer.COMBINED_FILTER
    assert sniffer.COMBINED_FIELDS[-3:] == ["frame.time_epoch", "wlan.seq", "wlan.ssid"]
    assert sniffer._N_FIXED == len(sniffer.COMBINED_FIELDS) - 1
```

- [ ] **Step 2: Update the `line()` helper** in `test_sniffer.py` so the two new fixed fields sit before the SSID tail:

```python
def line(st, sa, bssid, freq, sig="-50", priv="0",
         ht="", vht="", he="", rx8="", rx16="",
         wn="", wm="", wf="", ssid="", ts="", seq=""):
    """Build one COMBINED_FIELDS pipe-line (18 fixed fields + ssid tail)."""
    return "|".join([str(st), sa, sa, "ff:ff:ff:ff:ff:ff", bssid, str(freq),
                     sig, priv, ht, vht, he, rx8, rx16, wn, wm, wf, ts, seq, ssid])
```

- [ ] **Step 3: Run tests to verify the new ones fail and the old ones now fail too**

Run: `python3 -m pytest test_sniffer.py -q`
Expected: many failures — `parse_combined` unpacks 16 fixed fields and the helper now emits 18, so SSIDs come out wrong. That is the signal the helper and parser move together.

- [ ] **Step 4: Implement** in `sniffer.py`

Replace lines 49–50:

```python
DEAUTH = 12
DISASSOC = 10
PROBE_REQ = 4
```

Replace the `COMBINED_FILTER` block (lines 55–59):

```python
COMBINED_FILTER = (f"wlan.fc.type_subtype=={BEACON} || "
                   f"wlan.fc.type_subtype=={PROBE_RESP} || "
                   f"wlan.fc.type_subtype=={DEAUTH} || "
                   f"wlan.fc.type_subtype=={DISASSOC} || "
                   f"wlan.fc.type_subtype=={PROBE_REQ}")
```

Replace the `COMBINED_FIELDS` block and `_N_FIXED` (lines 64–77):

```python
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
```

Add `import attribution` after `import device_id` (line 47).

Replace `parse_combined` (lines 93–123):

```python
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
```

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m pytest -q`
Expected: all pass — 62 original + 3 new in `test_sniffer.py` + 52 in `test_attribution.py` (2 of those skipped without pcaps)

- [ ] **Step 6: Commit**

```bash
git add sniffer.py test_sniffer.py
git commit -F - <<'EOF'
sniffer: capture disassoc, per-chain RSSI, timestamps and sequence numbers

The scan capture already received all of this and threw it away; flood
attribution needs it. rssi stays the first (combined) value so nothing
downstream changes.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 9: `sniffer.py` — `Aggregator.tracks` and attributed flood rows

**Files:**
- Modify: `sniffer.py:126-155` (`Aggregator.__init__`, `add`)
- Modify: `sniffer.py:277-303` (`flood_rows`)
- Modify: `test_sniffer.py`

**Interfaces:**
- Consumes: `attribution.Tracks`, `attribution.make_sample`, `attribution.attribute`, `attribution.TYPE_NAMES`
- Produces: `Aggregator.tracks: attribution.Tracks`; `Aggregator.deauth_ts` / `deauth_rssi` keyed `(freq, src, st)`; `flood_rows()` rows gain `"st"`, `"type"` (`"deauth"`/`"disassoc"`/`""` for the all row) and `"attrib"` (`Attribution` or `None`); a spoofed source with N clusters yields N `src` rows

- [ ] **Step 1: Write the failing tests** (append to `test_sniffer.py`)

```python
# ---- flood attribution in the aggregator ----

def _beacon(bssid, freq, sig, ssid_hex, ts):
    return line(8, bssid, bssid, freq, sig=sig, ssid=ssid_hex, ts=str(ts))


def _flood(sa, freq, sig, ts, seq, st=12):
    return line(st, sa, "02:00:5e:00:09:0c", freq, sig=sig, ts=str(ts), seq=str(seq))


def test_disassoc_rows_are_separate_from_deauth_rows():
    ls = [_flood("ff:ff:ff:ff:ff:ff", 5540, "-59,-62,-61", 1000 + i * 0.1, i) for i in range(20)]
    ls += [_flood("ff:ff:ff:ff:ff:ff", 5540, "-59,-62,-61", 1000 + i * 0.1, i, st=10) for i in range(10)]
    agg = feed(ls, now=1002.0)
    src_rows = [r for r in agg.flood_rows(now=1002.0, rate_threshold=2.0) if r["kind"] == "src"]
    assert sorted(r["type"] for r in src_rows) == ["deauth", "disassoc"]
    assert all(r["src"] == "ff:ff:ff:ff:ff:ff" for r in src_rows)
    allrow = [r for r in agg.flood_rows(now=1002.0) if r["kind"] == "all"][0]
    assert allrow["type"] == "" and allrow["attrib"] is None
    assert allrow["rate"] == pytest.approx(30 / 5.0)


def test_spoofed_flood_row_carries_attribution_to_matching_radio():
    ls = []
    for i in range(40):
        ts = 1000 + i * 0.5
        ls.append(_flood("ff:ff:ff:ff:ff:ff", 5540, "-59,-62,-61", ts, 600 + i))
        ls.append(_beacon("02:00:5e:00:01:c0", 5540, "-59,-62,-61", "436f7270", ts))   # Corp
        ls.append(_beacon("02:00:5e:00:01:c1", 5540, "-59,-62,-61", "4775657374", ts)) # Guest
        ls.append(_beacon("02:00:5e:00:02:a0", 5540, "-67,-70,-69", "4f74686572", ts)) # Other
    agg = feed(ls, now=1020.0)
    rows = [r for r in agg.flood_rows(now=1020.0, rate_threshold=2.0) if r["kind"] == "src"]
    assert len(rows) == 1
    a = rows[0]["attrib"]
    assert a is not None and a.radio.key == "02:00:5e:00:01:c"
    assert rows[0]["rssi"] == -59
    assert rows[0]["type"] == "deauth" and rows[0]["st"] == 12


def test_real_source_deauth_is_not_attributed():
    # an AP we have heard beaconing deauths a client: real source, no attribution
    ls = [_beacon("02:00:5e:00:01:c0", 2437, "-50", "436f7270", 1000.0)]
    ls += [_flood("02:00:5e:00:01:c0", 2437, "-50", 1000 + i * 0.1, i) for i in range(5)]
    agg = feed(ls, now=1001.0)
    rows = [r for r in agg.flood_rows(now=1001.0) if r["kind"] == "src"]
    assert len(rows) == 1 and rows[0]["attrib"] is None
    assert agg.tracks.source(2437, "02:00:5e:00:01:c0", 12) == []


def test_two_rssi_clusters_from_one_spoofed_source_are_two_rows():
    ls = []
    for i in range(40):
        ts = 1000 + i * 0.5
        ls.append(_flood("ff:ff:ff:ff:ff:ff", 5220, "-61,-63,-62", ts, 100 + i))
        ls.append(_beacon("02:00:5e:00:01:c0", 5220, "-61,-63,-62", "436f7270", ts))
    for i in range(20):
        ts = 1000 + i
        ls.append(_flood("ff:ff:ff:ff:ff:ff", 5220, "-91,-93,-92", ts, 500 + i))
        ls.append(_beacon("02:00:5e:00:01:60", 5220, "-91,-93,-92", "436f7270", ts))
    agg = feed(ls, now=1020.0)
    rows = [r for r in agg.flood_rows(now=1020.0, rate_threshold=2.0) if r["kind"] == "src"]
    assert [r["rssi"] for r in rows] == [-61, -91]
    assert [r["attrib"].radio.key for r in rows] == ["02:00:5e:00:01:c", "02:00:5e:00:01:6"]
    assert rows[0]["rate"] > rows[1]["rate"]           # rate split by cluster share
    assert rows[0]["flood"] == rows[1]["flood"]        # the flag is per source


def test_tracks_use_frame_timestamp_not_drain_time():
    agg = feed([_flood("ff:ff:ff:ff:ff:ff", 5540, "-59", 1234.5, 1)], now=9999.0)
    assert agg.tracks.source(5540, "ff:ff:ff:ff:ff:ff", 12)[0].ts == 1234.5
```

Also add `import pytest` at the top of `test_sniffer.py` (after `import sniffer`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_sniffer.py -q -k "disassoc or attribut or clusters or timestamp"`
Expected: FAIL with `KeyError: 'type'` / `AttributeError: 'Aggregator' object has no attribute 'tracks'`

- [ ] **Step 3: Implement**

`Aggregator.__init__` (line 127) — add after `self.freq_ts`:

```python
        self.tracks = attribution.Tracks()   # per-frame RSSI history for attribution
```

`Aggregator.add` (lines 137–155) — replace the beacon and deauth branches:

```python
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
```

`flood_rows` (lines 277–303) — replace whole method:

```python
    def flood_rows(self, now=None, rate_threshold=2.0):
        """Rows for the MGMT FLOODS view: an 'all floods on ch N' row per
        active channel, plus a per-source row - or one row per RSSI cluster
        when a spoofed source turns out to be several radios - hottest
        channel first."""
        now = time.time() if now is None else now
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
            attrs = attribution.attribute(freq, src, st, self.tracks)
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
```

- [ ] **Step 4: Run the whole suite**

Run: `python3 -m pytest -q`
Expected: all pass. The three pre-existing flood tests (`test_raspberry_pi_flood_badged_as_pwnagotchi`, `test_spoofed_source_flood_badged_as_deauther`, `test_low_rate_deauth_not_badged_as_flood`) still pass: their sources never beaconed, so they are attributed, produce one `–` cluster row each, and `rows[0]["flood"]` is unchanged.

- [ ] **Step 5: Commit**

```bash
git add sniffer.py test_sniffer.py
git commit -F - <<'EOF'
sniffer: feed attribution tracks and attribute spoofed flood rows

Flood rows are keyed by (channel, source, subtype), carry the flood type
and an Attribution, and a spoofed source that clusters into several radios
becomes one row per radio.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 10: `sniffer.py` — MGMT FLOODS view, `format_flood_row`, TRACK MAC line, tracks in the target

**Files:**
- Modify: `sniffer.py:1-30` (docstring mode list), `sniffer.py:386-388` (`MODE_NAMES`), `sniffer.py:487-511` (flood view), `sniffer.py:532-547` (MODE_MAC view), `sniffer.py:411-420` and `sniffer.py:562-566` and `sniffer.py:646-660` (target dicts)
- Modify: `test_sniffer.py`

**Interfaces:**
- Consumes: `attribution.short_label`
- Produces: `sniffer.format_flood_row(r, oui, f2c) -> str` (module-level, testable); `sniffer.FLOOD_HEADER: str`; `MODE_NAMES[1] == "MGMT FLOODS"`; target dicts of kind `flood_src`, `flood_all`, `mac` gain `"tracks": agg.tracks`

- [ ] **Step 1: Write the failing tests** (append to `test_sniffer.py`)

```python
# ---- MGMT FLOODS rendering ----

F2C = {5540: 108, 2437: 6}


def test_mode_renamed_to_mgmt_floods():
    assert sniffer.MODE_NAMES[1] == "MGMT FLOODS"


def test_format_flood_row_all_row():
    r = {"kind": "all", "freq": 5540, "src": None, "st": None, "type": "",
         "rate": 12.4, "rssi": None, "flood": True, "attrib": None}
    s = sniffer.format_flood_row(r, OUI, F2C)
    assert s.startswith("⚑ 5.5GHz 108  ")
    assert "ALL floods on ch" in s and s.rstrip().endswith("–")


def test_format_flood_row_spoofed_with_attribution():
    ls = []
    for i in range(40):
        ts = 1000 + i * 0.5
        ls.append(_flood("ff:ff:ff:ff:ff:ff", 5540, "-59,-62,-61", ts, 600 + i))
        ls.append(_beacon("02:00:5e:00:01:c0", 5540, "-59,-62,-61", "436f7270", ts))
        ls.append(_beacon("02:00:5e:00:02:a0", 5540, "-67,-70,-69", "4f74686572", ts))
    agg = feed(ls, now=1020.0)
    r = [x for x in agg.flood_rows(now=1020.0, rate_threshold=2.0) if x["kind"] == "src"][0]
    s = sniffer.format_flood_row(r, OUI, F2C)
    assert "deauth" in s and "ff:ff:ff:ff:ff:ff" in s and "⚠ deauther?" in s
    assert s.rstrip().endswith(sniffer.attribution.short_label(r["attrib"]))
    assert "VENDOR" not in sniffer.FLOOD_HEADER and "LIKELY SOURCE" in sniffer.FLOOD_HEADER
    assert "TYPE" in sniffer.FLOOD_HEADER


def test_format_flood_row_real_source_shows_dash():
    r = {"kind": "src", "freq": 2437, "src": "02:00:5e:00:01:c0", "st": 12,
         "type": "deauth", "rate": 0.2, "rssi": -71, "flood": False, "attrib": None}
    s = sniffer.format_flood_row(r, OUI, F2C)
    assert s.startswith("  2.4GHz   6  deauth  ") and s.rstrip().endswith("–")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_sniffer.py -q -k "mgmt or format_flood"`
Expected: FAIL with `AssertionError` / `AttributeError: module 'sniffer' has no attribute 'format_flood_row'`

- [ ] **Step 3: Implement**

Docstring (lines 11–13) — replace the mode 2 entry:

```
  2. MGMT FLOODS   - channels under a deauth/disassoc flood, ranked by rate,
                     with a LIKELY SOURCE column naming the beaconing radio
                     whose signal matches each spoofed source (attribution.py).
```

`MODE_NAMES` (line 387):

```python
MODE_NAMES = ["NETWORKS", "MGMT FLOODS", "PROBE CLIENTS", "TRACK MAC"]
```

Add after `identity_str` (after line 353), before `resolve_target`:

```python
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
```

Flood view in `select_screen` (lines 487–511) — replace the block from `elif mode == MODE_FLOOD:` to the `_draw_list(...)` call:

```python
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
```

MODE_MAC view (lines 532–547) — in the `else:` (not locating) branch, after the `mac_error` line, add:

```python
                m = mac_input.strip().lower()
                if valid_mac(m):
                    hits = [r for r in agg.flood_rows(now, args.rate)
                            if r["kind"] == "src" and r["src"] == m and r["attrib"]]
                    for i, r in enumerate(hits[:3]):
                        stdscr.addnstr(9 + i, 2,
                                       f"flooding on ch{f2c.get(r['freq'], '?')}: "
                                       f"{attribution.short_label(r['attrib'])}",
                                       w - 3, curses.A_BOLD)
```

Target dicts — add `"tracks": agg.tracks` to each of these returns:

- auto-locate return (line 418–420):
  ```python
            return {"kind": "mac", "mac": locating, "freq": agg.seen_ch[locating],
                    "ident": identity_str(locating, oui), "tracks": agg.tracks}
  ```
- ENTER on a typed MAC already heard (lines 564–565):
  ```python
                    return {"kind": "mac", "mac": m, "freq": agg.seen_ch[m],
                            "ident": identity_str(m, oui), "tracks": agg.tracks}
  ```
- flood ENTER (lines 648–654):
  ```python
                if r["kind"] == "all":
                    return {"kind": "flood_all", "freq": r["freq"], "tracks": agg.tracks}
                return {"kind": "flood_src", "src": r["src"], "freq": r["freq"],
                        "ident": identity_str(r["src"], oui, role="attacker",
                                              is_flood=r["flood"]),
                        "tracks": agg.tracks}
  ```
- probe ENTER (lines 657–659): also add `"tracks": agg.tracks` — a client MAC might be a flood source.

- [ ] **Step 4: Run the whole suite**

Run: `python3 -m pytest -q`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add sniffer.py test_sniffer.py
git commit -F - <<'EOF'
sniffer: MGMT FLOODS view with TYPE and LIKELY SOURCE columns

DEAUTH FLOODS becomes MGMT FLOODS (deauth + disassoc). VENDOR is folded
into DEVICE in this view to pay for the attribution column. TRACK MAC shows
the same attribution when the typed MAC is currently flooding. Targets
carry the scan screen's tracks so the hunt starts warm.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 11: `router_hunt.py` — hunt capture fields, `with_beacons`, `feed_tracks`

**Files:**
- Modify: `router_hunt.py:173-190` (`HUNT_FIELDS`, `parse_hunt`)
- Modify: `router_hunt.py:716-725` (`build_target_filter`)
- Modify: `router_hunt.py` imports (line ~50, after `from deauth_sweep import ...`)
- Modify: `test_sniffer.py`

**Interfaces:**
- Consumes: `attribution.parse_chains`, `attribution.make_sample`, `attribution.Tracks`, `attribution.BEACON/DEAUTH/DISASSOC`
- Produces:
  - `HUNT_FIELDS = ["frame.time_epoch", "wlan.fc.type_subtype", "wlan.sa", "wlan.ta", "wlan.bssid", "radiotap.channel.freq", "radiotap.dbm_antsignal", "wlan.seq", "wlan.ssid"]`
  - `parse_hunt(line) -> {ts, rssi, chains, st, sa, ta, bssid, freq, seq, ssid}`
  - `build_target_filter(bssids=None, sa=None, with_beacons=False) -> (dfilter, label)`
  - `feed_tracks(rec, tracks) -> None` — beacon → `add_radio`; deauth/disassoc whose `sa` is not a known BSSID → `add_source`
  - `is_target(rec, target: set|None) -> bool` — `target=None` means every deauth/disassoc frame is the target; otherwise `sa` or `ta` in the set

- [ ] **Step 1: Write the failing tests** (append to `test_sniffer.py`)

```python
# ---- hunt capture: fields, filter, track routing ----

import router_hunt


def hunt_line(st, sa, ta, bssid, freq, sig="-50", seq="", ssid="", ts="1000.0"):
    return "|".join([ts, str(st), sa, ta, bssid, str(freq), sig, seq, ssid])


def test_parse_hunt_keeps_everything_attribution_needs():
    rec = router_hunt.parse_hunt(hunt_line(12, "ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff",
                                           "02:00:5e:00:01:8c", 5540, "-59,-62,-61", "686"))
    assert rec["rssi"] == -59 and rec["chains"] == [-59, -62, -61]
    assert rec["st"] == 12 and rec["seq"] == 686 and rec["ts"] == 1000.0
    assert rec["bssid"] == "02:00:5e:00:01:8c" and rec["ssid"] == ""


def test_parse_hunt_decodes_ssid_tail_with_pipe():
    rec = router_hunt.parse_hunt(hunt_line(8, "02:00:5e:00:01:c0", "02:00:5e:00:01:c0",
                                           "02:00:5e:00:01:c0", 5540, ssid="a|b"))
    assert rec["ssid"] == "a|b"
    assert router_hunt.parse_hunt("x|8|a|b|c|5540|-50|1|s") is None     # bad ts
    assert router_hunt.parse_hunt(hunt_line(8, "a", "b", "c", 5540, sig="")) is None  # no rssi


def test_hunt_fields_order_matches_parser():
    assert router_hunt.HUNT_FIELDS == ["frame.time_epoch", "wlan.fc.type_subtype",
                                       "wlan.sa", "wlan.ta", "wlan.bssid",
                                       "radiotap.channel.freq", "radiotap.dbm_antsignal",
                                       "wlan.seq", "wlan.ssid"]


def test_build_target_filter_optionally_adds_beacons():
    f, lbl = router_hunt.build_target_filter(sa="ff:ff:ff:ff:ff:ff")
    assert f == "wlan.sa==ff:ff:ff:ff:ff:ff || wlan.ta==ff:ff:ff:ff:ff:ff"
    f2, _ = router_hunt.build_target_filter(sa="ff:ff:ff:ff:ff:ff", with_beacons=True)
    assert f2 == "(wlan.sa==ff:ff:ff:ff:ff:ff || wlan.ta==ff:ff:ff:ff:ff:ff) || wlan.fc.type_subtype==8"
    f3, lbl3 = router_hunt.build_target_filter(bssids={"02:00:5e:00:01:80"}, with_beacons=True)
    assert f3.endswith(") || wlan.fc.type_subtype==8") and lbl3 == "02:00:5e:00:01:80"


def test_is_target_with_set_and_with_none():
    d = router_hunt.parse_hunt(hunt_line(12, "ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", "x", 5540))
    b = router_hunt.parse_hunt(hunt_line(8, "02:00:5e:00:01:c0", "02:00:5e:00:01:c0",
                                         "02:00:5e:00:01:c0", 5540))
    assert router_hunt.is_target(d, {"ff:ff:ff:ff:ff:ff"}) is True
    assert router_hunt.is_target(b, {"ff:ff:ff:ff:ff:ff"}) is False
    assert router_hunt.is_target(d, None) is True          # ALL floods on the channel
    assert router_hunt.is_target(b, None) is False         # a beacon is never the target


def test_feed_tracks_routes_beacons_and_spoofed_floods():
    import attribution
    t = attribution.Tracks()
    b = router_hunt.parse_hunt(hunt_line(8, "02:00:5e:00:01:c0", "02:00:5e:00:01:c0",
                                         "02:00:5e:00:01:c0", 5540, "-59,-62,-61", ssid="436f7270"))
    d = router_hunt.parse_hunt(hunt_line(12, "ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff",
                                         "02:00:5e:00:01:c0", 5540, "-59,-62,-61", "686"))
    real = router_hunt.parse_hunt(hunt_line(12, "02:00:5e:00:01:c0", "02:00:5e:00:01:c0",
                                            "02:00:5e:00:01:c0", 5540, "-59,-62,-61", "7"))
    for rec in (b, d, real):
        router_hunt.feed_tracks(rec, t)
    assert [r.key for r in t.radios_on(5540)] == ["02:00:5e:00:01:c"]
    assert t.radios_on(5540)[0].name() == "Corp"
    assert len(t.source(5540, "ff:ff:ff:ff:ff:ff", 12)) == 1
    assert t.source(5540, "02:00:5e:00:01:c0", 12) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_sniffer.py -q -k "hunt or target_filter or is_target or feed_tracks"`
Expected: FAIL — `parse_hunt` rejects the 9-field line / `AttributeError` for `is_target`, `feed_tracks` / `TypeError` for `with_beacons`

- [ ] **Step 3: Implement**

Add the import after the `deauth_sweep` import (around line 52):

```python
import attribution
```

Replace `HUNT_FIELDS` and `parse_hunt` (lines 173–190):

```python
# ---- hunt: frames transmitted BY the target, plus (optionally) beacons ----
# SSID last: it may contain '|'. The timestamp, subtype, BSSID, per-chain RSSI
# and sequence number feed flood attribution (attribution.py) while hunting;
# the RSSI meter itself reads only "rssi".
HUNT_FIELDS = ["frame.time_epoch", "wlan.fc.type_subtype", "wlan.sa", "wlan.ta",
               "wlan.bssid", "radiotap.channel.freq", "radiotap.dbm_antsignal",
               "wlan.seq", "wlan.ssid"]
_N_HUNT_FIXED = len(HUNT_FIELDS) - 1


def parse_hunt(line):
    parts = line.split("|")
    if len(parts) < len(HUNT_FIELDS):
        return None
    ts, st, sa, ta, bssid, freq, sig, seq = parts[:_N_HUNT_FIXED]
    try:
        ts = float(ts)
    except ValueError:
        return None
    chains = attribution.parse_chains(sig)
    if not chains:
        return None
    return {"ts": ts, "rssi": chains[0], "chains": chains,
            "st": first_int(st),
            "sa": sa.split(",")[0].strip().lower(),
            "ta": ta.split(",")[0].strip().lower(),
            "bssid": bssid.split(",")[0].strip().lower(),
            "freq": first_int(freq), "seq": first_int(seq),
            "ssid": decode_ssid("|".join(parts[_N_HUNT_FIXED:]))}


def is_target(rec, target):
    """Does this hunt-capture record belong to the RSSI meter? `target` is the
    set of MACs being hunted, or None for 'every deauth/disassoc on the channel'."""
    if target is None:
        return rec["st"] in (attribution.DEAUTH, attribution.DISASSOC)
    return rec["sa"] in target or rec["ta"] in target


def feed_tracks(rec, tracks):
    """Route one hunt-capture record into the attribution tracks: beacons to
    their radio, spoofed-source deauth/disassoc to their flood."""
    if not rec["freq"]:
        return
    sample = attribution.make_sample(rec["ts"], rec["chains"], rec["seq"])
    if rec["st"] == attribution.BEACON and rec["bssid"]:
        tracks.add_radio(rec["freq"], rec["bssid"], rec["ssid"], sample)
    elif rec["st"] in (attribution.DEAUTH, attribution.DISASSOC):
        if rec["sa"] and rec["sa"] not in tracks.bssids:
            tracks.add_source(rec["freq"], rec["sa"], rec["st"], sample)
```

Replace `build_target_filter` (lines 716–725):

```python
def build_target_filter(bssids=None, sa=None, with_beacons=False):
    """Display filter for frames sent by the target. with_beacons also passes
    every beacon on the channel - they feed attribution, never the meter."""
    if sa:
        m = sa.lower()
        core, label = f"wlan.sa=={m} || wlan.ta=={m}", sa
    else:
        terms = []
        for b in bssids:
            terms.append(f"wlan.sa=={b}")
            terms.append(f"wlan.ta=={b}")
        core, label = " || ".join(terms), ", ".join(sorted(bssids))
    if with_beacons:
        return f"({core}) || wlan.fc.type_subtype=={attribution.BEACON}", label
    return core, label
```

Check `router_hunt.py`'s own `main()` (search for `build_target_filter(` and `parse_hunt` uses below line 740): the standalone tool calls `build_target_filter(bssids=...)` with no `with_beacons` and consumes `rec["rssi"]` — both unchanged, no edit needed. Confirm with `grep -n 'build_target_filter\|parse_hunt\|HUNT_FIELDS' router_hunt.py`.

- [ ] **Step 4: Run the whole suite**

Run: `python3 -m pytest -q`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add router_hunt.py test_sniffer.py
git commit -F - <<'EOF'
router_hunt: hunt capture keeps chains/seq/subtype, can include beacons

parse_hunt now carries what attribution needs; the meter still reads only
rssi. build_target_filter(with_beacons=True) passes the channel's beacons
alongside the target. is_target/feed_tracks route each record to the meter
or the tracks.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 12: hunt screen attribution line + `sniffer.py` wiring

**Files:**
- Modify: `router_hunt.py:586-710` (`hunt()`)
- Modify: `sniffer.py:355-380` (`resolve_target`), `sniffer.py:773-784` (`main()` hunt call)
- Modify: `test_sniffer.py`

**Interfaces:**
- Consumes: `attribution.attribute_channel`, `attribution.hunt_line`, `is_target`, `feed_tracks`
- Produces:
  - `hunt(stdscr, iface, label, cap, txguard, args, attrib=None)` where `attrib = {"tracks": Tracks, "target": set|None, "freq": int, "sa": str|None}` or `None` (network hunts)
  - `resolve_target(t, f2c) -> (dfilter, label, freq, chan, attrib)` — fifth element is that dict or `None`

- [ ] **Step 1: Write the failing tests** (append to `test_sniffer.py`)

```python
# ---- hunt wiring ----

def test_resolve_target_builds_attrib_context_for_flood_and_mac_only():
    import attribution
    tr = attribution.Tracks()
    f2c = {5540: 108}
    d, lbl, freq, ch, ctx = sniffer.resolve_target(
        {"kind": "flood_src", "src": "ff:ff:ff:ff:ff:ff", "freq": 5540, "tracks": tr}, f2c)
    assert d.endswith("|| wlan.fc.type_subtype==8") and ch == 108
    assert ctx == {"tracks": tr, "target": {"ff:ff:ff:ff:ff:ff"}, "freq": 5540,
                   "sa": "ff:ff:ff:ff:ff:ff"}

    d, _, _, _, ctx = sniffer.resolve_target({"kind": "flood_all", "freq": 5540, "tracks": tr}, f2c)
    assert d == "(wlan.fc.type_subtype==12 || wlan.fc.type_subtype==10) || wlan.fc.type_subtype==8"
    assert ctx["target"] is None and ctx["sa"] is None

    d, _, _, _, ctx = sniffer.resolve_target(
        {"kind": "mac", "mac": "02:00:5e:00:09:01", "freq": 5540, "tracks": tr}, f2c)
    assert ctx["target"] == {"02:00:5e:00:09:01"} and "type_subtype==8" in d

    d, _, _, _, ctx = sniffer.resolve_target(
        {"kind": "net", "bssids": {"02:00:5e:00:01:80"}, "freq": 5540}, f2c)
    assert ctx is None and "type_subtype==8" not in d


def test_resolve_target_without_tracks_gives_no_context():
    d, _, _, _, ctx = sniffer.resolve_target(
        {"kind": "flood_src", "src": "ff:ff:ff:ff:ff:ff", "freq": 5540}, {5540: 108})
    assert ctx is None and "type_subtype==8" not in d
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest test_sniffer.py -q -k resolve_target`
Expected: FAIL with `ValueError: not enough values to unpack` (resolve_target returns 4)

- [ ] **Step 3: Implement `resolve_target`** (replace `sniffer.py:355-380`)

```python
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
```

- [ ] **Step 4: Implement the hunt screen changes** in `router_hunt.py`

Signature (line 586):

```python
def hunt(stdscr, iface, label, cap, txguard, args, attrib=None):
```

After `frames = deque()` (line 601) add:

```python
    attr_lines = []           # attribution.hunt_line() strings, refreshed once a second
    last_attr = 0.0
```

Replace the drain loop body (lines 605–615, from `for _ in range(4000):` through `last_rssi = r`):

```python
        for _ in range(4000):
            try:
                rec = cap.q.get_nowait()
            except queue.Empty:
                break
            if attrib is not None:
                feed_tracks(rec, attrib["tracks"])
                if not is_target(rec, attrib["target"]):
                    continue                     # a beacon: attribution only
            r = rec["rssi"]
            roll.append((rec["ts"], r))
            trend.add(rec["ts"], r)
            frames.append(rec["ts"])
            last_rssi = r
```

After the `fps = len(frames) / 3.0` line add:

```python
        if attrib is not None and now - last_attr >= 1.0:
            attrs = attribution.attribute_channel(attrib["freq"], attrib["tracks"],
                                                  sa=attrib["sa"])
            attr_lines = [attribution.hunt_line(a) for a in attrs] or \
                         [attribution.hunt_line(attribution.Attribution(
                             freq=attrib["freq"], sa=attrib["sa"] or "", subtype=0,
                             samples=0, rssi_mean=0.0, marker=attribution.MARK_NA,
                             radio=None, dist=None, margin=None, runner_up=None,
                             runner_dist=None, fading_r=None, bins=0, seq_pct=None,
                             one_chain=False))]
            last_attr = now
```

In the draw section, after the row-1 key help (`stdscr.addnstr(1, 0, f"beep {audio}   " ...)`), add:

```python
        if attr_lines:
            stdscr.addnstr(2, 0, attr_lines[0], w - 1, curses.A_BOLD)
            for i, extra in enumerate(attr_lines[1:3]):        # further clusters
                stdscr.addnstr(12 + i, 0, extra, w - 1, curses.A_NORMAL)
```

- [ ] **Step 5: Wire `main()` in `sniffer.py`** (lines 773–784)

```python
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
```

Also add `DISASSOC` to nothing new in imports — `sniffer.py` defines it (Task 8); `BEACON` is already imported from `router_hunt`.

- [ ] **Step 6: Run the whole suite and a syntax/import check**

Run: `python3 -m pytest -q && python3 -c "import sniffer, router_hunt, attribution; print('imports ok')"`
Expected: all pass; `imports ok`

- [ ] **Step 7: Live check (operator, needs the radio)**

Run: `sudo ./sniffer.py` on a floor with the flood.
Expected: `MGMT FLOODS` shows `?`/`✓` in `LIKELY SOURCE`; ENTER on a flooded row parks; row 2 of the hunt screen reads `ATTRIBUTION …` with `r=–` at first and a rising bin count, moving to `✓` within ~30 s; `TX-GUARD 0 packets transmitted` unchanged. Record the observed line in the commit message.

- [ ] **Step 8: Commit**

```bash
git add router_hunt.py sniffer.py test_sniffer.py
git commit -F - <<'EOF'
hunt screen: live attribution line while parked on a flood

The hunt capture for flood/MAC targets also passes beacons; they feed the
attribution tracks (warm-started from the scan screen) and never the meter.
Row 2 shows the refined verdict with every number, refreshed each second.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

### Task 13: README and spec note

**Files:**
- Modify: `README.md:12-36` (mode table + intro), `README.md` tools table (`sniffer.py` and new `attribution.py` rows), `README.md` sweep5g section ("Analysing the result" paragraph), `README.md` "What the full-band sweeps found" (one sentence pointing at the live column)
- Modify: `docs/superpowers/specs/2026-09-04-flood-attribution-design.md` (radio-key deviation)

- [ ] **Step 1: Mode table row** — replace the `DEAUTH FLOODS` row in the table at `README.md:20-24`:

```markdown
| **MGMT FLOODS** | channels under a deauth or disassoc flood, ranked by frames/sec, `⚑` = flood, with **TYPE**, **DEVICE**, and **LIKELY SOURCE** — the beaconing radio whose signal matches each spoofed source (`✓` confident · `?` possible · `✗` no AP matches, likely a separate device · `–` no beacons on that channel yet). A spoofed source that is really two radios shows as two rows. An `ALL floods on ch N` row per channel handles everything at once | the attacker's transmitter (or every flood on that channel); the hunt screen then shows the refined attribution with its numbers |
```

And in the `TRACK MAC` row, append to the second column: `; if that MAC is currently flooding, its LIKELY SOURCE is shown under the input box`.

- [ ] **Step 2: New subsection** after `### Antenna` (before the `---` at `README.md:144`):

```markdown
### Flood attribution (LIKELY SOURCE)

A flood's source address is forged, so it says nothing about the transmitter.
The signal does. `attribution.py` keeps a 60-second history of every spoofed
deauth/disassoc frame (combined RSSI, both RX chains, sequence number) and of
every beacon, per channel, and applies the four techniques from the floor-6
offline analysis:

1. **Cluster by RSSI** — one spoofed address may be several radios.
2. **Match the signal vector** `[combined, chain A, chain B]` against every
   radio beaconing on that channel; report the best and the runner-up margin.
3. **Correlate the fading** in 5-second bins — a transmitter and its own
   beacons share one propagation path, so they fade together.
4. **Sequence continuity** — one monotonic counter across many targets means
   one transmit queue (shown, not scored).

`✓` needs a match within 1 dB, a runner-up at least 2 dB further, and fading
r ≥ 0.6 (or 30+ frames when the hop dwell was too short for bins). While the
scanner hops you mostly see `?`; hit ENTER to park and the hunt screen's
`ATTRIBUTION` line fills in and flips to `✓` as bins accumulate. `✗` means no
beaconing AP is within 6 dB of the signal — the evidence that would point at a
hidden device rather than infrastructure.

The same engine runs offline over a capture from `sweep5g.sh`:

```bash
./attribution.py --pcap pcaps/floor6/floor_6_channel_108.pcapng
./attribution.py --pcap pcaps/floor7/floor_7_channel_44.pcapng --type deauth
```

which prints one row per cluster with the distance, margin, fading r, bin
count and sequence continuity — the floor-6 write-up, regenerated by code.
It reads a file; no radio is involved.
```

- [ ] **Step 3: Tools table** — update the `sniffer.py` row's purpose to end with `…adaptive channel hopping, and **live flood attribution**`; add after `device_id.py`:

```markdown
| `attribution.py` | Which beaconing radio is behind a spoofed-source flood: RSSI clustering, signal-vector match, fading correlation, sequence continuity. Feeds the LIKELY SOURCE column live; `--pcap` runs it over a capture (standalone, unit-tested against real captures) |
```

And in the sentence listing the tested modules, change `(`test_device_id.py`, `test_sniffer.py`, `test_hopper.py`)` to `(`test_device_id.py`, `test_sniffer.py`, `test_hopper.py`, `test_attribution.py`)`.

- [ ] **Step 4: sweep5g section** — replace the closing paragraph that begins `**Analysing the result.**`:

```markdown
**Analysing the result.** With the whole band on disk you can attribute frames
rather than just detect them: `./attribution.py --pcap <file>` clusters the
forged deauths by signal vector, correlates their fading against every AP
beaconing on that channel, and names the transmitter — see
[Flood attribution](#flood-attribution-likely-source).
[What the full-band sweeps found](#what-the-full-band-sweeps-found) is that
method applied to a floor's worth of captures.
```

- [ ] **Step 5: Spec note** — in the spec, under `## Engine: attribution.py`, replace the sentence beginning `Physical radio key is` with:

```markdown
Physical radio key is `attribution.radio_key`: the first five octets plus the
high nibble of the sixth (`02:00:5e:00:0a:c`). The spec originally said
`device_id.base_mac_key` (five octets); the floor-6 channel 44 has two radios
in one five-octet block on the same channel, which a five-octet key would
merge. `device_id.base_mac_key` and the NETWORKS view are unchanged.
```

- [ ] **Step 6: Check the README renders and the suite is green**

Run: `grep -n '^#\+ ' README.md | sed -n '1,25p' && python3 -m pytest -q`
Expected: `### Flood attribution (LIKELY SOURCE)` appears between `### Antenna` and `## What we're looking for`; all tests pass

- [ ] **Step 7: Commit**

```bash
git add README.md docs/superpowers/specs/2026-09-04-flood-attribution-design.md
git commit -F - <<'EOF'
README: document flood attribution and the offline --pcap mode

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01R8aDhSUfnFkjoBfv7AeUFx
EOF
```

---

## Self-review

**Spec coverage.** Techniques 1–4 → Tasks 2–4. Engine API, verdict table, thresholds → Tasks 1, 5. Offline CLI → Task 7. Capture changes (`sniffer.py`) → Tasks 8, 9. Capture changes (`router_hunt.py`) → Tasks 11, 12. MGMT FLOODS layout, TRACK MAC line, hunt line, no new keys → Tasks 10, 12. Testing: unit → Tasks 1–6, integration → Tasks 8–11, ground truth → Task 7, manual → Task 12 step 7. README → Task 13. Radio-key deviation recorded in Global Constraints and Task 13.

**Type consistency.** `Tracks.add_radio(freq, bssid, ssid, sample)` is used identically in Tasks 1, 5, 7, 9, 11. `fading_r` returns `(r, bins)` everywhere (Tasks 4, 5). `flood_rows` keys `st/type/attrib` match between Task 9 (producer) and Task 10 (`format_flood_row`). `resolve_target` returns five values in Task 12 and is unpacked as five in `main()`. `hunt(attrib=)` dict keys `tracks/target/freq/sa` match between Task 12's `resolve_target` and `hunt`.

**Placeholder scan.** Every code step carries the code; no "similar to", no TBD.
