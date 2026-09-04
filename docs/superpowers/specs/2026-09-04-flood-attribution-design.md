# Flood attribution: naming the radio behind a spoofed-source flood

**Date:** 2026-09-04
**Status:** approved design, awaiting implementation plan

## Problem

A deauth or disassoc flood carries a spoofed source address (`ff:ff:ff:ff:ff:ff`,
`fe:ff:ff:ff:ff:ff`, …). `sniffer.py` can hunt it by RSSI, but the list only says
"spoofed source, unknown". The floor-6 offline analysis showed the transmitter
can be *attributed* — every forged frame on that floor matched a beaconing
neighbour-network radio by signal vector and fading correlation, which changed
the conclusion from "hidden rogue device" to "infrastructure containment".

This design brings those techniques into `sniffer.py` so the same answer appears
live, and adds an offline mode so the engine can be validated against captures
where the answer is already known.

## Scope

- Attribute **deauth (subtype 12) and disassoc (subtype 10)** floods with a
  spoofed source to a physical beaconing radio on the same channel.
- Show the result as a column in the flood list (renamed `MGMT FLOODS`) and in
  `TRACK MAC`, and as a refined line on the hunt screen.
- Offline CLI over a pcap for validation and post-sweep analysis.

Out of scope: control-frame floods (no source address to attribute), cross-channel
reasoning, persistence, vendor lookup (stays in `device_id.py`).

## Techniques

All four are the ones used in the floor-6 analysis, in the same order.

1. **RSSI clustering.** One spoofed source on one channel may be several radios
   (ch 44 had two, at −61 and −91 dBm). Frames are split on combined RSSI:
   1 dB histogram, cut at any valley ≥ 5 dB wide whose bins hold < 10 % of the
   neighbouring peak. Each cluster is attributed separately.
2. **Signal-vector matching.** Mean `[combined, chain A, chain B]` of the cluster
   vs the mean beacon vector of every radio beaconing on that channel; Euclidean
   distance in dB. Best candidate and runner-up give `dist` and `margin`.
   Two RX chains give a coarse bearing signature a single value cannot.
3. **Fading correlation.** Pearson r between per-5-s-bin mean combined RSSI of
   the cluster and of a candidate, over bins where both have ≥ 2 samples.
   `None` with < 4 shared bins. A transmitter and its own beacons share one
   propagation path and fade together.
4. **Sequence continuity.** Fraction of time-ordered consecutive frames whose
   `wlan.seq` advances by exactly +1 (mod 4096). Descriptive only — it collapses
   at weak RSSI through capture loss, not attribution error — shown, not scored.

## Engine: `attribution.py`

Pure logic, no radio, no curses. Same standing as `device_id.py`.

```
Sample      = (ts, combined, chain_a, chain_b, seq)   # chains may be None
Tracks
  sources[(freq, sa, subtype)] -> deque[Sample]        # spoofed-source frames
  radios[(freq, base_mac)]     -> RadioTrack           # beacons per physical radio
      .samples deque[Sample], .bssids set, .ssids Counter
  add_source(freq, sa, subtype, sample)
  add_radio(freq, base_mac, bssid, ssid, sample)
  radios_on(freq) -> [RadioTrack]
  evict(now)      # drop samples older than WINDOW_S
cluster(samples) -> [list[Sample]]
match(cluster, radios) -> [(radio, dist)] sorted by dist
fading_r(cluster, radio, bin_s=5.0) -> float | None
seq_continuity(cluster) -> float | None
attribute(freq, sa, subtype, tracks) -> [Attribution]  # one per cluster
analyse_pcap(path, subtype=None) -> [Attribution]      # offline
```

`Attribution` carries: `marker`, `radio` (or None), `dist`, `margin`, `runner_up`,
`fading_r`, `bins`, `seq_pct`, `samples`, `rssi_mean`, `one_chain` (bool).

Physical radio key is `attribution.radio_key`: octets 2–5 plus the high
nibble of octet 6 (`00:5e:00:0a:c` for `02:00:5e:00:0a:c0`). The spec
originally said `device_id.base_mac_key` (five octets). Two allocation
schemes appear in the floor-6 data — virtual BSSIDs enumerated in the low
nibble of the last octet, or a per-SSID first octet with a fixed trailing
block — and only this key collapses both to one radio; a five-octet key
merged two radios on channel 44 and split one radio into several tracks
elsewhere, collapsing the runner-up margin. `device_id.base_mac_key` and
the NETWORKS view are unchanged.

### Verdict

| Marker | Condition | Meaning |
|---|---|---|
| `✓` | dist ≤ 1.0 dB and margin ≥ 1.0 dB and (r ≥ 0.6, or r is None with ≥ 30 samples) | confident |
| `?` | a best candidate exists but some threshold fails | possibly X |
| `✗` | best dist > 6.0 dB, or no radio within range | no beaconing AP matches — likely a separate device |
| `–` | no beacons seen on the channel | cannot say |

Thresholds are module constants (`DIST_OK=1.0`, `MARGIN_OK=1.0`, `R_OK=0.6`,
`DIST_NONE=6.0`, `MIN_SAMPLES_NO_R=30`, `WINDOW_S=60`, `BIN_S=5`, `VALLEY_DB=5`),
set from the floor-6 numbers: matches 0.02–0.17 dB, runner-ups 1.15–10.5 dB,
r 0.69–0.99. Loosening any of them to make a ground-truth test pass is stated in
the commit message with the number. MARGIN_OK was lowered from 2.0 during
implementation: the channel-108 ground-truth margin is 1.12 dB, and the
sibling-track collapse that the radio-key fix removed was ~0.02 dB, so 1.0
keeps the same discrimination without sitting on the boundary.

`✗` is a first-class finding, not a failure: "no beaconing AP within 6 dB of
this signal" is exactly the evidence that would point at a hidden device, so the
column distinguishes infrastructure containment from a rogue transmitter.

### Offline CLI

`./attribution.py --pcap FILE [--type deauth|disassoc]` runs tshark over the
capture, feeds the same `Tracks`, and prints one table row per cluster with all
numbers. This regenerates the floor-6 write-up by code and is the validation path.

## Capture changes

### `sniffer.py` (scan)

- `COMBINED_FILTER` adds `wlan.fc.type_subtype==10`.
- `COMBINED_FIELDS` adds `wlan.seq` in the fixed block; `_N_FIXED` → 17.
  `test_sniffer.line()` gains the field with a default so existing tests stand.
- `parse_combined`: `rssi` stays the first value; new `chains` = all values as
  ints (pattern from `deauth_hunt.py:445`); new `seq`.
- `Aggregator.tracks = attribution.Tracks()`. In `add()`: beacons →
  `add_radio`; deauth/disassoc with a spoofed source → `add_source`.
  Spoofed = broadcast-ish source, or a source that has never been heard to
  beacon. Real-source AP→client deauths count toward flood rate as now and are
  not attributed.
- `deauth_ts` / `deauth_rssi` keyed by `(freq, src, subtype)`.
- `flood_rows()` rows gain `type` and `attrib`; a source with N clusters yields N
  rows. Computed on each redraw — a few hundred samples, cheap.

### `router_hunt.py` (hunt)

- `HUNT_FIELDS` adds `wlan.seq`, `wlan.fc.type_subtype`; `parse_hunt` keeps
  `chains`, `seq`, `st`. The meter still reads `rec["rssi"]` — untouched.
- `build_target_filter(..., with_beacons=False)`: when true, filter becomes
  `(<target terms>) || wlan.fc.type_subtype==8`. `resolve_target` sets it for
  `flood_src`, `flood_all`, `mac`; not for `net`.
- `hunt(..., tracks=None)`: target-matching records feed the meter as now;
  beacons feed `tracks.add_radio`; target-matching deauth/disassoc feed both the
  meter and `tracks.add_source`. The scan screen's `agg.tracks` is passed in so
  the hunt starts warm.

Beacons roughly add "all APs on channel × ~10/s" to the hunt capture (≈400 fps on
a 37-AP channel); the scan capture already sustains that. Beacons never reach the
meter's rolling window.

**Receive-only status is unchanged.** Only display filters and parsed fields
change; no new external command, no `iw` call, nothing on the TX path.

## Screens

### MGMT FLOODS (renamed from DEAUTH FLOODS)

`S` cycling and row order unchanged. Layout:

```
⚑    GHz  ch  TYPE    SOURCE             DEVICE          rate  RSSI  LIKELY SOURCE
⚑ 5.5GHz 108  deauth  ff:ff:ff:ff:ff:ff  ⚠ deauther?    12.1   -59  ✓ NEIGHBOR-CORP +3 (…f1:79:40)  1.2dB
  5.5GHz 108  deauth  ff:ff:ff:ff:ff:ff  ⚠ deauther?     0.4   -89  ? NEIGHBOR-CORP +3 (…f1:79:e0)
⚑ 5.3GHz  64  deauth  fe:ff:ff:ff:ff:ff  ⚠ deauther?    11.8   -66  ✗ no AP match — separate device?
  2.4GHz   6  deauth  02:00:5e:00:01:8f  AP              0.2   -71  –
```

- `TYPE` 8 chars. `VENDOR` dropped from this view (empty for spoofed sources;
  folded into `DEVICE` for real ones). Stays in NETWORKS and PROBE CLIENTS.
- `LIKELY SOURCE`: marker, radio display name (most-seen SSID, `+N` other
  BSSIDs — same naming as the NETWORKS device view), base-MAC tail, margin on
  `✓`. `ALL` rows and real-source rows show `–`.
- ~112 columns; on narrower terminals `_draw_list` truncates on the right.

### TRACK MAC

When the typed MAC is currently a flood source, the status line (row 3) shows
the same attribution string. Otherwise unchanged.

### Hunt screen

One line under the header, only for `flood_src`, `flood_all`, `mac` targets:

```
ATTRIBUTION   ✓ NEIGHBOR-CORP +3 (…f1:79:40)  dist 0.02dB  margin 1.15dB  fading r=+0.98 (11 bins)  seq +1: 91%   runner-up WALKIN-SITE (…49:54)
```

Refreshed every redraw. Reads `?` with `r=– (2 bins)` right after parking and
flips to `✓` as bins accumulate. Several clusters → one line each. `✗` renders
as `✗ no beaconing AP within 6dB (nearest X at 9.4dB) — likely a separate
device`. Single-chain drivers get `(1-chain: combined only)` after the distance.

No new keys.

## Testing

### `test_attribution.py` (new, synthetic)

- `cluster`: one group → 1; two groups 30 dB apart → 2; 3 dB apart → 1; sparse
  tail does not split.
- `match`: three radios, cluster 0.05 dB from one → that one best, margin =
  distance to runner-up; missing chains → 1-D with `one_chain=True`.
- `fading_r`: shared sinusoidal drift + noise → r > 0.9; independent → |r| < 0.4;
  < 4 shared bins → `None`.
- `seq_continuity`: perfect run → 1.0; alternate frames dropped → ~0; wrap
  4095→0 counts as +1.
- `verdict`: every row of the marker table, incl. `✓` with r=None and ≥ 30
  samples, `✗` at 6.1 dB.
- `Tracks`: eviction past 60 s; deauth and disassoc keyed separately.

### `test_sniffer.py` (extended)

- disassoc lines → flood rows with `type="disassoc"`, separate from deauth rows
  for the same source.
- spoofed flood + beacons from two radios → `attrib` names the matching radio.
- real-source AP→client deauth → marker `–`.
- all existing tests pass unchanged.

### Ground truth (real captures, skipped when absent)

```python
@pytest.mark.skipif(not os.path.exists(CH108), reason="local capture not present")
def test_floor6_ch108_attributes_to_known_radio():
    results = attribution.analyse_pcap(CH108)
    best = max(results, key=lambda a: a.samples)
    assert best.marker == "✓"
    assert best.radio.base_mac.endswith("f1:79:40")
    assert best.margin > 1.0 and best.fading_r > 0.9
```

Committed tests cover ch 108 (single radio, strong) and ch 44 (two clusters).
Assertions use only what the capture itself contains — no live identifier is
written into the repo beyond a six-character MAC tail. Captures stay gitignored.

### Manual

`sudo ./sniffer.py` on a floor with the flood: `?` marks while hopping; ENTER on
a flooded row parks and the hunt line moves to `✓` within ~30 s. Needs the radio;
done by the operator.

## Files

| File | Change |
|---|---|
| `attribution.py` | new: engine + offline CLI |
| `test_attribution.py` | new |
| `sniffer.py` | disassoc + seq + chains; tracks; MGMT FLOODS view; TRACK MAC line; hunt handoff |
| `router_hunt.py` | `parse_hunt` chains/seq/st; `with_beacons`; `hunt(tracks=)` + attribution line |
| `test_sniffer.py` | `line()` gains seq; new tests |
| `README.md` | column, markers, offline CLI, technique summary |
