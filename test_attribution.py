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
    assert A.radio_key("02:00:5E:00:0A:C0") == "00:5e:00:0a:c"
    assert A.radio_key("02:00:5e:00:0a:c3") == "00:5e:00:0a:c"
    assert A.radio_key("02:00:5e:00:0a:60") == "00:5e:00:0a:6"
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
    assert {r.key for r in radios} == {"00:5e:00:01:c", "00:5e:00:01:6"}
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
    assert A.verdict(_attr(radio=r, dist=0.5, margin=0.5, fading_r=0.8)) == A.MARK_MAYBE   # margin
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
    assert a.radio.key == "00:5e:00:01:c"
    assert a.radio.name() == "Corp +1"
    assert a.dist == pytest.approx(0.0, abs=1e-6)
    assert a.runner_up.key == "00:5e:00:02:a"
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
    assert [a.radio.key for a in out] == ["00:5e:00:01:c", "00:5e:00:03:6"]
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
    assert a.radio.key == "00:5e:00:01:c"       # nearest is still reported
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
    assert len(one) == 1 and one[0].radio.key == "00:5e:00:02:a"
    assert A.attribute_channel(2437, t) == []


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
