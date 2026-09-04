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
