#!/usr/bin/env python3
"""Tests for adaptive channel-hopping scheduling (router_hunt.py).

Pure-function tests only - no radio, no threads. Run: pytest test_hopper.py
"""
import pytest

import router_hunt as rh


# ---- channel_dwell: per-channel dwell from an activity score ----

def test_dwell_silent_channel_gets_minimum():
    assert rh.channel_dwell(0, base=1.2, lo=0.3, hi=3.0) == 0.3


def test_dwell_silent_primary_kept_warm():
    # a quiet 2.4GHz primary (1/6/11) still gets the base dwell
    assert rh.channel_dwell(0, base=1.2, lo=0.3, hi=3.0, priority=True) == 1.2


def test_dwell_any_activity_gets_base():
    assert rh.channel_dwell(3, base=1.2, lo=0.3, hi=3.0, hot=15) == 1.2


def test_dwell_hot_channel_gets_maximum():
    assert rh.channel_dwell(40, base=1.2, lo=0.3, hi=3.0, hot=15) == 3.0
    assert rh.channel_dwell(15, base=1.2, lo=0.3, hi=3.0, hot=15) == 3.0


# ---- weighted_schedule: build the next sweep's (chan,freq,band,dwell) list ----

CHANS = [(1, 2412, "2.4"), (6, 2437, "2.4"), (36, 5180, "5"),
         (64, 5320, "5"), (149, 5745, "5")]


def test_schedule_covers_every_channel_in_order():
    sched = rh.weighted_schedule(CHANS, {}, base=1.2, lo=0.3, hi=3.0)
    assert [(c, f, b) for c, f, b, d in sched] == CHANS  # nothing dropped/reordered


def test_schedule_weights_by_activity():
    activity = {2437: 3, 5320: 40}          # ch6 lightly busy, ch64 flooded
    sched = rh.weighted_schedule(CHANS, activity, base=1.2, lo=0.3, hi=3.0, hot=15)
    dwell = {c: d for c, f, b, d in sched}
    assert dwell[64] == 3.0                 # flood -> max
    assert dwell[6] == 1.2                  # some activity -> base
    assert dwell[1] == 1.2                  # quiet primary -> base (kept warm)
    assert dwell[36] == 0.3                 # silent non-primary -> min
    assert dwell[149] == 0.3


def test_schedule_all_quiet_shortens_non_primaries():
    sched = rh.weighted_schedule(CHANS, {}, base=1.2, lo=0.3, hi=3.0)
    total = sum(d for c, f, b, d in sched)
    # 1 and 6 are primaries (base 1.2); 36/64/149 drop to 0.3
    assert total == pytest.approx(1.2 + 1.2 + 0.3 + 0.3 + 0.3)
    # and it is strictly faster than a uniform sweep at base dwell
    assert total < len(CHANS) * 1.2


# ---- Hopper._sweep: the flag selects uniform vs weighted ----

def test_hopper_uniform_gives_equal_dwell():
    hop = rh.Hopper("wlan1", CHANS, dwell=1.2, adaptive=False)
    assert [d for c, f, b, d in hop._sweep()] == [1.2] * len(CHANS)


def test_hopper_adaptive_uses_activity():
    hop = rh.Hopper("wlan1", CHANS, dwell=1.2, adaptive=True,
                    min_dwell=0.3, max_dwell=3.0, hot=15)
    hop.set_activity({5320: 40})            # ch64 flooded
    dwell = {c: d for c, f, b, d in hop._sweep()}
    assert dwell[64] == 3.0
    assert dwell[36] == 0.3                 # silent non-primary
    assert dwell[1] == 1.2                  # quiet primary kept warm


def test_hopper_min_dwell_never_exceeds_base():
    hop = rh.Hopper("wlan1", CHANS, dwell=0.2, adaptive=True, min_dwell=0.3)
    assert hop.min_dwell <= hop.dwell       # a tiny base still bounds min
