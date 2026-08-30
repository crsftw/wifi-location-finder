#!/usr/bin/env python3
"""Integration tests for sniffer.py aggregation + device/threat rendering.

Feeds synthetic tshark 'combined' lines through the real parse_combined ->
Aggregator path (no radio, no curses). Run: pytest test_sniffer.py
"""
import sniffer
import device_id

OUI = device_id.load_oui()


def line(st, sa, bssid, freq, sig="-50", priv="0",
         wn="", wm="", wf="", ssid=""):
    """Build one COMBINED_FIELDS pipe-line (11 fixed fields + ssid tail)."""
    return "|".join([str(st), sa, sa, "ff:ff:ff:ff:ff:ff", bssid, str(freq),
                     sig, priv, wn, wm, wf, ssid])


def feed(lines, now=1000.0, flood_window=5.0):
    agg = sniffer.Aggregator(flood_window=flood_window)
    for L in lines:
        rec = sniffer.parse_combined(L)
        assert rec is not None, f"parse failed: {L!r}"
        agg.add(rec, now=now)
    return agg


def test_pwnagotchi_beacon_sets_pwn_flag_and_badge():
    # a de:ad:be:ef:de:ad advertisement beacon (transmitter addr is random)
    agg = feed([line(8, "aa:bb:cc:dd:ee:ff", device_id.PWNAGOTCHI_BSSID, 2437)])
    net = agg.networks[device_id.PWNAGOTCHI_BSSID]
    assert net["pwn"] is True
    dev = sniffer.device_or_badge(net["bssid"], OUI, net, role="ap",
                                  is_pwn=net["pwn"])
    assert dev == "⚠ pwnagotchi"


def test_normal_ap_has_no_pwn_flag():
    agg = feed([line(8, "b8:11:4b:fc:f6:80", "b8:11:4b:fc:f6:80", 5320,
                     ssid="486f6d654e6574")])  # 'HomeNet'
    net = agg.networks["b8:11:4b:fc:f6:80"]
    assert net["pwn"] is False
    dev = sniffer.device_or_badge(net["bssid"], OUI, net, role="ap")
    assert dev == "AP"


def test_raspberry_pi_flood_badged_as_pwnagotchi():
    src = "b8:27:eb:11:22:33"
    agg = feed([line(12, src, "b8:11:4b:fc:f6:80", 2437)] * 20)  # 20/5s = 4/s
    rows = [r for r in agg.flood_rows(now=1000.0, rate_threshold=2.0)
            if r["kind"] == "src"]
    assert rows and rows[0]["flood"] is True
    dev = sniffer.device_or_badge(src, OUI, role="attacker",
                                  is_flood=rows[0]["flood"])
    assert dev == "⚠ pwnagotchi?"


def test_spoofed_source_flood_badged_as_deauther():
    src = "fe:ff:ff:ff:ff:ff"  # the origin-case spoof
    agg = feed([line(12, src, "b8:11:4b:fc:f6:80", 5320)] * 20)
    rows = [r for r in agg.flood_rows(now=1000.0, rate_threshold=2.0)
            if r["kind"] == "src"]
    assert rows and rows[0]["flood"] is True
    dev = sniffer.device_or_badge(src, OUI, role="attacker",
                                  is_flood=rows[0]["flood"])
    assert dev == "⚠ deauther?"


def test_low_rate_deauth_not_badged_as_flood():
    # a single deauth is not a flood -> falls back to the plain role, no badge
    src = "b8:27:eb:11:22:33"
    agg = feed([line(12, src, "b8:11:4b:fc:f6:80", 2437)])
    rows = [r for r in agg.flood_rows(now=1000.0, rate_threshold=2.0)
            if r["kind"] == "src"]
    assert rows and rows[0]["flood"] is False
    dev = sniffer.device_or_badge(src, OUI, role="attacker",
                                  is_flood=rows[0]["flood"])
    assert dev == "Raspberry Pi"  # device_guess maker hint, not a threat badge
