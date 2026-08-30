#!/usr/bin/env python3
"""Integration tests for sniffer.py aggregation + device/threat rendering.

Feeds synthetic tshark 'combined' lines through the real parse_combined ->
Aggregator path (no radio, no curses). Run: pytest test_sniffer.py
"""
import sniffer
import device_id

OUI = device_id.load_oui()


def line(st, sa, bssid, freq, sig="-50", priv="0",
         ht="", vht="", he="", rx8="", rx16="",
         wn="", wm="", wf="", ssid=""):
    """Build one COMBINED_FIELDS pipe-line (16 fixed fields + ssid tail)."""
    return "|".join([str(st), sa, sa, "ff:ff:ff:ff:ff:ff", bssid, str(freq),
                     sig, priv, ht, vht, he, rx8, rx16, wn, wm, wf, ssid])


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


# ---- feature 5: probe-request client view ----

def probe(sa, freq, ssid_hex="", sig="-60"):
    """A probe-request line (subtype 4): client sa, broadcast bssid, probed ssid."""
    return line(4, sa, "ff:ff:ff:ff:ff:ff", freq, sig=sig, ssid=ssid_hex)


def test_probe_request_builds_client_record():
    agg = feed([probe("d8:3a:dd:aa:bb:cc", 2437, "4d794e6574")])  # 'MyNet'
    assert "d8:3a:dd:aa:bb:cc" in agg.clients
    c = agg.clients["d8:3a:dd:aa:bb:cc"]
    assert c["freq"] == 2437
    assert c["ssids"] == {"MyNet"}
    assert c["count"] == 1


def test_probe_requests_accumulate_ssids_and_count():
    sa = "d8:3a:dd:aa:bb:cc"
    agg = feed([probe(sa, 2437, "4d794e6574"),      # MyNet
                probe(sa, 2437, "436166655f4749"),  # Cafe_GI
                probe(sa, 2437, "")])               # wildcard - no ssid
    c = agg.clients[sa]
    assert c["ssids"] == {"MyNet", "Cafe_GI"}
    assert c["count"] == 3


def test_probe_wildcard_only_client_has_empty_ssid_set():
    sa = "1c:2a:3b:aa:bb:cc"
    agg = feed([probe(sa, 5320), probe(sa, 5320)])
    c = agg.clients[sa]
    assert c["ssids"] == set()
    assert c["count"] == 2


def test_client_rows_sorted_by_rssi_desc():
    agg = feed([probe("1c:2a:3b:00:00:01", 2437, sig="-70"),
                probe("1c:2a:3b:00:00:02", 2437, sig="-40"),
                probe("1c:2a:3b:00:00:03", 2437, sig="-55")])
    rows = agg.client_rows()
    assert [r["mac"] for r in rows] == ["1c:2a:3b:00:00:02",
                                        "1c:2a:3b:00:00:03",
                                        "1c:2a:3b:00:00:01"]


def test_probe_requests_do_not_pollute_networks():
    agg = feed([probe("d8:3a:dd:aa:bb:cc", 2437, "4d794e6574")])
    assert agg.networks == {}


def test_randomized_client_vendor_flag():
    # 0xda first octet -> locally administered (randomized)
    agg = feed([probe("da:11:22:33:44:55", 2437, "4d794e6574")])
    assert sniffer.vendor_cell("da:11:22:33:44:55", OUI) == "rnd"


# ---- feature 6/7: capability fingerprint through the parse -> aggregator path ----

def test_network_phy_fingerprint():
    # an 802.11ac AP: HT + VHT present, 2 spatial streams (MCS 8-15 set)
    agg = feed([line(8, "b8:11:4b:fc:f6:80", "b8:11:4b:fc:f6:80", 5320,
                     ht="0x09ad", vht="0x0f815932", rx8="0xff",
                     ssid="486f6d654e6574")])
    net = agg.networks["b8:11:4b:fc:f6:80"]
    assert net["has_ht"] and net["has_vht"] and not net["has_he"]
    assert net["streams"] == 2
    assert sniffer.phy_cell(net) == "ac·5G·2ss"


def test_client_phy_fingerprint_pi_class():
    # a single-stream 2.4GHz 802.11n client (the Pi-Zero-W / ESP class)
    agg = feed([line(4, "d8:3a:dd:aa:bb:cc", "ff:ff:ff:ff:ff:ff", 2437,
                     ht="0x012c", ssid="4d794e6574")])
    c = agg.clients["d8:3a:dd:aa:bb:cc"]
    assert sniffer.phy_cell(c) == "n·2.4G·1ss"


def test_phy_fingerprint_absent_without_caps():
    # a deauth frame carries no capability IEs -> no fingerprint claimed
    agg = feed([line(8, "b8:11:4b:fc:f6:80", "b8:11:4b:fc:f6:80", 5320,
                     ssid="486f6d654e6574")])
    assert sniffer.phy_cell(agg.networks["b8:11:4b:fc:f6:80"]) == ""


def test_identity_str_includes_phy():
    agg = feed([line(8, "b8:27:eb:11:22:33", "b8:27:eb:11:22:33", 2437,
                     ht="0x012c", ssid="70616e6963")])  # Raspberry Pi AP
    net = agg.networks["b8:27:eb:11:22:33"]
    ident = sniffer.identity_str(net["bssid"], OUI, net, role="ap")
    assert ident == "Raspberry Pi · n·2.4G·1ss"


# ---- multi-BSSID collapse: device_rows() ----

def test_device_rows_collapses_shared_radio_block():
    # one Cisco radio, 3 BSSIDs sharing the first five octets, 3 SSIDs
    agg = feed([
        line(8, "b8:11:4b:fc:f6:80", "b8:11:4b:fc:f6:80", 5320, sig="-66",
             ht="0x09ad", vht="0x0f81", rx8="0xff", ssid="4e6574"),        # 'Net'
        line(8, "b8:11:4b:fc:f6:81", "b8:11:4b:fc:f6:81", 5320, sig="-60",
             ssid="4775657374"),                                           # 'Guest'
        line(8, "b8:11:4b:fc:f6:82", "b8:11:4b:fc:f6:82", 5320, sig="-70",
             ssid="496f54"),                                               # 'IoT'
    ])
    devs = agg.device_rows()
    assert len(devs) == 1
    dv = devs[0]
    assert dv["base"] == "b8:11:4b:fc:f6"
    assert dv["bssids"] == {"b8:11:4b:fc:f6:80", "b8:11:4b:fc:f6:81",
                            "b8:11:4b:fc:f6:82"}
    assert dv["n_bssids"] == 3
    assert dv["ssids"] == {"Net", "Guest", "IoT"}
    assert dv["rssi"] == -60          # strongest member
    assert dv["count"] == 3
    # capability presence propagates from whichever member advertised it
    assert dv["has_vht"] and sniffer.phy_cell(dv) == "ac·5G·2ss"


def test_device_rows_keeps_separate_radios_apart():
    agg = feed([
        line(8, "b8:11:4b:fc:f6:80", "b8:11:4b:fc:f6:80", 5320, ssid="4e6574"),
        line(8, "f8:6b:d9:49:79:a0", "f8:6b:d9:49:79:a0", 2437, ssid="4f74686572"),
    ])
    devs = agg.device_rows()
    assert len(devs) == 2
    assert {d_["base"] for d_ in devs} == {"b8:11:4b:fc:f6", "f8:6b:d9:49:79"}


def test_device_rows_sorted_by_rssi_desc():
    agg = feed([
        line(8, "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:01", 2437, sig="-80", ssid="41"),
        line(8, "bb:bb:bb:bb:bb:01", "bb:bb:bb:bb:bb:01", 2437, sig="-40", ssid="42"),
    ])
    assert [d_["base"] for d_ in agg.device_rows()] == ["bb:bb:bb:bb:bb",
                                                        "aa:aa:aa:aa:aa"]


def test_device_row_flags_pwnagotchi_member():
    agg = feed([line(8, "aa:bb:cc:dd:ee:ff", device_id.PWNAGOTCHI_BSSID, 2437)])
    dv = agg.device_rows()[0]
    assert dv["pwn"] is True
