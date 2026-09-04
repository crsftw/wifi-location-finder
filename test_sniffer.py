#!/usr/bin/env python3
"""Integration tests for sniffer.py aggregation + device/threat rendering.

Feeds synthetic tshark 'combined' lines through the real parse_combined ->
Aggregator path (no radio, no curses). Run: pytest test_sniffer.py
"""
import sniffer
import pytest
import device_id
import router_hunt

OUI = device_id.load_oui()


def line(st, sa, bssid, freq, sig="-50", priv="0",
         ht="", vht="", he="", rx8="", rx16="",
         wn="", wm="", wf="", ssid="", ts="", seq=""):
    """Build one COMBINED_FIELDS pipe-line (18 fixed fields + ssid tail)."""
    return "|".join([str(st), sa, sa, "ff:ff:ff:ff:ff:ff", bssid, str(freq),
                     sig, priv, ht, vht, he, rx8, rx16, wn, wm, wf, ts, seq, ssid])


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
    agg = feed([line(8, "02:00:5e:00:01:80", "02:00:5e:00:01:80", 5320,
                     ssid="486f6d654e6574")])  # 'HomeNet'
    net = agg.networks["02:00:5e:00:01:80"]
    assert net["pwn"] is False
    dev = sniffer.device_or_badge(net["bssid"], OUI, net, role="ap")
    assert dev == "AP"


def test_raspberry_pi_flood_badged_as_pwnagotchi():
    src = "b8:27:eb:11:22:33"
    agg = feed([line(12, src, "02:00:5e:00:01:80", 2437)] * 20)  # 20/5s = 4/s
    rows = [r for r in agg.flood_rows(now=1000.0, rate_threshold=2.0)
            if r["kind"] == "src"]
    assert rows and rows[0]["flood"] is True
    dev = sniffer.device_or_badge(src, OUI, role="attacker",
                                  is_flood=rows[0]["flood"])
    assert dev == "⚠ pwnagotchi?"


def test_spoofed_source_flood_badged_as_deauther():
    src = "fe:ff:ff:ff:ff:ff"  # the origin-case spoof
    agg = feed([line(12, src, "02:00:5e:00:01:80", 5320)] * 20)
    rows = [r for r in agg.flood_rows(now=1000.0, rate_threshold=2.0)
            if r["kind"] == "src"]
    assert rows and rows[0]["flood"] is True
    dev = sniffer.device_or_badge(src, OUI, role="attacker",
                                  is_flood=rows[0]["flood"])
    assert dev == "⚠ deauther?"


def test_low_rate_deauth_not_badged_as_flood():
    # a single deauth is not a flood -> falls back to the plain role, no badge
    src = "b8:27:eb:11:22:33"
    agg = feed([line(12, src, "02:00:5e:00:01:80", 2437)])
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
    agg = feed([line(8, "02:00:5e:00:01:80", "02:00:5e:00:01:80", 5320,
                     ht="0x09ad", vht="0x0f815932", rx8="0xff",
                     ssid="486f6d654e6574")])
    net = agg.networks["02:00:5e:00:01:80"]
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
    agg = feed([line(8, "02:00:5e:00:01:80", "02:00:5e:00:01:80", 5320,
                     ssid="486f6d654e6574")])
    assert sniffer.phy_cell(agg.networks["02:00:5e:00:01:80"]) == ""


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
        line(8, "02:00:5e:00:01:80", "02:00:5e:00:01:80", 5320, sig="-66",
             ht="0x09ad", vht="0x0f81", rx8="0xff", ssid="4e6574"),        # 'Net'
        line(8, "02:00:5e:00:01:81", "02:00:5e:00:01:81", 5320, sig="-60",
             ssid="4775657374"),                                           # 'Guest'
        line(8, "02:00:5e:00:01:82", "02:00:5e:00:01:82", 5320, sig="-70",
             ssid="496f54"),                                               # 'IoT'
    ])
    devs = agg.device_rows()
    assert len(devs) == 1
    dv = devs[0]
    assert dv["base"] == "02:00:5e:00:01"
    assert dv["bssids"] == {"02:00:5e:00:01:80", "02:00:5e:00:01:81",
                            "02:00:5e:00:01:82"}
    assert dv["n_bssids"] == 3
    assert dv["ssids"] == {"Net", "Guest", "IoT"}
    assert dv["rssi"] == -60          # strongest member
    assert dv["count"] == 3
    # capability presence propagates from whichever member advertised it
    assert dv["has_vht"] and sniffer.phy_cell(dv) == "ac·5G·2ss"


def test_device_rows_keeps_separate_radios_apart():
    agg = feed([
        line(8, "02:00:5e:00:01:80", "02:00:5e:00:01:80", 5320, ssid="4e6574"),
        line(8, "02:00:5e:00:02:a0", "02:00:5e:00:02:a0", 2437, ssid="4f74686572"),
    ])
    devs = agg.device_rows()
    assert len(devs) == 2
    assert {d_["base"] for d_ in devs} == {"02:00:5e:00:01", "02:00:5e:00:02"}


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


# ---- adaptive hopping: per-channel activity snapshot ----

def test_channel_activity_counts_frames_per_freq():
    agg = feed([
        line(8, "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:01", 2437, ssid="41"),
        line(8, "aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:01", 2437, ssid="41"),
        line(12, "fe:ff:ff:ff:ff:ff", "02:00:5e:00:01:80", 5320)],
        now=1000.0)
    act = agg.channel_activity(now=1000.0, window=5.0)
    assert act[2437] == 2
    assert act[5320] == 1


def test_channel_activity_windows_out_old_frames():
    agg = sniffer.Aggregator()
    agg.add(sniffer.parse_combined(line(8, "aa:aa:aa:aa:aa:01",
            "aa:aa:aa:aa:aa:01", 2437, ssid="41")), now=1000.0)
    # a later frame; the old one falls outside a 5s window
    agg.add(sniffer.parse_combined(line(8, "aa:aa:aa:aa:aa:01",
            "aa:aa:aa:aa:aa:01", 2437, ssid="41")), now=1008.0)
    act = agg.channel_activity(now=1008.0, window=5.0)
    assert act[2437] == 1


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
    assert a is not None and a.radio.key == "00:5e:00:01:c"
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


def test_real_ap_deauth_before_its_beacon_is_not_attributed():
    # the hopper lands mid-burst: this AP's deauths arrive before its next
    # beacon, so they are first recorded as a spoofed-source flood - once
    # the beacon lands the AP must be forgotten as a source, not attributed
    # to its own radio
    ls = [_flood("02:00:5e:00:01:c0", 2437, "-50", 1000 + i * 0.1, i) for i in range(5)]
    ls.append(_beacon("02:00:5e:00:01:c0", 2437, "-50", "436f7270", 1000.6))
    agg = feed(ls, now=1001.0)
    assert agg.tracks.source(2437, "02:00:5e:00:01:c0", 12) == []
    rows = [r for r in agg.flood_rows(now=1001.0) if r["kind"] == "src"]
    assert len(rows) == 1 and rows[0]["attrib"] is None


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
    assert [r["attrib"].radio.key for r in rows] == ["00:5e:00:01:c", "00:5e:00:01:6"]
    assert rows[0]["rate"] > rows[1]["rate"]           # rate split by cluster share
    assert rows[0]["flood"] == rows[1]["flood"]        # the flag is per source


def test_tracks_use_frame_timestamp_not_drain_time():
    agg = feed([_flood("ff:ff:ff:ff:ff:ff", 5540, "-59", 1234.5, 1)], now=9999.0)
    assert agg.tracks.source(5540, "ff:ff:ff:ff:ff:ff", 12)[0].ts == 1234.5


def test_flood_rows_evicts_a_source_that_has_gone_stale():
    ls = [_flood("ff:ff:ff:ff:ff:ff", 5540, "-59,-62,-61", 1000 + i * 0.1, i) for i in range(20)]
    agg = feed(ls, now=1000.0)
    rows = [r for r in agg.flood_rows(now=1100.0) if r["kind"] == "src"]
    assert not any(r["src"] == "ff:ff:ff:ff:ff:ff" for r in rows)
    assert agg.tracks.source_keys(5540) == []


def test_flood_rows_caches_attribution_for_one_second():
    ls = []
    for i in range(40):
        ts = 1000 + i * 0.5
        ls.append(_flood("ff:ff:ff:ff:ff:ff", 5540, "-59,-62,-61", ts, 600 + i))
        ls.append(_beacon("02:00:5e:00:01:c0", 5540, "-59,-62,-61", "436f7270", ts))
        ls.append(_beacon("02:00:5e:00:02:a0", 5540, "-67,-70,-69", "4f74686572", ts))
    agg = feed(ls, now=1020.0)
    r1 = [x for x in agg.flood_rows(now=1020.0, rate_threshold=2.0) if x["kind"] == "src"][0]
    r2 = [x for x in agg.flood_rows(now=1020.0, rate_threshold=2.0) if x["kind"] == "src"][0]
    assert r1["attrib"] is r2["attrib"]
    r3 = [x for x in agg.flood_rows(now=1022.0, rate_threshold=2.0) if x["kind"] == "src"][0]
    assert r3["attrib"] is not r1["attrib"]


def test_attribute_channel_empty_for_a_target_that_is_not_a_flood_source():
    import attribution
    t = attribution.Tracks()
    t.add_radio(5540, "02:00:5e:00:01:c0", "Corp", attribution.Sample(1.0, -59, -62, -61, None))
    assert attribution.attribute_channel(5540, t, sa="02:00:5e:00:09:01") == []


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


# ---- hunt capture: fields, filter, track routing ----


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
    assert [r.key for r in t.radios_on(5540)] == ["00:5e:00:01:c"]
    assert t.radios_on(5540)[0].name() == "Corp"
    assert len(t.source(5540, "ff:ff:ff:ff:ff:ff", 12)) == 1
    assert t.source(5540, "02:00:5e:00:01:c0", 12) == []
