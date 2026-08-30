#!/usr/bin/env python3
"""Tests for device_id.py (OUI vendor lookup, randomized-MAC flag, device guess).

Pure-function tests only - no radio, no capture. Run: pytest test_device_id.py
"""
import textwrap

import device_id as d


# A tiny in-memory OUI table so tests don't depend on the system oui.txt.
SAMPLE = textwrap.dedent("""\
    D8-3A-DD   (hex)		Raspberry Pi Trading Ltd
    D83ADD     (base 16)		Raspberry Pi Trading Ltd
    B8-27-EB   (hex)		Raspberry Pi Foundation
    B827EB     (base 16)		Raspberry Pi Foundation
    10-06-1C   (hex)		Espressif Inc.
    10061C     (base 16)		Espressif Inc.
    50-C7-BF   (hex)		TP-LINK TECHNOLOGIES CO.,LTD.
    50C7BF     (base 16)		TP-LINK TECHNOLOGIES CO.,LTD.
    00-00-0C   (hex)		Cisco Systems, Inc
    00000C     (base 16)		Cisco Systems, Inc
""")


def make_oui(tmp_path):
    p = tmp_path / "oui.txt"
    p.write_text(SAMPLE)
    return d.load_oui([str(p)])


# ---- oui_key ----

def test_oui_key_normalizes_case_and_separators():
    assert d.oui_key("d8:3a:dd:11:22:33") == "D83ADD"
    assert d.oui_key("D8-3A-DD-11-22-33") == "D83ADD"
    assert d.oui_key("D83ADD112233") == "D83ADD"


def test_oui_key_rejects_junk():
    assert d.oui_key("") is None
    assert d.oui_key("??") is None
    assert d.oui_key("xx:yy:zz:11:22:33") is None
    assert d.oui_key(None) is None


# ---- randomized-MAC flag (locally-administered bit) ----

def test_randomized_true_when_laa_bit_set():
    # second-least-significant bit of the first octet
    assert d.is_randomized("da:a1:19:00:11:22") is True   # 0xda -> ...10
    assert d.is_randomized("02:00:00:00:00:00") is True


def test_randomized_false_for_real_ouis():
    assert d.is_randomized("d8:3a:dd:11:22:33") is False  # Raspberry Pi
    assert d.is_randomized("b8:27:eb:00:00:00") is False


def test_broadcast_and_junk_not_randomized():
    assert d.is_randomized("ff:ff:ff:ff:ff:ff") is False
    assert d.is_randomized("") is False
    assert d.is_randomized("fe:ff:ff:ff:ff:ff") is False  # the origin-case spoof src


# ---- vendor lookup ----

def test_vendor_resolves_from_table(tmp_path):
    oui = make_oui(tmp_path)
    assert "Raspberry Pi" in d.vendor_for("d8:3a:dd:11:22:33", oui)
    assert "Espressif" in d.vendor_for("10:06:1c:aa:bb:cc", oui)


def test_vendor_blank_when_randomized(tmp_path):
    oui = make_oui(tmp_path)
    # a randomized MAC's OUI is meaningless - do not resolve it
    assert d.vendor_for("da:a1:19:00:11:22", oui) == ""


def test_vendor_blank_when_unknown(tmp_path):
    oui = make_oui(tmp_path)
    assert d.vendor_for("1c:2a:3b:00:11:22", oui) == ""


# ---- short vendor display ----

def test_short_vendor_trims_corporate_noise():
    assert d.short_vendor("Espressif Inc.") == "Espressif"
    assert d.short_vendor("Raspberry Pi Trading Ltd") == "Raspberry Pi"
    assert d.short_vendor("Cisco Systems, Inc") == "Cisco"
    assert d.short_vendor("TP-LINK TECHNOLOGIES CO.,LTD.") == "TP-Link"


def test_short_vendor_length_capped():
    assert len(d.short_vendor("Some Very Long Manufacturer Name Company")) <= 12


# ---- device guess ----

def test_device_guess_prefers_wps_model(tmp_path):
    oui = make_oui(tmp_path)
    g = d.device_guess("50:c7:bf:00:11:22", oui, wps_model="Archer C7", frame_role="ap")
    assert "Archer C7" in g


def test_device_guess_raspberry_pi_from_oui(tmp_path):
    oui = make_oui(tmp_path)
    assert d.device_guess("d8:3a:dd:00:11:22", oui) == "Raspberry Pi"
    assert d.device_guess("b8:27:eb:00:11:22", oui) == "Raspberry Pi"


def test_device_guess_esp_from_oui(tmp_path):
    oui = make_oui(tmp_path)
    assert "ESP" in d.device_guess("10:06:1c:00:11:22", oui)


def test_device_guess_falls_back_to_frame_role(tmp_path):
    oui = make_oui(tmp_path)
    # unknown vendor, but we know it sent beacons -> it's an AP
    assert d.device_guess("1c:2a:3b:00:11:22", oui, frame_role="ap") == "AP"
    assert d.device_guess("1c:2a:3b:00:11:22", oui, frame_role="attacker") == "attacker"


def test_device_guess_randomized_marked(tmp_path):
    oui = make_oui(tmp_path)
    assert d.device_guess("da:a1:19:00:11:22", oui) == "rnd-MAC"


def test_device_guess_empty_when_nothing_known(tmp_path):
    oui = make_oui(tmp_path)
    assert d.device_guess("1c:2a:3b:00:11:22", oui) == ""


# ---- feature 4: pwnagotchi / deauther badge ----

def test_pwnagotchi_bssid_constant():
    # the public advertisement signature address (pwnagotchi mesh/wifi.py)
    assert d.PWNAGOTCHI_BSSID == "de:ad:be:ef:de:ad"


def test_badge_pwnagotchi_beacon_is_definitive(tmp_path):
    oui = make_oui(tmp_path)
    # a de:ad:be:ef:de:ad beacon: it is announcing itself -> no question mark
    assert d.deauther_badge("de:ad:be:ef:de:ad", oui, is_flood=False,
                            is_pwn_beacon=True) == "⚠ pwnagotchi"
    # even without flood context, the beacon flag wins
    assert d.deauther_badge("b8:27:eb:00:11:22", oui, is_flood=False,
                            is_pwn_beacon=True) == "⚠ pwnagotchi"


def test_badge_raspberry_pi_flood(tmp_path):
    oui = make_oui(tmp_path)
    assert d.deauther_badge("b8:27:eb:00:11:22", oui, is_flood=True) == "⚠ pwnagotchi?"
    assert d.deauther_badge("d8:3a:dd:00:11:22", oui, is_flood=True) == "⚠ pwnagotchi?"


def test_badge_espressif_flood(tmp_path):
    oui = make_oui(tmp_path)
    assert d.deauther_badge("10:06:1c:00:11:22", oui, is_flood=True) == "⚠ ESP deauther?"


def test_badge_unknown_hardware_flood(tmp_path):
    oui = make_oui(tmp_path)
    # a sustained flood is an attack regardless of vendor
    assert d.deauther_badge("1c:2a:3b:00:11:22", oui, is_flood=True) == "⚠ deauther?"
    # the origin-case spoofed source (no resolvable vendor) still badges
    assert d.deauther_badge("fe:ff:ff:ff:ff:ff", oui, is_flood=True) == "⚠ deauther?"


def test_badge_empty_when_no_flood_and_no_beacon(tmp_path):
    oui = make_oui(tmp_path)
    assert d.deauther_badge("b8:27:eb:00:11:22", oui, is_flood=False) == ""
    assert d.deauther_badge("1c:2a:3b:00:11:22", oui, is_flood=False) == ""
