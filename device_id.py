#!/usr/bin/env python3
"""
device_id.py - passive device identification for the deauth-hunt toolkit.

Turns metadata we already capture into a *vendor* and a coarse *device guess*,
so a router, a Raspberry Pi, or an ESP-based deauther is obvious at a glance in
the NETWORKS / DEAUTH FLOODS lists and in the hunt header.

Everything here is passive and local: it parses the IEEE OUI database that ships
on the box (`/usr/share/ieee-data/oui.txt`, 200k+ prefixes) and the cleartext
WPS strings already present in beacons/probe-responses. No probing, no network.

Feature slice 1+2+3 of the identity roadmap:
  1. vendor (OUI) + randomized-MAC flag,
  2. WPS device/model/manufacturer,
  3. device-type role (AP / client / attacker).

Pure functions, unit-tested in test_device_id.py.
"""
import os
import re

# Where the IEEE OUI list lives on Debian/Kali (ieee-data package) and a couple
# of common fallbacks. First readable one wins.
OUI_PATHS = [
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/nmap/nmap-mac-prefixes",  # different format; parsed leniently
]

# Corporate noise words dropped when shortening a vendor name for display.
_NOISE = {
    "inc", "inc.", "incorporated", "corp", "corp.", "corporation", "co",
    "co.", "co.,ltd.", "co.,ltd", "ltd", "ltd.", "llc", "l.l.c.", "gmbh",
    "ag", "sa", "s.a.", "plc", "company", "technologies", "technology",
    "tech", "electronics", "electronic", "systems", "system", "networks",
    "network", "communications", "communication", "solutions", "trading",
    "international", "group", "limited", "the", "&",
}

# Canonical short names for brands whose auto-shortening would look wrong
# (ALLCAPS acronyms, odd punctuation). Keyed by a lowercase substring of the
# full OUI vendor string.
_CANON = {
    "raspberry pi": "Raspberry Pi",
    "espressif": "Espressif",
    "tp-link": "TP-Link",
    "cisco": "Cisco",
    "netgear": "Netgear",
    "ubiquiti": "Ubiquiti",
    "d-link": "D-Link",
    "asustek": "ASUS",
    "asus": "ASUS",
    "aruba": "Aruba",
    "mikrotik": "MikroTik",
    "zyxel": "ZyXEL",
    "huawei": "Huawei",
    "xiaomi": "Xiaomi",
    "amazon": "Amazon",
    "google": "Google",
    "apple": "Apple",
    "samsung": "Samsung",
    "intel": "Intel",
    "realtek": "Realtek",
    "mediatek": "MediaTek",
}

# Vendor substring -> short device-class label (device maker recognition). Used
# by device_guess when there's no WPS model string to be more specific.
_DEVICE_HINTS = (
    ("raspberry pi", "Raspberry Pi"),
    ("espressif", "ESP32/8266"),
    ("pwnie", "Pwnie Express"),
    ("hak5", "Hak5"),
)


def load_oui(paths=None):
    """Parse the IEEE OUI database into {"AABBCC": "Vendor Name"}.

    Reads the `(base 16)` lines of oui.txt (`AABBCC     (base 16)\\t\\tVendor`),
    which give the 24-bit prefix already stripped of separators. Falls back to a
    lenient `AABBCC<sep>Vendor` parse for other files (e.g. nmap's list). Returns
    {} if no file is readable - callers must treat an empty map as "no vendors".
    """
    for path in (paths or OUI_PATHS):
        if not os.path.isfile(path):
            continue
        try:
            table = {}
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if "(base 16)" in line:
                        left, _, right = line.partition("(base 16)")
                        key = left.strip().upper()
                        vendor = right.strip()
                    elif "(hex)" in line:
                        continue  # the (base 16) twin carries the same data
                    else:
                        m = re.match(r"\s*([0-9A-Fa-f]{6})[\s:-]+(.+)", line)
                        if not m:
                            continue
                        key, vendor = m.group(1).upper(), m.group(2).strip()
                    if len(key) == 6 and vendor:
                        table[key] = vendor
            if table:
                return table
        except OSError:
            continue
    return {}


def oui_key(mac):
    """The 24-bit OUI of a MAC as 'AABBCC', or None if it isn't a real MAC.

    Accepts colon/dash-separated MACs and bare 12-hex strings. Junk in the OUI
    octets themselves (e.g. 'xx:yy:zz:...') is rejected rather than silently
    skipped, so a bad address never resolves to a wrong vendor.
    """
    if not mac:
        return None
    s = str(mac).strip()
    m = re.match(r"^([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})", s)
    if m:
        return "".join(m.groups()).upper()
    if re.match(r"^[0-9a-fA-F]{6,}$", s):
        return s[:6].upper()
    return None


def _first_octet(mac):
    k = oui_key(mac)
    if k is None:
        return None
    try:
        return int(k[:2], 16)
    except ValueError:
        return None


def is_randomized(mac):
    """True if the MAC is locally-administered (randomized) - LG bit set.

    The locally-administered bit is bit 1 (0x02) of the first octet. Modern
    phones/laptops randomize their MAC this way, which makes the OUI meaningless.
    Broadcast/multicast and the origin-case `fe:ff...` spoof are not treated as
    randomized (they're not a device's own address).
    """
    o = _first_octet(mac)
    if o is None:
        return False
    if o & 0x01:            # group/multicast bit - not a unicast device address
        return False
    # broadcast-spoof addresses (fe:ff:ff:ff:ff:ff and the like) carry the LAA
    # bit but aren't a device's own randomized MAC - they're handled elsewhere.
    hexonly = re.sub(r"[^0-9a-fA-F]", "", str(mac)).lower()
    if len(hexonly) >= 12 and hexonly[2:12] == "ff" * 5:
        return False
    return bool(o & 0x02)


def vendor_for(mac, oui):
    """Full OUI vendor string for a MAC, or '' if unknown or randomized."""
    if is_randomized(mac):
        return ""
    k = oui_key(mac)
    if k is None:
        return ""
    return oui.get(k, "")


def short_vendor(vendor):
    """A <=12-char display form of a full OUI vendor name.

    Prefers a canonical name for known brands; otherwise drops corporate noise
    words, keeps the first meaningful token or two, and title-cases ALLCAPS.
    """
    if not vendor:
        return ""
    low = vendor.lower()
    for sub, name in _CANON.items():
        if sub in low:
            return name
    # split on whitespace and separating punctuation
    raw = re.split(r"[\s,./]+", vendor)
    words = [w for w in raw if w and w.strip(".").lower() not in _NOISE]
    if not words:
        words = [vendor.split()[0]]
    out = []
    total = 0
    for w in words:
        piece = w if not w.isupper() or len(w) <= 3 else w.title()
        add = (1 if out else 0) + len(piece)
        if total + add > 12:
            break
        out.append(piece)
        total += add
    if not out:
        out = [words[0][:12]]
    return " ".join(out)[:12]


def _role_label(frame_role):
    return {"ap": "AP", "attacker": "attacker", "client": "client"}.get(
        (frame_role or "").lower(), "")


def device_guess(mac, oui, wps_name="", wps_model="", wps_manuf="", frame_role=""):
    """A short human label for what a device *is*, best-effort, most specific first.

    Priority: WPS model/device name (exact) > known device-maker OUI (Raspberry
    Pi, ESP...) > randomized-MAC marker > frame role (AP/client/attacker). Returns
    '' when nothing is known.
    """
    for s in (wps_model, wps_name):
        s = (s or "").strip()
        if s:
            return s[:18]
    vendor = vendor_for(mac, oui).lower()
    if vendor:
        for sub, label in _DEVICE_HINTS:
            if sub in vendor:
                return label
    role = _role_label(frame_role)
    if role:
        return role
    if is_randomized(mac):
        return "rnd-MAC"
    manuf = (wps_manuf or "").strip()
    if manuf:
        return short_vendor(manuf)
    return ""
