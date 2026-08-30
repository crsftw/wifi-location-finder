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

# Pwnagotchi advertises its presence with beacon frames whose BSSID is this
# constant (the `SignatureAddress` in pwnagotchi's mesh/wifi.py; also what
# Kismet's pwnagotchi plugin keys on). It is stable across versions - if a
# future release changes it, update this one line.
PWNAGOTCHI_BSSID = "de:ad:be:ef:de:ad"


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


def base_mac_key(mac):
    """The first five octets of a MAC as 'aa:bb:cc:dd:ee', or None.

    APs that broadcast several BSSIDs from one physical radio allocate them in a
    contiguous block that shares the top five octets (the origin-case radio uses
    b8:11:4b:fc:f6:8x). Grouping on this key collapses those BSSIDs into one
    device. The shared prefix also guarantees a shared OUI, hence one vendor.
    """
    if not mac:
        return None
    hexonly = re.sub(r"[^0-9a-fA-F]", "", str(mac))
    m = re.match(r"^([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})"
                 r"[:-]([0-9a-fA-F]{2})[:-]([0-9a-fA-F]{2})[:-][0-9a-fA-F]{2}$",
                 str(mac).strip())
    if m:
        return ":".join(g.lower() for g in m.groups())
    if len(hexonly) == 12:
        b = hexonly.lower()
        return ":".join(b[i:i + 2] for i in range(0, 10, 2))
    return None


def base_mac_display(mac):
    """A device's base MAC for display, e.g. 'b8:11:4b:fc:f6:**' (or '')."""
    k = base_mac_key(mac)
    return f"{k}:**" if k else ""


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


def _as_int(v):
    """A tshark hex/dec field to int, 0 when empty/None/unparseable."""
    if v in (None, ""):
        return 0
    try:
        s = str(v).split(",")[0].strip()
        return int(s, 0) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return 0


def spatial_streams(rx_8to15, rx_16to23):
    """Spatial-stream count from the HT MCS Rx bitmask (1, 2, or 3-for-3+).

    802.11n MCS indices map to streams in groups of 8: 0-7 = 1 stream,
    8-15 = 2, 16-23 = 3. A nonzero higher group means the radio supports that
    many streams. We report up to 3 (3 means 3-or-more); most targets are 1-2.
    """
    if _as_int(rx_16to23):
        return 3
    if _as_int(rx_8to15):
        return 2
    return 1


def _band_str(freq):
    if not freq:
        return ""
    return "2.4G" if freq < 3000 else "5G"


def phy_fingerprint(freq, has_ht, has_vht, has_he, streams=1):
    """A compact PHY-capability fingerprint, or '' if no capability IEs seen.

    Feature slice 6 - a coarse device *class* from robust presence signals:
    generation (HE->ax, VHT->ac, HT->n), band (from freq), and spatial streams.
    e.g. 'n·2.4G·1ss' (the Pi-Zero-W / ESP class), 'ac·5G·2ss', 'ax·5G·2ss'.
    Returns '' when none of HT/VHT/HE were present, rather than claiming a
    'legacy' device we didn't actually confirm.
    """
    if not (has_ht or has_vht or has_he):
        return ""
    gen = "ax" if has_he else "ac" if has_vht else "n"
    band = _band_str(freq)
    parts = [gen, band, f"{streams}ss"]
    return "·".join(p for p in parts if p)


def deauther_badge(mac, oui, is_flood, is_pwn_beacon=False):
    """A threat badge for a transmitter, or '' if it looks benign.

    Feature slice 4 - all from solid, verifiable signals, no payload guessing:
      * a de:ad:be:ef:de:ad advertisement beacon is a pwnagotchi announcing
        itself -> '⚠ pwnagotchi' (definitive, no question mark);
      * a deauth-*flood* source is an attacker regardless of hardware, labelled
        by its OUI: Raspberry Pi -> '⚠ pwnagotchi?', Espressif -> '⚠ ESP
        deauther?', anything else -> '⚠ deauther?' (the '?' marks strong-but-
        not-certain evidence).
    """
    if is_pwn_beacon:
        return "⚠ pwnagotchi"
    if not is_flood:
        return ""
    vendor = vendor_for(mac, oui).lower()
    if "raspberry pi" in vendor:
        return "⚠ pwnagotchi?"
    if "espressif" in vendor:
        return "⚠ ESP deauther?"
    return "⚠ deauther?"
