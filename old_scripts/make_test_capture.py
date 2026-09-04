#!/usr/bin/env python3
"""
make_test_capture.py - synthesise a pcap carrying the exact deauth signature
observed in the real PEEKREMOTE capture, with a scripted RSSI profile.

Lets the whole filter -> meter -> SQLite -> dashboard path be validated off-site,
before anyone flies anywhere. The RSSI ramps up and back down, simulating walking
toward the emitter and past it.

  ./make_test_capture.py                 # 60s approach-and-retreat, ch64
  ./deauth_hunt.py --replay test.pcap    # watch the meter track it

SAFETY: this writes a FILE. It transmits nothing and needs no wireless hardware.
The target BSSIDs are locally-administered placeholders (02:00:5e:..) that match
no real hardware, so even if the file were replayed onto an interface it could
not deauthenticate anything real.

No production BSSID is stored in this repo. If you genuinely need byte-identical
fidelity with a real capture, pass --targets with a comma-separated list (or a
path to a file of one BSSID per line) kept outside version control - and never
replay the result onto an interface, because it is then a working deauth.
"""

import argparse
import math
import random
import struct

# Locally-administered placeholders (the 0x02 prefix is never vendor-assigned),
# preserving the real structure: 8 BSSIDs spread across 3 physical APs. These
# match no real hardware, so the generated file cannot deauthenticate anything.
SAFE_TARGETS = [
    "02:00:5e:00:01:8c", "02:00:5e:00:01:8d", "02:00:5e:00:01:8f",
    "02:00:5e:00:02:ac", "02:00:5e:00:02:ad", "02:00:5e:00:02:af",
    "02:00:5e:00:03:8c", "02:00:5e:00:03:8d",
]

ATTACKER_SA = "fe:ff:ff:ff:ff:ff"
REASON = 7
DATARATE_500K = 24          # 12 Mbps OFDM
LINKTYPE_RADIOTAP = 127

# radiotap present bits: Flags(1) Rate(2) Channel(3) dBmAntSignal(5) Antenna(11)
PRESENT = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 11)
CHAN_FLAGS_5G_OFDM = 0x0140


def load_targets(spec):
    """--targets: a comma-separated list, or a path to one-BSSID-per-line."""
    try:
        with open(spec) as fh:
            items = [ln.split("#")[0].strip() for ln in fh]
    except OSError:
        items = [x.strip() for x in spec.split(",")]
    items = [x for x in items if x]
    if not items:
        raise SystemExit(f"--targets: no BSSIDs found in {spec!r}")
    return items


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


def radiotap(freq, dbm, antenna=0):
    # 8-byte preamble + Flags,Rate at 8,9 + Channel (aligned 2) at 10..13
    # + signal at 14 + antenna at 15  =  16 bytes total
    body = struct.pack("<BB", 0x00, DATARATE_500K)
    body += struct.pack("<HH", freq, CHAN_FLAGS_5G_OFDM)
    body += struct.pack("<bB", dbm, antenna)
    hdr = struct.pack("<BBHI", 0, 0, 8 + len(body), PRESENT)
    return hdr + body


def deauth(dst, src, bssid, seq, reason=REASON):
    frame = struct.pack("<BBH", 0xC0, 0x00, 0x0030)          # FC + duration
    frame += mac_bytes(dst) + mac_bytes(src) + mac_bytes(bssid)
    frame += struct.pack("<H", (seq << 4) & 0xFFFF)          # seq ctl, frag 0
    frame += struct.pack("<H", reason)
    return frame                                             # 26 bytes


def rssi_profile(t, total, near=-45, far=-78, jitter=1.2):
    """Approach and retreat: far -> near -> far, with realistic jitter."""
    phase = t / total
    shape = math.sin(math.pi * min(max(phase, 0.0), 1.0)) ** 0.65
    base = far + (near - far) * shape
    return int(round(base + random.gauss(0, jitter)))


def main():
    print("ANTENNA: 0 antennas needed - neither directional nor omni; this "
          "generates a pcap file offline and uses no wireless radio at all.")
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", default="test.pcap")
    ap.add_argument("-d", "--duration", type=float, default=60.0, help="seconds")
    ap.add_argument("-r", "--rate", type=float, default=12.1, help="frames/sec")
    ap.add_argument("-f", "--freq", type=int, default=5320, help="MHz (ch64)")
    ap.add_argument("--near", type=int, default=-45, help="strongest dBm")
    ap.add_argument("--far", type=int, default=-78, help="weakest dBm")
    ap.add_argument("--noise", type=int, default=0,
                    help="also emit N/sec of unrelated beacons the filter must reject")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--targets", metavar="LIST|FILE",
                    help="comma-separated BSSIDs, or a file with one per line, "
                         "to use instead of the safe placeholders (fidelity "
                         "testing only - NEVER replay the result)")
    args = ap.parse_args()

    targets = load_targets(args.targets) if args.targets else SAFE_TARGETS
    random.seed(args.seed)
    n = int(args.duration * args.rate)
    seq = 1670
    t0 = 1756000000.0

    with open(args.out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RADIOTAP))

        def emit(ts, pkt):
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(pkt), len(pkt)))
            f.write(pkt)

        events = []
        for i in range(n):
            t = i / args.rate + random.gauss(0, 0.004)
            events.append((t, "deauth"))
        if args.noise:
            for i in range(int(args.duration * args.noise)):
                events.append((i / args.noise, "beacon"))
        events.sort()

        deauths = 0
        for t, kind in events:
            if kind == "deauth":
                dbm = rssi_profile(t, args.duration, args.near, args.far)
                bssid = targets[deauths % len(targets)]
                pkt = radiotap(args.freq, dbm) + deauth(bssid, ATTACKER_SA, bssid, seq)
                seq = (seq + 1) & 0xFFF
                deauths += 1
            else:
                # A beacon from an innocent AP - the display filter must drop it.
                body = struct.pack("<BBH", 0x80, 0x00, 0x0000)
                body += mac_bytes("ff:ff:ff:ff:ff:ff") * 1
                body += mac_bytes("00:11:22:33:44:55") * 2
                body += struct.pack("<H", 0) + b"\x00" * 12
                pkt = radiotap(args.freq, -60) + body
            emit(t0 + t, pkt)

    peak = max(rssi_profile(i / args.rate, args.duration, args.near, args.far)
               for i in range(n))
    print(f"wrote {args.out}")
    if args.targets:
        print("  !! built with caller-supplied BSSIDs - if any of them are real,")
        print("  !! this file is a working deauth. Keep it off any live interface.")
    else:
        print("  targets: locally-administered placeholders - harmless if replayed")
    print(f"  {deauths} deauth frames @ {args.rate} fps over {args.duration:.0f}s")
    print(f"  signature: sa={ATTACKER_SA} reason={REASON} rate={DATARATE_500K * 0.5} Mbps "
          f"freq={args.freq} MHz")
    print(f"  RSSI sweeps {args.far} -> ~{peak} -> {args.far} dBm")
    if args.noise:
        print(f"  plus {int(args.duration * args.noise)} decoy beacons the filter must reject")
    print(f"\n  ./deauth_hunt.py --replay {args.out}")


if __name__ == "__main__":
    main()
