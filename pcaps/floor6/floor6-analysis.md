# Deauthentication sources and targets — floor 6 full 5 GHz sweep

**Captures:** `/home/cristi/deauth-hunt/pcaps/floor6/floor_6_channel_<CH>.pcapng` (25 files, 60 s each, passive monitor mode, wlan1)  
**Date:** 2026-09-03, 15:38 – 16:03  
**Band:** 5 GHz only. Channels 36–165 captured; 169–177 refused by the adapter (outside GB regulatory domain). No 2.4 GHz or 6 GHz coverage in this sweep.

**Forged deauthentication frames found:** 8,517 across 8 of 25 channels. All have source address `ff:ff:ff:ff:ff:ff` and reason code 7. Every source is an HWKI radio; every target is a Cisco `-SR` BSSID.

Method: per channel, forged deauths were clustered by received signal strength, and each cluster matched against every beaconing AP on that channel using the three-value signal vector `[combined, antenna A, antenna B]` plus a temporal fading correlation over 5-second bins. Capture was passive (no transmission).

---

## Channel overview

| Channel | Frequency | Sub-band | Forged deauths | Beaconing APs | Source radios |
|---|---|---|---|---|---|
| 36 | 5180 MHz | UNII-1 | 893 | 17 | 1 |
| 44 | 5220 MHz | UNII-1 | 2,284 | 55 | 2 |
| 60 | 5300 MHz | UNII-2A | 564 | 12 | 1 |
| 64 | 5320 MHz | UNII-2A | 368 | 38 | 1 |
| 104 | 5520 MHz | UNII-2C | 233 | 36 | 1 |
| 108 | 5540 MHz | UNII-2C | 1,786 | 37 | 1 |
| 116 | 5580 MHz | UNII-2C | 1,321 | 20 | 1 |
| 132 | 5660 MHz | UNII-2C | 1,068 | 39 | 1 |
| 40, 48, 52, 56, 100, 112, 120, 124, 128, 136, 140, 144, 149, 153, 157, 161, 165 | — | — | 0 | — | — |

---

## Sources — 9 radios on 5 physical Cisco Meraki access points, all HWKI

Every source matched to the four virtual BSSIDs of one HWKI radio, typically within 0.1 dB, with the nearest non-HWKI candidate 1–10 dB away. The `8c:88:81` address in each `88:81` radio is a burned-in **Cisco Meraki** OUI, so the vendor is confirmed from the address, not inferred. The `88:91` radios are the same boxes' second 5 GHz radio (octet 3 bit 4 flipped, identical SSID template).

| Ch | Source radio | Physical AP | SSIDs | RSSI (dBm) | Frames | Vector match | Fading r | Next-best candidate |
|---|---|---|---|---|---|---|---|---|
| 36 | `*:88:81:f1:90:a0` | `…f1:90:a0` | HWKI set | -76.5 | 893 | 0.02 dB | +0.944 | 6.01 dB (WORKPLACE-SR) |
| 44 | `*:88:81:f1:8a:c0` | `…f1:8a:c0` | HWKI set | -61.3 | 1,618 | 0.02 dB | +0.958 | 3.16 dB (WORKPLACE-SR) |
| 44 | `*:88:81:f1:8a:60` | `…f1:8a:60` | HWKI set | -91.2 | 666 | 0.07 dB | +0.862 | 6.54 dB (GUEST-SR) |
| 60 | `*:88:81:f1:79:40` | `…f1:79:40` | HWKI set | -65.3 | 564 | 0.11 dB | +0.958 | 2.03 dB (MODERN-SR) |
| 64 | `*:88:81:f1:79:e0` | `…f1:79:e0` | HWKI set | -92.6 | 368 | 0.17 dB | +0.693 | 10.54 dB (WORKPLACE-SR) |
| 104 | `*:88:91:f1:79:e0` | `…f1:79:e0` | HWKI set | -89.1 | 233 | 0.05 dB | +0.798 | 3.41 dB (MODERN-SR) |
| 108 | `*:88:91:f1:79:40` | `…f1:79:40` | HWKI set | -58.9 | 1,786 | 0.02 dB | +0.985 | 1.15 dB (WALKIN-SR) |
| 116 | `*:88:91:f1:8a:c0` | `…f1:8a:c0` | HWKI set | -59.7 | 1,321 | 0.03 dB | +0.993 | 2.74 dB (MODERN-SR) |
| 132 | `*:88:91:f1:90:a0` | `…f1:90:a0` | HWKI set | -71.2 | 1,068 | 0.04 dB | +0.994 | 2.92 dB (WORKPLACE-SR) |
| | | | | **Total** | **8,517** | | | |

Physical AP grouping (two radios per box, `88:81` = radio 1, `88:91` = radio 2):

| Physical AP (address tail) | Radio 1 channel | Radio 2 channel | Frames | Strongest RSSI |
|---|---|---|---|---|
| `…f1:8a:c0` | 44 | 116 | 2,939 | -59.7 dBm |
| `…f1:79:40` | 60 | 108 | 2,350 | -58.9 dBm |
| `…f1:90:a0` | 36 | 132 | 1,961 | -71.2 dBm |
| `…f1:8a:60` | 44 | — | 666 | -91.2 dBm |
| `…f1:79:e0` | 64 | 104 | 601 | -89.1 dBm |

All nine source radios also beacon on their channel with the same SSID set (`HWKI-CORPORATE`, `HWKI-MANAGEMENT`, `HWKI-GUEST`, one hidden). None is ever a target. The Meraki radio confirmed earlier at `6c:ef:bd:bc:b7:10` does not beacon on any channel in this sweep.

Sequence-counter check: +1 between consecutive frames on the strong clusters is 83–94 %, i.e. one dedicated transmit stream per radio. The three weak clusters (below −89 dBm) show 42–50 % only because the sniffer misses many frames at that level.

---

## Targets — per channel

All targets carry Cisco Systems OUIs (`f8:6b:d9`, `b8:11:4b`, `70:61:7b`, `5c:5a:c7`) and belong to the `-SR` network. *Physical radio* is the five-octet prefix identifying the AP; the last octet identifies the SSID (`…c`/`…b` WORKPLACE-SR, `…d` WALKIN-SR, `…e` MODERN-SR, `…f` GUEST-SR). "not on channel" means the BSSID was not beaconing on that channel during the capture — the containing radio is working from a controller-side list.


### Channel 36 (5180 MHz) — 893 frames

| Target BSSID | SSID | Physical radio | Beacon RSSI | PMF | Frames | From |
|---|---|---|---|---|---|---|
| `f8:6b:d9:6f:3b:ac` | WORKPLACE-SR | `f8:6b:d9:6f:3b` | -73 dBm | no | 206 | `*:88:81:f1:90:a0` |
| `5c:5a:c7:14:b7:6f` | not on channel | `5c:5a:c7:14:b7` | — | — | 170 | `*:88:81:f1:90:a0` |
| `f8:6b:d9:6f:3b:af` | GUEST-SR | `f8:6b:d9:6f:3b` | -73 dBm | — | 163 | `*:88:81:f1:90:a0` |
| `f8:6b:d9:6f:3b:ad` | WALKIN-SR | `f8:6b:d9:6f:3b` | -73 dBm | no | 155 | `*:88:81:f1:90:a0` |
| `5c:5a:c7:14:b7:6c` | not on channel | `5c:5a:c7:14:b7` | — | — | 154 | `*:88:81:f1:90:a0` |
| `5c:5a:c7:14:b7:6d` | not on channel | `5c:5a:c7:14:b7` | — | — | 32 | `*:88:81:f1:90:a0` |
| `70:61:7b:d4:f7:ad` | not on channel | `70:61:7b:d4:f7` | — | — | 13 | `*:88:81:f1:90:a0` |

### Channel 44 (5220 MHz) — 2,284 frames

| Target BSSID | SSID | Physical radio | Beacon RSSI | PMF | Frames | From |
|---|---|---|---|---|---|---|
| `b8:11:4b:92:ba:cf` | GUEST-SR | `b8:11:4b:92:ba` | -77 dBm | — | 254 | `*:88:81:f1:8a:c0` (192) + `*:88:81:f1:8a:60` (62) |
| `b8:11:4b:fc:f4:ec` | WORKPLACE-SR | `b8:11:4b:fc:f4` | -70 dBm | no | 251 | `*:88:81:f1:8a:c0` (181) + `*:88:81:f1:8a:60` (70) |
| `b8:11:4b:fc:f4:ef` | GUEST-SR | `b8:11:4b:fc:f4` | -70 dBm | — | 236 | `*:88:81:f1:8a:c0` (186) + `*:88:81:f1:8a:60` (50) |
| `b8:11:4b:92:ba:cc` | WORKPLACE-SR | `b8:11:4b:92:ba` | -77 dBm | no | 227 | `*:88:81:f1:8a:c0` (183) + `*:88:81:f1:8a:60` (44) |
| `f8:6b:d9:30:d8:ef` | GUEST-SR | `f8:6b:d9:30:d8` | -62 dBm | — | 188 | `*:88:81:f1:8a:c0` |
| `f8:6b:d9:30:d8:ed` | WALKIN-SR | `f8:6b:d9:30:d8` | -62 dBm | no | 168 | `*:88:81:f1:8a:c0` |
| `f8:6b:d9:30:d8:eb` | WORKPLACE-SR | `f8:6b:d9:30:d8` | -62 dBm | yes | 145 | `*:88:81:f1:8a:c0` |
| `f8:6b:d9:42:3c:ac` | WORKPLACE-SR | `f8:6b:d9:42:3c` | -86 dBm | no | 119 | `*:88:81:f1:8a:c0` |
| `f8:6b:d9:42:3c:af` | GUEST-SR | `f8:6b:d9:42:3c` | -86 dBm | — | 113 | `*:88:81:f1:8a:c0` |
| `f8:6b:d9:42:3c:ad` | WALKIN-SR | `f8:6b:d9:42:3c` | -86 dBm | no | 112 | `*:88:81:f1:8a:c0` |
| `b8:11:4b:fc:e6:2c` | WORKPLACE-SR | `b8:11:4b:fc:e6` | -74 dBm | no | 79 | `*:88:81:f1:8a:60` (69) + `*:88:81:f1:8a:c0` (10) |
| `70:61:7b:e4:fe:8f` | not on channel | `70:61:7b:e4:fe` | — | — | 71 | `*:88:81:f1:8a:60` |
| `b8:11:4b:fc:e6:2d` | WALKIN-SR | `b8:11:4b:fc:e6` | -74 dBm | no | 65 | `*:88:81:f1:8a:60` (54) + `*:88:81:f1:8a:c0` (11) |
| `70:61:7b:e4:fe:8d` | not on channel | `70:61:7b:e4:fe` | — | — | 63 | `*:88:81:f1:8a:60` |
| `f8:6b:d9:49:45:eb` | WORKPLACE-SR | `f8:6b:d9:49:45` | -78 dBm | yes | 61 | `*:88:81:f1:8a:60` |
| `70:61:7b:d9:56:4d` | WALKIN-SR | `70:61:7b:d9:56` | -77 dBm | no | 61 | `*:88:81:f1:8a:60` |
| `b8:11:4b:fc:e6:2f` | GUEST-SR | `b8:11:4b:fc:e6` | -74 dBm | — | 43 | `*:88:81:f1:8a:60` (33) + `*:88:81:f1:8a:c0` (10) |
| `70:61:7b:e4:fe:8c` | not on channel | `70:61:7b:e4:fe` | — | — | 27 | `*:88:81:f1:8a:60` |
| `f8:6b:d9:49:45:ed` | WALKIN-SR | `f8:6b:d9:49:45` | -78 dBm | no | 1 | `*:88:81:f1:8a:60` |

### Channel 60 (5300 MHz) — 564 frames

| Target BSSID | SSID | Physical radio | Beacon RSSI | PMF | Frames | From |
|---|---|---|---|---|---|---|
| `70:61:7b:9f:92:4f` | GUEST-SR | `70:61:7b:9f:92` | -66 dBm | — | 174 | `*:88:81:f1:79:40` |
| `f8:6b:d9:42:43:6c` | WORKPLACE-SR | `f8:6b:d9:42:43` | -66 dBm | no | 152 | `*:88:81:f1:79:40` |
| `70:61:7b:9f:92:4c` | WORKPLACE-SR | `70:61:7b:9f:92` | -66 dBm | no | 133 | `*:88:81:f1:79:40` |
| `70:61:7b:9f:92:4d` | WALKIN-SR | `70:61:7b:9f:92` | -66 dBm | no | 105 | `*:88:81:f1:79:40` |

### Channel 64 (5320 MHz) — 368 frames

| Target BSSID | SSID | Physical radio | Beacon RSSI | PMF | Frames | From |
|---|---|---|---|---|---|---|
| `f8:6b:d9:30:69:0c` | WORKPLACE-SR | `f8:6b:d9:30:69` | -82 dBm | no | 79 | `*:88:81:f1:79:e0` |
| `b8:11:4b:92:39:8d` | not on channel | `b8:11:4b:92:39` | — | — | 78 | `*:88:81:f1:79:e0` |
| `b8:11:4b:92:39:8f` | not on channel | `b8:11:4b:92:39` | — | — | 70 | `*:88:81:f1:79:e0` |
| `70:61:7b:e4:c3:ec` | WORKPLACE-SR | `70:61:7b:e4:c3` | -87 dBm | no | 43 | `*:88:81:f1:79:e0` |
| `f8:6b:d9:49:79:ab` | WORKPLACE-SR | `f8:6b:d9:49:79` | -76 dBm | yes | 43 | `*:88:81:f1:79:e0` |
| `f8:6b:d9:49:79:ad` | WALKIN-SR | `f8:6b:d9:49:79` | -76 dBm | no | 41 | `*:88:81:f1:79:e0` |
| `f8:6b:d9:49:79:af` | GUEST-SR | `f8:6b:d9:49:79` | -76 dBm | — | 12 | `*:88:81:f1:79:e0` |
| `f8:6b:d9:30:69:0d` | WALKIN-SR | `f8:6b:d9:30:69` | -82 dBm | no | 2 | `*:88:81:f1:79:e0` |

### Channel 104 (5520 MHz) — 233 frames

| Target BSSID | SSID | Physical radio | Beacon RSSI | PMF | Frames | From |
|---|---|---|---|---|---|---|
| `f8:6b:d9:42:40:6c` | WORKPLACE-SR | `f8:6b:d9:42:40` | -68 dBm | no | 56 | `*:88:91:f1:79:e0` |
| `b8:11:4b:fc:f6:8c` | WORKPLACE-SR | `b8:11:4b:fc:f6` | -86 dBm | no | 56 | `*:88:91:f1:79:e0` |
| `f8:6b:d9:42:40:6f` | GUEST-SR | `f8:6b:d9:42:40` | -68 dBm | — | 47 | `*:88:91:f1:79:e0` |
| `f8:6b:d9:42:40:6d` | WALKIN-SR | `f8:6b:d9:42:40` | -68 dBm | no | 40 | `*:88:91:f1:79:e0` |
| `f8:6b:d9:42:9f:4c` | WORKPLACE-SR | `f8:6b:d9:42:9f` | -87 dBm | no | 27 | `*:88:91:f1:79:e0` |
| `f8:6b:d9:42:68:0d` | WALKIN-SR | `f8:6b:d9:42:68` | -88 dBm | no | 4 | `*:88:91:f1:79:e0` |
| `f8:6b:d9:42:68:0c` | WORKPLACE-SR | `f8:6b:d9:42:68` | -88 dBm | no | 3 | `*:88:91:f1:79:e0` |

### Channel 108 (5540 MHz) — 1,786 frames

| Target BSSID | SSID | Physical radio | Beacon RSSI | PMF | Frames | From |
|---|---|---|---|---|---|---|
| `b8:11:4b:fc:a9:0c` | WORKPLACE-SR | `b8:11:4b:fc:a9` | -74 dBm | no | 217 | `*:88:91:f1:79:40` |
| `f8:6b:d9:30:7e:cb` | WORKPLACE-SR | `f8:6b:d9:30:7e` | -64 dBm | yes | 201 | `*:88:91:f1:79:40` |
| `f8:6b:d9:30:7e:cd` | WALKIN-SR | `f8:6b:d9:30:7e` | -64 dBm | no | 184 | `*:88:91:f1:79:40` |
| `f8:6b:d9:49:54:8c` | WORKPLACE-SR | `f8:6b:d9:49:54` | -59 dBm | no | 182 | `*:88:91:f1:79:40` |
| `f8:6b:d9:30:7e:cf` | GUEST-SR | `f8:6b:d9:30:7e` | -64 dBm | — | 176 | `*:88:91:f1:79:40` |
| `b8:11:4b:fc:a9:0f` | GUEST-SR | `b8:11:4b:fc:a9` | -73 dBm | — | 169 | `*:88:91:f1:79:40` |
| `f8:6b:d9:49:54:8f` | GUEST-SR | `f8:6b:d9:49:54` | -59 dBm | — | 169 | `*:88:91:f1:79:40` |
| `f8:6b:d9:49:54:8d` | WALKIN-SR | `f8:6b:d9:49:54` | -59 dBm | no | 168 | `*:88:91:f1:79:40` |
| `b8:11:4b:fc:a9:0d` | WALKIN-SR | `b8:11:4b:fc:a9` | -74 dBm | no | 165 | `*:88:91:f1:79:40` |
| `70:61:7b:9f:8f:cf` | GUEST-SR | `70:61:7b:9f:8f` | -73 dBm | — | 155 | `*:88:91:f1:79:40` |

### Channel 116 (5580 MHz) — 1,321 frames

| Target BSSID | SSID | Physical radio | Beacon RSSI | PMF | Frames | From |
|---|---|---|---|---|---|---|
| `f8:6b:d9:42:9d:2c` | WORKPLACE-SR | `f8:6b:d9:42:9d` | -75 dBm | no | 191 | `*:88:91:f1:8a:c0` |
| `f8:6b:d9:30:5d:cf` | GUEST-SR | `f8:6b:d9:30:5d` | -58 dBm | — | 187 | `*:88:91:f1:8a:c0` |
| `f8:6b:d9:30:5d:cc` | WORKPLACE-SR | `f8:6b:d9:30:5d` | -58 dBm | no | 187 | `*:88:91:f1:8a:c0` |
| `f8:6b:d9:30:5d:cd` | WALKIN-SR | `f8:6b:d9:30:5d` | -58 dBm | no | 174 | `*:88:91:f1:8a:c0` |
| `b8:11:4b:92:5c:cf` | GUEST-SR | `b8:11:4b:92:5c` | -80 dBm | — | 170 | `*:88:91:f1:8a:c0` |
| `f8:6b:d9:42:9d:2d` | WALKIN-SR | `f8:6b:d9:42:9d` | -75 dBm | no | 163 | `*:88:91:f1:8a:c0` |
| `b8:11:4b:92:5c:cd` | WALKIN-SR | `b8:11:4b:92:5c` | -80 dBm | no | 143 | `*:88:91:f1:8a:c0` |
| `b8:11:4b:92:5c:cc` | WORKPLACE-SR | `b8:11:4b:92:5c` | -80 dBm | no | 106 | `*:88:91:f1:8a:c0` |

### Channel 132 (5660 MHz) — 1,068 frames

| Target BSSID | SSID | Physical radio | Beacon RSSI | PMF | Frames | From |
|---|---|---|---|---|---|---|
| `f8:6b:d9:49:7f:cf` | GUEST-SR | `f8:6b:d9:49:7f` | -40 dBm | — | 168 | `*:88:91:f1:90:a0` |
| `f8:6b:d9:30:7b:0d` | WALKIN-SR | `f8:6b:d9:30:7b` | -72 dBm | no | 164 | `*:88:91:f1:90:a0` |
| `b8:11:4b:fc:d3:0d` | WALKIN-SR | `b8:11:4b:fc:d3` | -88 dBm | no | 162 | `*:88:91:f1:90:a0` |
| `f8:6b:d9:49:7f:cb` | WORKPLACE-SR | `f8:6b:d9:49:7f` | -40 dBm | yes | 160 | `*:88:91:f1:90:a0` |
| `f8:6b:d9:49:7f:cd` | WALKIN-SR | `f8:6b:d9:49:7f` | -40 dBm | no | 153 | `*:88:91:f1:90:a0` |
| `f8:6b:d9:30:58:0c` | not on channel | `f8:6b:d9:30:58` | — | — | 136 | `*:88:91:f1:90:a0` |
| `f8:6b:d9:30:58:0f` | not on channel | `f8:6b:d9:30:58` | — | — | 121 | `*:88:91:f1:90:a0` |
| `f8:6b:d9:30:78:2c` | not on channel | `f8:6b:d9:30:78` | — | — | 4 | `*:88:91:f1:90:a0` |

**Totals across the sweep:** 71 target BSSIDs on 33 physical SR access points.

### Observations

- **By SSID:** WORKPLACE-SR 2,924, GUEST-SR 2,424, WALKIN-SR 2,230; not-beaconing-on-channel 939. **MODERN-SR is never targeted** on any channel, despite beaconing on every one of them alongside the targeted SSIDs.
- **The exemption is the security suite, not the PMF bit.** MODERN-SR advertises AKM 802.1X + 802.1X-SHA256 (`akm=1,5`) with PMF-capable. WORKPLACE-SR's PMF-capable variant (`…b` BSSIDs, `akm=1,3` = 802.1X + FT) is hit 5 times across 5 BSSIDs: `f8:6b:d9:30:d8:eb` ch44 (145), `f8:6b:d9:49:45:eb` ch44 (61), `f8:6b:d9:49:79:ab` ch64 (43), `f8:6b:d9:30:7e:cb` ch108 (201), `f8:6b:d9:49:7f:cb` ch132 (160). So Meraki's skip tracks the SHA-256/WPA3-class suite that MODERN-SR uses, not the mere presence of the MFP-capable flag. This refines the earlier finding.
- **Every last octet is b, c, d or f — never e.** Consistent with all previous floors.
- **Controller-side lists.** Several targets per channel are not beaconing on that channel at all (e.g. `5c:5a:c7:14:b7:*` on ch 36, `70:61:7b:e4:fe:*` on ch 44, `f8:6b:d9:30:58:*` on ch 132). The radio is containing addresses it cannot hear.
- **Strongest local target:** `f8:6b:d9:49:7f:*` on ch 132 at −40 dBm — the SR access point nearest the capture point on floor 6, being contained by the HWKI radio at `…f1:90:a0` from −71 dBm.

---

## Everything else

Ordinary (non-forged) deauthentications in the sweep — normal AP/client housekeeping, not containment:

| Ch | Count | From | To | Reason |
|---|---|---|---|---|
| 108 | 5 | `b8:11:4b:92:28:8f (GUEST-SR AP)` | `fe:40:d5:d0:49:3b (client)` | 7 — class-3 frame from non-associated STA |
| 104 | 5 | `f8:6b:d9:30:d8:af (GUEST-SR AP)` | `4e:f9:4e:5a:43:73 (client)` | 2 — previous auth no longer valid |
| 64 | 2 | `f8:6b:d9:30:60:2f (AP)` | `f2:cd:e6:bd:45:94 (client)` | 2 |
| 60 | 2 | `f8:d9:b8:2e:5e:71 (AP, non-SR)` | `d4:d8:53:ad:67:54 (client)` | 2 |
| 120 | 2 | `b8:11:4b:fc:f5:2f (AP)` | `be:67:26:2c:29:32 (client)` | 2 |
| 60 | 1 | `70:61:7b:9f:92:4f (GUEST-SR AP)` | `d2:1d:99:27:34:32 (client)` | 252 (vendor-specific) |
| 52 | 1 | `f8:6b:d9:01:5b:8f (AP)` | `92:97:fb:43:b2:20 (client)` | 252 |
| 52 | 1 | `70:61:7b:e4:f6:af (AP)` | `7a:79:54:90:62:79 (client)` | 252 |
| 116 | 1 | `f8:6b:d9:30:5d:cf (GUEST-SR AP)` | `d2:1d:99:27:34:32 (client)` | 252 |
| 108 | 1 | `f8:6b:d9:49:45:4f (AP)` | `7a:79:54:90:62:79 (client)` | 2 |
| 36 | 1 | `c0:56:27:be:b9:e3 (CRES_SR AP)` | `b2:19:17:fe:81:81 (client)` | 7 |
| 36 | 1 | `b2:19:17:fe:81:81 (client)` | `c0:56:27:be:b9:e3 (CRES_SR AP)` | 3 — station leaving |

Channels 149–165 (UNII-3, 5745–5825 MHz) carried a few hundred frames each and no deauthentications of any kind: the upper band is essentially unused in this building. Channel 144 was empty.

---

*Analysis produced with tshark 4.6.6 from passive monitor-mode captures on wlan1 (Alfa, `00:c0:ca:b6:d3:26`), 2026-09-03.*
