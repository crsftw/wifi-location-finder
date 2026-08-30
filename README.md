# deauth-hunt

A receive-only WiFi direction-finding toolkit for an Alfa AWUS036AXML (mt7921u).
It started as a hunt for one specific 802.11 deauthentication flood (the analysis
below), and grew into **`sniffer.py`** — an all-in-one tool that walks down the
*transmitter* behind any network, any deauth flood, or any specific MAC, using a
live RSSI meter with audio and colour feedback.

Everything here is **receive-only** — it never injects, deauthenticates, probes,
associates or scans (see [Receive-only, and provably so](#receive-only-and-provably-so)).

## `sniffer.py` — the all-in-one tool

Start it and you get a channel-hopping **scan screen**. Press **`S`** to cycle
between four modes; hit **ENTER** on a target and you drop into a shared RSSI
**hunt screen** to direction-find it.

| Mode (`S` to switch) | What it lists | ENTER hunts |
|---|---|---|
| **NETWORKS** | APs heard, hidden ones as `<hidden>` (SSID, BSSID, ch, **GHz**, RSSI, enc, **VENDOR**, **DEVICE**). Collapsed into **one row per physical device** by default (the 8 BSSIDs of one radio become a single `Guest +7` row); press **`g`** to expand to per-SSID. `SPACE` multi-selects a device (or a BSSID in flat view) | that device's transmitter(s) |
| **DEAUTH FLOODS** | channels under a deauth flood, ranked by deauths/sec, `⚑` = flood, with **VENDOR**/**DEVICE** for each source. A `ALL deauths on ch N` row per channel handles spoofed/randomised sources | the attacker's transmitter (or every deauth on that channel) |
| **PROBE CLIENTS** | client devices heard probing (phones, laptops, IoT), ranked by RSSI, with **VENDOR**, a **PHY** capability class, and the **PROBES** column — the named networks each client is searching for (its saved-network list, which ties a device to its home/work SSIDs) | that client's transmitter |
| **TRACK MAC** | a text box — type a MAC | that MAC, **auto-located** by hopping until it's heard, then parked on its channel |

Every list has a **GHz** column showing whether the target transmits on **2.x**
or **5.x GHz**.

The scanner uses **adaptive channel hopping** by default (the header shows
`(adaptive)`): it still visits every channel each sweep, but weights the dwell
toward activity — a flooded channel gets the most time, an active one the base
dwell (`--dwell`), a silent one the minimum (`--min-dwell`), and 2.4 GHz
primaries (1/6/11) stay warm even when quiet. That collapses the many empty
5 GHz channels and concentrates listening where the devices are, so a typical
sweep finishes in about half the time and the RSSI stream on a busy channel is
much denser. Pass **`--no-adaptive`** for plain uniform hopping.

### Device identification (VENDOR / DEVICE columns)

The scan lists carry these passive-identity columns, and the identity follows you into
the hunt header (`deauth src fe:ff:ff:ff:ff:ff [attacker]`):

- **VENDOR** — the transmitter's manufacturer, resolved from its MAC's OUI against
  the on-box IEEE database (`/usr/share/ieee-data/oui.txt`). A **`rnd`** here means
  the MAC is locally-administered (randomized), so the OUI is meaningless — common
  for modern phones/laptops, rare for routers, Raspberry Pis, or ESP-based hardware.
- **DEVICE** — a best-effort guess of *what it is*, most specific first: the
  cleartext **WPS** device/model name from beacons (often the exact router model,
  sometimes literally the hostname) → a known device-maker (**Raspberry Pi**,
  **ESP32/8266**…) → the frame's role (**AP** / **attacker**).

So a Pi-based deauther shows up as `Raspberry Pi` / `attacker`, and a TP-Link AP
advertising WPS as `TP-Link` / `Archer C7` at a glance. All of this is passive
metadata already in the frames — still **receive-only**, no probing. If the OUI
database isn't installed, the columns stay sparse (install the `ieee-data` package).

#### Pwnagotchi / deauther badges

The DEVICE column also surfaces a **threat badge** when a transmitter looks like
an attack device, from solid signals only (no fragile payload guessing):

| Badge | Meaning | Signal |
|---|---|---|
| `⚠ pwnagotchi` | a pwnagotchi is present, announcing itself | a beacon whose BSSID is `de:ad:be:ef:de:ad` — pwnagotchi's advertisement signature (definitive, no `?`) |
| `⚠ pwnagotchi?` | likely a pwnagotchi / Pi-based deauther | a **deauth flood** whose source has a **Raspberry Pi** OUI |
| `⚠ ESP deauther?` | likely an ESP8266/ESP32 "Deauther" board | a deauth flood whose source has an **Espressif** OUI |
| `⚠ deauther?` | some device is flooding deauths | a deauth flood from any other (or spoofed) source |

The `?` marks strong-but-not-certain evidence; the bare `de:ad:be:ef:de:ad`
beacon is certain. The badge follows a target into the hunt header
(`deauth src b8:27:eb:… [Raspberry Pi · ⚠ pwnagotchi?]`). Note that a pwnagotchi
randomises the *transmitter* of its advertisement beacons, so those aren't
reliably huntable — the huntable target is its deauth-flooding radio (the
Raspberry-Pi-OUI source), which the badge points you straight at.

#### Capability fingerprint (PHY class)

Beacons and probe requests advertise a device's 802.11 capabilities, which give
a coarse **device class** independent of the OUI. From the HT/VHT/HE capability
elements and the HT MCS map, each transmitter gets a compact fingerprint:

- **generation** — `ax` (HE / Wi-Fi 6), `ac` (VHT / Wi-Fi 5), `n` (HT / Wi-Fi 4);
- **band** — `2.4G` / `5G` (from the frequency);
- **spatial streams** — `1ss` / `2ss` / `3ss` (from the MCS Rx bitmask).

So a single-stream 2.4 GHz 802.11n device reads `n·2.4G·1ss` — the class of a
Raspberry Pi Zero W or an ESP board — while a modern phone reads `ax·5G·2ss`.
The fingerprint shows as the **PHY** column in PROBE CLIENTS and is folded into
the hunt header (`[Raspberry Pi · n·2.4G·1ss]`) so you know what you're walking
toward. It stays blank when no capability elements were seen — no unconfirmed
guesses.

Direction finding tracks the **transmitter only** (`wlan.sa` / `wlan.ta`), never
the destination: RSSI is the strength of whoever *sent* the frame, so a frame
*to* your target carries some other radio's signal and would point the wrong way.

### The hunt screen (shared by all four modes)

- **Big dBm readout**, rolling average, **peak-hold**, and a live sparkline.
- **Gradient bars** — a red → orange → yellow → green ramp (weak → strong).
- **Audio warmer/colder cues:**
  - one short **high** beep (1200 Hz) when the smoothed signal *rises* past the
    threshold (default 1 dB over a 10 s window),
  - two short **low** beeps (500 Hz) when it *falls*.
  - `--geiger` instead gives a continuous tone whose **rate and pitch both climb**
    with signal strength (a metal-detector feel) — good for the final approach.

  Audio uses a real backend (`sox`/`pw-play`), not the terminal bell, and works
  under `sudo` (it plays as your user). Test it with no radio: `./sniffer.py --test-beep`.

### Quickstart

```bash
sudo ./init-hunt.sh          # put the card in monitor mode (see below)
sudo ./sniffer.py            # scan → S to switch modes → ENTER to hunt
sudo ./sniffer.py --geiger   # continuous-tone hunt
```

`sniffer.py` needs `sudo` because it changes channels (`iw`) to hop and to park
on a target. `init-hunt.sh` still does the one-time monitor-mode setup.

### Keys

| Where | Key | Action |
|---|---|---|
| Scan screen | `S` | switch mode: NETWORKS → DEAUTH FLOODS → PROBE CLIENTS → TRACK MAC |
| | `g` | (NETWORKS) toggle device view (one row per radio) ↔ per-SSID |
| | ↑ / ↓ | move the cursor |
| | `SPACE` | (NETWORKS) select / deselect the device (or BSSID in per-SSID view) |
| | `ENTER` | hunt the selected/typed target |
| | `ESC` | cancel a MAC auto-locate |
| | `q` | quit |
| Hunt screen | `p` | reset peak-hold (do this at the start of every antenna sweep) |
| | `b` | toggle the beeps |
| | `q` | back to the scan screen |

### Antenna

**Scan with an omni** (both jacks, or at least one dual-band omni) so you don't
miss a network/flood coming from any direction or either band. When you commit
to a target, `sniffer.py` reminds you to **swap to a single directional antenna
(one jack, other empty)** for the hunt — an omni pollutes the RSSI bearing. Every
script prints its recommended antenna as its first line.

---

## What we're looking for (the origin case)

Derived from the PEEKREMOTE capture of 2026-08-24 11:32 UTC (100 frames):

| Property | Value |
|---|---|
| Channel | **64** (5320 MHz, 5 GHz, DFS) |
| PHY rate | 12 Mbps OFDM |
| Source MAC | `fe:ff:ff:ff:ff:ff` — broadcast with the I/G bit cleared |
| Destination | equals BSSID — deauth aimed *at* the AP, spoofing a client |
| Reason code | 7, on all 100 frames |
| Rate | ~12 frames/sec, sustained |
| Targets | 3 physical APs (`02:00:5e:00:01:8x`, `02:00:5e:00:02:ax`, `02:00:5e:00:03:8x`) |
| Signal at sensor | −66.4 dBm mean, **σ 1.25 dB** |

Two conclusions the capture supports directly:

**One transmitter.** Sequence numbers run 1670 → 1772 strictly increasing with only
3 gaps, while rotating across 8 BSSIDs. A single 802.11 sequence counter spanning
multiple spoofed targets can only come from one radio.

**It is stationary.** σ of 1.25 dB over 8.5 seconds. A device being carried swings
10–20 dB. This is mounted, plugged in, or sitting on a shelf — it will still be
there when you arrive.

It is *not* Cisco rogue containment: containment spoofs a rogue's BSSID to deauth
its clients, whereas this spoofs a fake client to attack your own infrastructure.

In `sniffer.py` this attacker shows up in **DEAUTH FLOODS** on channel 64 with
source `fe:ff:ff:ff:ff:ff`; hit ENTER on it (or on the `ALL deauths on ch 64` row)
to direction-find it.

## Receive-only, and provably so

Nothing in this toolkit transmits. It does not inject, deauthenticate, probe,
associate or scan. That is enforced at four levels rather than promised:

**No transmit-capable code exists.** The only external commands are `tshark`
(a libpcap capture handle, which has no TX path), `iw` for read-only queries and
mode/channel setup, and `ip link`. No `aireplay-ng`, `mdk4`, `tcpreplay`, scapy,
or raw sockets appear anywhere.

**Monitor mode is set before the interface comes up.** Bringing a *managed*
interface up invites the supplicant to start active scanning, and active scanning
transmits probe requests. `init-hunt.sh` orders the operations so that window
never opens, and it refuses to continue if NetworkManager, `wpa_supplicant` or
`iwd` is bound to the interface.

**Transmit power is switched off** after monitor mode is established, falling
back to a 0 mBm floor if the driver rejects `off`.

**The transmit counter is checked.** `init-hunt.sh` baselines
`/sys/class/net/<if>/statistics/tx_packets`, runs its verification capture, and
aborts if the counter moved. Every live tool (`sniffer.py`, `router_hunt.py`,
`deauth_hunt.py`, `deauth_sweep.py`) then watches the same counter for the whole
session and shows a running `TX-GUARD 0 packets transmitted` line, turning it into
a warning the instant it changes.

`rfkill` is scoped to this phy alone — never a global `rfkill unblock wifi`,
which would re-enable every radio on the machine.

Note that channel *hopping* (used by `sniffer.py` and `deauth_sweep.py`) only
retunes the receiver with `iw`; retuning is not transmitting.

## The tools

| File | Purpose |
|---|---|
| `sniffer.py` | **All-in-one DF:** networks (collapsed to one row per device) / deauth floods / probe clients / a specific MAC → shared RSSI hunt. Vendor + device + pwnagotchi/deauther badges + PHY class, and adaptive channel hopping |
| `device_id.py` | Passive device identification: OUI→vendor, randomized-MAC flag, WPS/role device guess, pwnagotchi/deauther badge, PHY-capability fingerprint (standalone, unit-tested) |
| `deauth_sweep.py` | Sweep every 2.4/5 GHz channel and report **which channel** a deauth flood is on, so you know where to hunt |
| `router_hunt.py` | Discover networks and direction-find one (the discovery + hunt engine `sniffer.py` builds on; usable standalone). Also holds the adaptive-hopping scheduler |
| `deauth_hunt.py` | Single-channel RSSI meter with **waypoint recorder, SQLite log, and web dashboard** — for logged, methodical building sweeps once you know the channel |
| `init-hunt.sh` | Card setup: regdomain, monitor mode, channel, chain constraint, capture verification |
| `hunt.db` | SQLite: every sample plus your marked waypoints (written by `deauth_hunt.py`) |
| `old_scripts/antenna-check.sh` | Pre-hunt antenna test: live signal swing, per-chain RSSI probe (receive-only) |
| `old_scripts/make_test_capture.py` | Synthesises a pcap with the exact signature, for off-site validation |

`sniffer.py` imports the capture, hopping, hunt, audio and colour code from
`router_hunt.py` / `deauth_hunt.py` / `deauth_sweep.py`, and the vendor/device
identification from `device_id.py`, so those five `.py` files must stay together
in this folder. The pure logic (identification, threat/PHY classification,
multi-BSSID collapse, adaptive-hop scheduling) is unit-tested — run **`pytest`**
(`test_device_id.py`, `test_sniffer.py`, `test_hopper.py`).

### Which tool when

- **Don't know the channel, or want the one screen for everything** → `sniffer.py`.
- **Just want to know which channel the flood is on** → `sudo ./deauth_sweep.py`.
- **Know the channel and want a logged, floor-by-floor sweep with waypoints and a
  web view** → `deauth_hunt.py` (below).

## `deauth_hunt.py` — logged single-channel hunt

For a methodical building sweep on a known channel. It adds the same audio and
gradient bars as `sniffer.py`, plus waypoint recording, a SQLite log, and a web
dashboard at <http://127.0.0.1:8777> while it runs.

```bash
sudo ./init-hunt.sh          # regdomain GB, monitor mode, channel 64, verify
./deauth_hunt.py             # no sudo needed — capture only, you're in the wireshark group
```

| Key | Action |
|---|---|
| `m` | Mark a waypoint — prompts for label and heading |
| `f` | Set the current floor |
| `r` | Reset peak hold (do this at the start of every antenna sweep) |
| `c` | Clear the rolling window |
| `p` | Pause/resume per-sample logging |
| `b` | Toggle the beeps |
| `q` | Quit |

Audio flags (`--geiger`, `--no-beep`, `--test-beep`) work here too.

### Validating off-site

No attack traffic needed — replay the synthetic capture:

```bash
old_scripts/make_test_capture.py --noise 5   # 726 deauths + 300 decoy beacons
./deauth_hunt.py --replay test.pcap          # meter tracks a simulated approach
```

The RSSI profile ramps −78 → −45 → −78, simulating walking toward the emitter
and past it. Decoy beacons verify the display filter rejects unrelated traffic.

### Useful queries

```sql
-- Best reading per floor
SELECT floor, MAX(rssi_max) best, COUNT(*) n FROM waypoint GROUP BY floor ORDER BY best DESC;

-- Signal over time on one floor (spot when it moved or stopped)
SELECT datetime(ts,'unixepoch'), rssi FROM sample WHERE floor='2' ORDER BY ts;

-- Which APs it targeted, and how often
SELECT da, COUNT(*) FROM sample GROUP BY da ORDER BY 2 DESC;
```

## Field procedure

**Before you go.** Get the physical locations of the targeted APs from the
controller, plus their per-AP RSSI from the AWIPS alarm. The emitter sits inside
their mutual coverage — that usually means one floor and one wing. Start there.

**Antenna.** The AWUS036AXML is 2×2. `init-hunt.sh` tries to constrain the radio
to one RX chain; mt7921 usually refuses. If it does, **physically remove the second
antenna** — otherwise the omni pollutes RSSI and your bearings go mushy. (Scan with
an omni, then swap to the directional for the hunt.)

Run `sudo old_scripts/antenna-check.sh` to confirm the directional works. It streams
the strongest nearby AP's signal while you rotate the antenna: a working directional
swings 15–25 dB between pointed at the source and pointed away; an omni, or a
directional on a dead port, barely moves. It also reports whether the driver exposes
per-chain RSSI — if it reports a single combined value (typical for mt7921), the port
you plug into is irrelevant, so connect the directional to either jack and leave the
other empty.

**Sweeping.** At each point: press `r`, rotate the antenna slowly through 360°,
watch peak hold, then record with the bearing that produced the peak. Signal is a
coarse distance proxy; the *bearing at peak* is what you triangulate on. The
warmer/colder beeps let you do this without staring at the screen.

**Reading the numbers.** 5 GHz attenuates hard through floors and walls, which
works in your favour — the falloff is steep. Watch σ as well as the mean: rising σ
usually means multipath, so step a metre and re-measure rather than trusting it.

## Restore the card

```bash
sudo ip link set wlan1 down && sudo iw dev wlan1 set type managed && sudo ip link set wlan1 up
```

## The fix, independent of the hunt

These frames claim to come from an unassociated station. With **PMF / 802.11w**
enabled on the affected SSIDs, the APs ignore them outright and the disruption
stops — whether or not the device is ever found. That change needs whoever owns
the Cisco controller, so it's worth starting in parallel with the search.
