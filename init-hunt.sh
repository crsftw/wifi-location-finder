#!/usr/bin/env bash
# init-hunt.sh - prepare an Alfa AWUS036AXML (mt7921u) for deauth direction finding.
#
# Puts the card into monitor mode on the attack channel, sets the regulatory
# domain, tries to constrain the radio to a single RX chain (so a directional
# antenna gives a clean bearing), then verifies it can actually hear traffic.
#
# RECEIVE-ONLY. Nothing here transmits: no injection, no deauth, no probe
# requests, no association. Monitor mode neither scans nor beacons nor ACKs,
# transmit power is switched off, and the interface's tx_packets counter is
# checked before and after the verification capture to prove it.
#
# Deliberately does NOT run `airmon-ng check kill` - that would tear down the
# host's own wifi connection. Only the target interface is touched.

set -euo pipefail

echo "ANTENNA: use 1 directional antenna (one jack, leave the other empty) - this prepares the card for the RSSI direction-finding hunt; it constrains the radio to a single RX chain, so a second/omni antenna pollutes the bearing."

CHANNEL="${HUNT_CHANNEL:-64}"
FREQ="${HUNT_FREQ:-5320}"
REGDOM="${HUNT_REG:-GB}"
DRIVER="${HUNT_DRIVER:-mt7921u}"
IFACE="${HUNT_IFACE:-}"
PROBE_WAIT="${HUNT_PROBE_WAIT:-75}"
USB_VENDOR="${HUNT_USB_VENDOR:-0e8d}"
RELEASE_BT="${HUNT_RELEASE_BT:-1}"
VERIFY_SECS="${HUNT_VERIFY_SECS:-6}"
SINGLE_CHAIN="${HUNT_SINGLE_CHAIN:-1}"

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; CYN=$'\e[36m'; DIM=$'\e[2m'; RST=$'\e[0m'; BLD=$'\e[1m'
ok()   { printf '  %s+%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YLW" "$RST" "$*"; }
err()  { printf '  %sx%s %s\n' "$RED" "$RST" "$*" >&2; }
step() { printf '\n%s==>%s %s%s%s\n' "$CYN" "$RST" "$BLD" "$*" "$RST"; }

trap 'err "failed at line $LINENO"' ERR

[[ $EUID -eq 0 ]] || { err "must run as root:  sudo $0 $*"; exit 1; }

# ---------------------------------------------------------------- interface
step "Locating the capture interface"

find_iface() {
    local cand n
    for cand in /sys/class/net/*; do
        n=$(basename "$cand")
        [[ -e "$cand/device/driver" ]] || continue
        if [[ "$(basename "$(readlink -f "$cand/device/driver")")" == "$DRIVER" ]]; then
            printf '%s' "$n"; return 0
        fi
    done
    return 1
}

usb_present() { lsusb 2>/dev/null | grep -qiE "ID ${USB_VENDOR}:"; }

[[ -n "$IFACE" ]] || IFACE=$(find_iface || true)

# The mt7921u takes 30-40 seconds to load firmware and register a netdev after
# plug-in. Running the script inside that window looks exactly like "not plugged
# in", so wait it out rather than telling the operator something untrue.
if [[ -z "$IFACE" ]] && usb_present; then
    warn "adapter is on the USB bus but has not registered an interface yet"
    warn "mt7921u firmware load normally takes 30-40s - waiting up to ${PROBE_WAIT}s"
    for (( i = 1; i <= PROBE_WAIT; i++ )); do
        sleep 1
        IFACE=$(find_iface || true)
        if [[ -n "$IFACE" ]]; then
            printf '\r%*s\r' 44 ""
            ok "bound after ${i}s"
            break
        fi
        printf '\r    waiting for driver probe... %ds ' "$i"
    done
    [[ -n "$IFACE" ]] || printf '\r%*s\r' 44 ""
fi

if [[ -z "$IFACE" ]]; then
    if usb_present; then
        err "adapter is on the USB bus but the driver never bound (waited ${PROBE_WAIT}s)"
        err "Recent kernel messages:"
        dmesg 2>/dev/null | grep -iE "mt7921u|mt76|usb 1-" | tail -6 | sed 's/^/        /' >&2
        printf '\n' >&2
        err "A probe failure with 'error -5' is a known mt7921u quirk. In order:"
        err "  1. Unplug, wait 5s, plug back in, then re-run this script"
        err "  2. Move it to a USB 3 (blue) port - probe is far more reliable there"
        err "  3. sudo modprobe -r mt7921u && sudo modprobe mt7921u"
    else
        err "no MediaTek device on the USB bus and no interface using '$DRIVER'"
        err "The adapter is not plugged in, or the port is dead. Check with: lsusb"
    fi
    exit 1
fi
[[ -e "/sys/class/net/$IFACE" ]] || { err "interface '$IFACE' does not exist"; exit 1; }
ok "interface ${BLD}${IFACE}${RST} (driver $DRIVER)"

# Refuse to hijack the interface carrying the default route.
DEFAULT_IF=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}' || true)
if [[ "$IFACE" == "$DEFAULT_IF" ]]; then
    err "$IFACE carries the default route - refusing to put it in monitor mode"
    exit 1
fi

PHY=$(basename "$(readlink -f "/sys/class/net/$IFACE/phy80211")")
ok "phy ${BLD}${PHY}${RST}"

# USB link speed - monitor capture is fine on USB2 but worth flagging.
USBSPEED=$(cat "$(readlink -f "/sys/class/net/$IFACE/device")/../speed" 2>/dev/null || echo "")
if [[ -n "$USBSPEED" ]]; then
    if (( ${USBSPEED%%.*} < 5000 )); then
        warn "adapter on a ${USBSPEED} Mbps USB port - move it to a USB 3 (blue) port for headroom"
    else
        ok "USB link ${USBSPEED} Mbps"
    fi
fi

# ------------------------------------------------------------- interference
step "Checking for processes that fight over the interface"
CONFLICT=0
for svc in NetworkManager wpa_supplicant iwd; do
    if pgrep -x "$svc" >/dev/null 2>&1; then
        case "$svc" in
            NetworkManager)
                if command -v nmcli >/dev/null 2>&1; then
                    nmcli device set "$IFACE" managed no >/dev/null 2>&1 \
                        && ok "told NetworkManager to leave $IFACE alone" \
                        || warn "could not set $IFACE unmanaged in NetworkManager"
                else
                    err "NetworkManager is running but nmcli is missing, so $IFACE"
                    err "cannot be marked unmanaged. NM may retake the interface and"
                    err "start scanning, which transmits. Refusing to continue."
                    err "Fix: add to /etc/NetworkManager/conf.d/unmanaged.conf"
                    err "    [keyfile]"
                    err "    unmanaged-devices=interface-name:$IFACE"
                    exit 1
                fi ;;
            *)
                if pgrep -af "$svc" 2>/dev/null | grep -q -- "$IFACE"; then
                    err "$svc is bound to $IFACE"
                    err "It would try to associate or scan, and scanning TRANSMITS"
                    err "probe requests. Stop it for this interface, then re-run:"
                    err "    sudo pkill -f '$svc.*$IFACE'"
                    exit 1
                else
                    ok "$svc running but not on $IFACE"
                fi ;;
        esac
    fi
done
(( CONFLICT == 0 )) && ok "no blocking conflicts"

# ------------------------------------------------------- combo-chip bluetooth
# The MT7921 is a WiFi+BT combo. Its Bluetooth functions share the same USB
# device, and btmtk's firmware setup can take 35+ seconds and time out, which
# drags the WiFi side down with it ("RTNETLINK answers: Connection timed out"
# on `ip link set up`). We only ever want the WiFi function, so release the rest.
# The laptop's own internal Bluetooth is on a different USB device and is
# untouched.
if [[ "$RELEASE_BT" == "1" ]]; then
    step "Releasing the Bluetooth function of the combo chip"
    USBIF=$(basename "$(readlink -f "/sys/class/net/$IFACE/device")" 2>/dev/null || echo "")
    USBDEV="${USBIF%%:*}"
    RELEASED=0
    if [[ -n "$USBDEV" && -d /sys/bus/usb/drivers/btusb ]]; then
        for d in /sys/bus/usb/devices/"$USBDEV":*; do
            [[ -e "$d" ]] || continue
            n=$(basename "$d")
            [[ "$n" == "$USBIF" ]] && continue
            drv=$(basename "$(readlink -f "$d/driver" 2>/dev/null)" 2>/dev/null || echo "")
            [[ "$drv" == "btusb" ]] || continue
            if printf '%s' "$n" > /sys/bus/usb/drivers/btusb/unbind 2>/dev/null; then
                ok "released $n from btusb"
                RELEASED=$((RELEASED + 1))
            else
                warn "could not release $n from btusb"
            fi
        done
    fi
    if (( RELEASED > 0 )); then
        ok "$RELEASED Bluetooth function(s) released - WiFi now has the device to itself"
        printf '    %sthe laptop internal Bluetooth is a separate device, unaffected%s\n' "$DIM" "$RST"
        sleep 1
    else
        ok "no Bluetooth functions bound to this adapter"
    fi
fi

# ------------------------------------------------------------------ regdom
step "Setting regulatory domain to $REGDOM"
CUR=$(iw reg get 2>/dev/null | awk '/^country/{print $2; exit}' | tr -d ':')
if [[ "$CUR" == "$REGDOM" ]]; then
    ok "already $REGDOM"
else
    iw reg set "$REGDOM"
    sleep 1
    NEW=$(iw reg get 2>/dev/null | awk '/^country/{print $2; exit}' | tr -d ':')
    if [[ "$NEW" == "$REGDOM" ]]; then
        ok "$CUR -> $REGDOM"
    else
        warn "requested $REGDOM but kernel reports $NEW (a driver may pin the domain)"
    fi
fi

# ------------------------------------------------------------- monitor mode
step "Switching $IFACE to monitor mode"
# Unblock ONLY this phy. A global `rfkill unblock wifi` would re-enable every
# radio on the machine, which is not ours to decide.
for rk in /sys/class/ieee80211/"$PHY"/rfkill*; do
    [[ -e "$rk/soft" ]] || continue
    if [[ "$(cat "$rk/soft" 2>/dev/null)" == "1" ]]; then
        rfkill unblock "$(basename "$rk" | tr -dc '0-9')" 2>/dev/null \
            && ok "soft-unblocked $PHY only" || true
    fi
done

# Monitor mode is set BEFORE the interface comes up. Bringing a managed-mode
# interface up invites the supplicant to start active scanning, and active
# scanning transmits probe requests.
ip link set "$IFACE" down 2>/dev/null || true
sleep 0.5
if iw dev "$IFACE" set type monitor 2>/dev/null; then
    ok "type set to monitor"
else
    CURTYPE=$(iw dev "$IFACE" info 2>/dev/null | awk '/^\ttype/{print $2}')
    [[ "$CURTYPE" == "monitor" ]] || { err "could not set monitor mode (type is '$CURTYPE')"; exit 1; }
    ok "already in monitor mode"
fi

# Bringing the interface up drives a firmware command that this chip sometimes
# times out on, particularly over USB 2. Retry rather than dying on the first go.
UP_OK=0
for attempt in 1 2 3 4; do
    if ip link set "$IFACE" up 2>/dev/null; then UP_OK=1; break; fi
    warn "interface refused to come up (attempt ${attempt}/4) - retrying"
    ip link set "$IFACE" down 2>/dev/null || true
    sleep 3
done

if (( UP_OK == 0 )); then
    err "could not bring $IFACE up - the driver timed out talking to firmware"
    err ""
    err "Recent kernel messages:"
    dmesg 2>/dev/null | grep -iE "mt7921|mt76|Bluetooth: hci|usb ${USBDEV:-1-}" | tail -8 | sed 's/^/        /' >&2
    err ""
    err "In order of effectiveness:"
    err "  1. Move the adapter to a USB 3 (blue) port - this chip is unstable on USB 2"
    err "  2. Unplug, wait 10s, replug, wait for the driver to bind, re-run"
    err "  3. sudo modprobe -r mt7921u mt7921_common mt792x_usb && sudo modprobe mt7921u"
    exit 1
fi

MODE=$(iw dev "$IFACE" info 2>/dev/null | awk '/^\ttype/{print $2}')
[[ "$MODE" == "monitor" ]] || { err "interface type is '$MODE', expected 'monitor'"; exit 1; }
ok "monitor mode active and interface up"

# ----------------------------------------------------------------- channel
step "Tuning to channel $CHANNEL (${FREQ} MHz)"
if iw dev "$IFACE" set channel "$CHANNEL" 2>/dev/null; then
    ok "set channel $CHANNEL"
elif iw dev "$IFACE" set freq "$FREQ" 2>/dev/null; then
    ok "set freq ${FREQ} MHz (channel form was rejected)"
else
    err "could not tune to channel $CHANNEL / ${FREQ} MHz"
    err "check that $REGDOM permits it:  iw phy $PHY info | grep -A2 '${FREQ}'"
    exit 1
fi
ACTUAL=$(iw dev "$IFACE" info 2>/dev/null | awk '/channel/{print $0}' | sed 's/^\s*//')
[[ -n "$ACTUAL" ]] && ok "radio reports: $ACTUAL"

CHINFO=$(iw phy "$PHY" info 2>/dev/null | grep -E "^\s+\* ${FREQ}\.0 MHz" || true)
if [[ "$CHINFO" == *"disabled"* ]]; then
    err "channel $CHANNEL is DISABLED under $REGDOM - cannot receive on it"
    exit 1
elif [[ "$CHINFO" == *"radar detection"* ]]; then
    ok "channel $CHANNEL is DFS - receive-only is fine, we never transmit"
fi

# ------------------------------------------------------- transmit lockdown
step "Disabling transmit"
TXPOWER_OFF=0
if iw dev "$IFACE" set txpower off 2>/dev/null; then
    TXPOWER_OFF=1; ok "txpower off (interface)"
elif iw phy "$PHY" set txpower off 2>/dev/null; then
    TXPOWER_OFF=1; ok "txpower off (phy)"
elif iw dev "$IFACE" set txpower fixed 0 2>/dev/null; then
    ok "txpower floored to 0 mBm (driver would not accept 'off')"
else
    warn "driver accepted no txpower setting"
fi
printf '    %smonitor mode does not associate, scan, beacon or ACK - nothing in\n' "$DIM"
printf '    this toolkit has a transmit path. txpower is belt-and-braces.%s\n' "$RST"

TX_BASELINE=$(cat "/sys/class/net/$IFACE/statistics/tx_packets" 2>/dev/null || echo 0)
ok "TX counter baseline: $TX_BASELINE packets"

# ------------------------------------------------------------ antenna chain
if [[ "$SINGLE_CHAIN" == "1" ]]; then
    step "Constraining radio to a single RX chain"
    AVAIL=$(iw phy "$PHY" info 2>/dev/null | awk '/Available Antennas/{print $3, $5}')
    if iw phy "$PHY" set antenna 1 1 2>/dev/null; then
        ok "restricted to chain 0 - RSSI now reflects one antenna port only"
    else
        warn "driver rejected chain selection (normal for mt7921)"
        warn "${BLD}physically remove the second antenna${RST} - otherwise the omni"
        warn "pollutes RSSI and your directional bearings go mushy"
    fi
    [[ -n "$AVAIL" ]] && printf '    %savailable antennas: %s%s\n' "$DIM" "$AVAIL" "$RST"
fi

# ------------------------------------------------------------------ verify
step "Verifying capture (${VERIFY_SECS}s)"
TMPCAP=$(mktemp /tmp/hunt-verify.XXXXXX.pcap)
cleanup_cap() { rm -f "$TMPCAP"; }
trap cleanup_cap EXIT

timeout $((VERIFY_SECS + 4)) dumpcap -i "$IFACE" -a duration:"$VERIFY_SECS" -w "$TMPCAP" -q >/dev/null 2>&1 || true

if [[ ! -s "$TMPCAP" ]]; then
    err "captured nothing at all - the interface is up but deaf"
    exit 1
fi

TOTAL=$(tshark -r "$TMPCAP" 2>/dev/null | wc -l || echo 0)
DEAUTH=$(tshark -r "$TMPCAP" -Y 'wlan.fc.type_subtype==12' 2>/dev/null | wc -l || echo 0)
SIGNATURE=$(tshark -r "$TMPCAP" -Y 'wlan.fc.type_subtype==12 && wlan.sa==fe:ff:ff:ff:ff:ff' 2>/dev/null | wc -l || echo 0)
HASRSSI=$(tshark -r "$TMPCAP" -T fields -e radiotap.dbm_antsignal 2>/dev/null | grep -c . || echo 0)

printf '    frames captured       : %s\n' "$TOTAL"
printf '    with radiotap RSSI    : %s\n' "$HASRSSI"
printf '    deauth frames         : %s\n' "$DEAUTH"
printf '    %smatching attack sig%s   : %s\n' "$BLD" "$RST" "$SIGNATURE"

if (( TOTAL == 0 )); then
    err "no frames - wrong channel, or nothing on air here"
elif (( HASRSSI == 0 )); then
    err "frames arrive but carry no signal strength - direction finding will not work"
    exit 1
else
    ok "radiotap RSSI present - direction finding will work"
fi

if (( SIGNATURE > 0 )); then
    printf '\n  %s*** ATTACK TRAFFIC DETECTED ON THIS CHANNEL ***%s\n' "$GRN$BLD" "$RST"
    tshark -r "$TMPCAP" -Y 'wlan.fc.type_subtype==12 && wlan.sa==fe:ff:ff:ff:ff:ff' \
        -T fields -e radiotap.dbm_antsignal -e wlan.da -e wlan.seq 2>/dev/null | head -5 | sed 's/^/      /'
elif (( DEAUTH > 0 )); then
    warn "deauths present but none match fe:ff:ff:ff:ff:ff - different source?"
else
    printf '\n  %snote:%s no attack traffic here - expected if you are off-site.\n' "$DIM" "$RST"
fi

# ------------------------------------------------- prove we transmitted nothing
step "Confirming the interface transmitted nothing"
TX_NOW=$(cat "/sys/class/net/$IFACE/statistics/tx_packets" 2>/dev/null || echo 0)
TX_DELTA=$(( TX_NOW - TX_BASELINE ))
MODE_NOW=$(iw dev "$IFACE" info 2>/dev/null | awk '/^\ttype/{print $2}')
printf '    interface mode        : %s\n' "$MODE_NOW"
printf '    tx_packets before     : %s\n' "$TX_BASELINE"
printf '    tx_packets after      : %s\n' "$TX_NOW"
if [[ "$MODE_NOW" != "monitor" ]]; then
    err "interface is '$MODE_NOW', not monitor - aborting"
    exit 1
fi
if (( TX_DELTA > 0 )); then
    err "interface transmitted $TX_DELTA packets during a receive-only capture"
    err "Something else is driving this radio. Investigate before continuing."
    exit 1
fi
ok "${BLD}0 packets transmitted${RST} - capture is verifiably passive"

# ------------------------------------------------------------------- ready
cat <<EOF

${GRN}${BLD}Ready.${RST}
  interface : ${BLD}${IFACE}${RST}   channel ${BLD}${CHANNEL}${RST} (${FREQ} MHz)   regdom ${BLD}${REGDOM}${RST}

Start the hunt (no sudo needed - you are in the 'wireshark' group):

  ${CYN}./deauth_hunt.py --iface ${IFACE}${RST}

Restore the card to normal wifi afterwards:

  ${DIM}sudo ip link set ${IFACE} down && sudo iw dev ${IFACE} set type managed && sudo ip link set ${IFACE} up${RST}
EOF
