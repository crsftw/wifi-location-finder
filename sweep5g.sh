#!/usr/bin/env bash
# sweep5g.sh — passive 5 GHz channel sweep, one pcapng per channel, per floor.
#
# RECEIVE-ONLY. The only things this script does to the radio are
#   `iw dev <iface> set channel N`  (retunes the receiver; no transmission)
#   `dumpcap -i <iface> -w ...`      (captures; no transmission)
# It never scans, never associates, never injects.
#
# Output:  $PCAP_ROOT/floor<N>/floor_<N>_channel_<CH>.pcapng
#
# Overridable via environment:
#   IFACE=wlan1      monitor-mode interface
#   DWELL=60         seconds per channel
#   PCAP_ROOT=./pcaps
#   CHANNELS="36 40 ..."  space-separated list, to sweep a subset
#   FLOOR=6          skip the interactive prompt
#
# Example quick test:  DWELL=5 CHANNELS="36 44" FLOOR=0 ./sweep5g.sh

set -u

IFACE="${IFACE:-wlan1}"
DWELL="${DWELL:-60}"
PCAP_ROOT="${PCAP_ROOT:-./pcaps}"

# Every 20 MHz channel number the 802.11 standard defines in the 5 GHz band,
# deliberately including ones outside the usual UK allocation (68, 96, 144,
# 169-177). Anything the adapter's regulatory domain refuses is reported at
# the end rather than silently skipped.
DEFAULT_CHANNELS="36 40 44 48 52 56 60 64 68 96 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161 165 169 173 177"
read -r -a CHANNELS <<< "${CHANNELS:-$DEFAULT_CHANNELS}"

# ---------------------------------------------------------------- helpers
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }

# iw needs CAP_NET_ADMIN; dumpcap usually has its own capabilities, so only
# escalate for iw. -n: never block on a password prompt mid-sweep.
if [ "$(id -u)" -eq 0 ]; then IW=(iw); else IW=(sudo -n iw); fi
KEEPALIVE=""

CHILD=""
cleanup() {
    if [ -n "$CHILD" ] && kill -0 "$CHILD" 2>/dev/null; then
        kill -INT "$CHILD" 2>/dev/null
        wait "$CHILD" 2>/dev/null
    fi
    [ -n "${KEEPALIVE:-}" ] && kill "$KEEPALIVE" 2>/dev/null
    return 0
}
trap 'info ""; info "interrupted — files captured so far are kept (last channel file is partial)"; cleanup; summary; exit 130' INT TERM

# ---------------------------------------------------------------- checks
command -v iw      >/dev/null || die "iw not found"
command -v dumpcap >/dev/null || die "dumpcap not found (install wireshark-common)"

iw dev "$IFACE" info >/dev/null 2>&1 || die "interface '$IFACE' not found — is the adapter plugged in?"
MODE=$(iw dev "$IFACE" info | awk '/type/ {print $2}')
[ "$MODE" = "monitor" ] || die "'$IFACE' is in '$MODE' mode, not monitor. Put it in monitor mode first:
    sudo ip link set $IFACE down
    sudo iw dev $IFACE set type monitor
    sudo ip link set $IFACE up"

if [ "$(id -u)" -ne 0 ]; then
    if ! sudo -n true 2>/dev/null; then
        # password needed: ask once now, then keep the timestamp fresh for the
        # whole sweep so it can't expire and stall a channel change.
        sudo -v || die "sudo is required to retune the interface (iw set channel)"
        ( while :; do sudo -n -v 2>/dev/null; sleep 60; done ) &
        KEEPALIVE=$!
    fi
fi

# ---------------------------------------------------------------- floor
if [ -z "${FLOOR:-}" ]; then
    while :; do
        read -r -p "Which floor are you on? (integer): " FLOOR
        [[ "$FLOOR" =~ ^-?[0-9]+$ ]] && break
        info "  please enter a whole number"
    done
fi
[[ "$FLOOR" =~ ^-?[0-9]+$ ]] || die "FLOOR must be an integer, got '$FLOOR'"

OUTDIR="$PCAP_ROOT/floor$FLOOR"
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

# ---------------------------------------------------------------- summary
summary() {
    info ""
    info "================ summary: floor $FLOOR  ($(( ($(date +%s) - START) / 60 )) min) ================"
    printf '%-6s %-9s %-10s %-10s %s\n' "ch" "packets" "beacons" "spoofed" "size"
    printf '%-6s %-9s %-10s %-10s %s\n' "" "" "" "deauths*" ""
    for CH in "${DONE[@]}"; do
        FILE="$OUTDIR/floor_${FLOOR}_channel_${CH}.pcapng"
        [ -s "$FILE" ] || continue
        PK=$(capinfos -c -M "$FILE" 2>/dev/null | awk '/Number of packets/ {print $NF}')
        SZ=$(du -h "$FILE" | cut -f1)
        if command -v tshark >/dev/null; then
            BC=$(tshark -r "$FILE" -Y "wlan.fc.type_subtype==8" 2>/dev/null | wc -l)
            DA=$(tshark -r "$FILE" -Y "wlan.fc.type_subtype==12 && wlan.ta==ff:ff:ff:ff:ff:ff" 2>/dev/null | wc -l)
        else
            BC="-"; DA="-"
        fi
        printf '%-6s %-9s %-10s %-10s %s\n' "$CH" "${PK:-?}" "$BC" "$DA" "$SZ"
    done
    info "* deauth frames with source ff:ff:ff:ff:ff:ff — the containment signature"
    if [ "${#REFUSED[@]}" -gt 0 ]; then
        info ""
        info "channels refused by the adapter: ${REFUSED[*]}"
        info "  (outside the current regulatory domain: 'iw reg get'. Nothing was captured there.)"
    fi
    info ""
    info "files in $OUTDIR"
}

# ---------------------------------------------------------------- sweep
declare -a DONE=() REFUSED=()
TOTAL=${#CHANNELS[@]}
START=$(date +%s)

info ""
info "interface : $IFACE (monitor)"
info "floor     : $FLOOR   ->  $OUTDIR"
info "channels  : $TOTAL   dwell: ${DWELL}s each   (~$(( TOTAL * DWELL / 60 )) min total)"
info "regdomain : $(iw reg get 2>/dev/null | awk '/^country/ {sub(/:$/,"",$2); print $2; exit}')"
info ""

i=0
for CH in "${CHANNELS[@]}"; do
    i=$((i+1))
    FILE="$OUTDIR/floor_${FLOOR}_channel_${CH}.pcapng"

    if ! "${IW[@]}" dev "$IFACE" set channel "$CH" 2>/dev/null; then
        printf '[%2d/%2d] ch %-3s  refused by adapter/regdomain — skipped\n' "$i" "$TOTAL" "$CH"
        REFUSED+=("$CH")
        continue
    fi
    # confirm the retune actually took
    ACTUAL=$(iw dev "$IFACE" info | awk '/channel/ {print $2; exit}')
    if [ "$ACTUAL" != "$CH" ]; then
        printf '[%2d/%2d] ch %-3s  retune did not take (adapter reports ch %s) — skipped\n' "$i" "$TOTAL" "$CH" "$ACTUAL"
        REFUSED+=("$CH")
        continue
    fi

    printf '[%2d/%2d] ch %-3s  capturing %ss -> %s\n' "$i" "$TOTAL" "$CH" "$DWELL" "$(basename "$FILE")"
    dumpcap -i "$IFACE" -a "duration:$DWELL" -w "$FILE" -q >/dev/null 2>&1 &
    CHILD=$!
    wait "$CHILD"
    CHILD=""
    DONE+=("$CH")
done

summary
cleanup
exit 0
