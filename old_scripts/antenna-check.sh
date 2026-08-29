#!/usr/bin/env bash
# antenna-check.sh - verify a directional antenna is connected and working.
#
# Finds the strongest nearby AP and streams its signal strength live, so you can
# rotate the antenna and watch the number move. A working directional swings
# 15-25 dB between pointing at a source and pointing away. An omni barely moves.
#
# Also reports whether the driver exposes per-chain RSSI, which decides whether
# antenna port identity matters at all.
#
# RECEIVE-ONLY: passive capture, no injection, no probing. TX counter verified.

set -euo pipefail

echo "ANTENNA: use 1 directional antenna - this script verifies a directional is connected and working by making its RSSI swing as you rotate it; an omni barely moves and would fail the check."

IFACE="${HUNT_IFACE:-}"
DRIVER="${HUNT_DRIVER:-mt7921u}"
CHANNEL="${1:-}"
DWELL="${HUNT_DWELL:-2}"
SCAN_CHANNELS="${HUNT_SCAN_CHANNELS:-36 40 44 48 149 157 1 6 11}"

RED=$'\e[31m'; GRN=$'\e[32m'; YLW=$'\e[33m'; CYN=$'\e[36m'; DIM=$'\e[2m'; RST=$'\e[0m'; BLD=$'\e[1m'
ok(){ printf '  %s+%s %s\n' "$GRN" "$RST" "$*"; }
warn(){ printf '  %s!%s %s\n' "$YLW" "$RST" "$*"; }
err(){ printf '  %sx%s %s\n' "$RED" "$RST" "$*" >&2; }
step(){ printf '\n%s==>%s %s%s%s\n' "$CYN" "$RST" "$BLD" "$*" "$RST"; }

[[ $EUID -eq 0 ]] || { err "must run as root (needs to change channel): sudo $0 $*"; exit 1; }

if [[ -z "$IFACE" ]]; then
    for c in /sys/class/net/*; do
        [[ -e "$c/device/driver" ]] || continue
        [[ "$(basename "$(readlink -f "$c/device/driver")")" == "$DRIVER" ]] && { IFACE=$(basename "$c"); break; }
    done
fi
[[ -n "$IFACE" ]] || { err "no $DRIVER interface. Run init-hunt.sh first."; exit 1; }
[[ "$(iw dev "$IFACE" info | awk '/^\ttype/{print $2}')" == "monitor" ]] \
    || { err "$IFACE is not in monitor mode. Run: sudo ./init-hunt.sh"; exit 1; }

TX0=$(cat "/sys/class/net/$IFACE/statistics/tx_packets" 2>/dev/null || echo 0)
TMP=$(mktemp -d /tmp/antcheck.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

# ------------------------------------------------------------ find traffic
if [[ -z "$CHANNEL" ]]; then
    step "Finding a channel with traffic (${DWELL}s each)"
    BEST=0; CHANNEL=""
    for ch in $SCAN_CHANNELS; do
        iw dev "$IFACE" set channel "$ch" 2>/dev/null || continue
        timeout $((DWELL + 3)) dumpcap -i "$IFACE" -a duration:"$DWELL" -w "$TMP/s.pcap" -q >/dev/null 2>&1 || true
        n=$(tshark -r "$TMP/s.pcap" -Y 'wlan.fc.type_subtype==8' 2>/dev/null | wc -l || echo 0)
        printf '    ch %-4s %4s beacons\n' "$ch" "$n"
        (( n > BEST )) && { BEST=$n; CHANNEL=$ch; }
    done
    [[ -n "$CHANNEL" ]] || { err "no beacons on any scanned channel - is the antenna connected at all?"; exit 1; }
    ok "using channel $CHANNEL ($BEST beacons)"
else
    iw dev "$IFACE" set channel "$CHANNEL" 2>/dev/null \
        || { err "could not tune to channel $CHANNEL"; exit 1; }
    ok "channel $CHANNEL"
fi

# --------------------------------------------------- per-chain reporting?
step "Checking whether the driver reports per-chain RSSI"
timeout 10 dumpcap -i "$IFACE" -a duration:5 -w "$TMP/c.pcap" -q >/dev/null 2>&1 || true
SHAPES=$(tshark -r "$TMP/c.pcap" -T fields -e radiotap.dbm_antsignal 2>/dev/null \
         | awk -F, 'NF>0{print NF}' | sort -n | uniq -c | head -3)
NCHAIN=$(tshark -r "$TMP/c.pcap" -T fields -e radiotap.dbm_antsignal 2>/dev/null \
         | awk -F, 'NF>m{m=NF} END{print m+0}')
printf '    values per frame: \n%s\n' "$(echo "$SHAPES" | sed 's/^/      /')"
if (( NCHAIN > 1 )); then
    ok "driver reports $NCHAIN separate chain values"
    printf '    %syou can tell the ports apart - the chain that drops when you\n' "$DIM"
    printf '    unscrew an antenna is that port%s\n' "$RST"
else
    ok "driver reports a single combined value (typical for mt7921)"
    printf '    %sport identity is therefore irrelevant: connect the directional to\n' "$DIM"
    printf '    either jack and leave the other empty%s\n' "$RST"
fi

# --------------------------------------------------------- reference AP
step "Picking the strongest AP as a reference"
REF=$(tshark -r "$TMP/c.pcap" -Y 'wlan.fc.type_subtype==8' \
      -T fields -e wlan.ta -e radiotap.dbm_antsignal 2>/dev/null \
      | awk -F'\t' '$1!=""{split($2,a,",");
          if(a[1]!=""){s[$1]+=a[1];n[$1]++}}
          END{for(k in s){m=s[k]/n[k]; if(m>best||best==0){best=m;bk=k}} print bk}')
[[ -n "$REF" ]] || { err "no beacons captured - antenna may not be connected"; exit 1; }
REFNAME=$(tshark -r "$TMP/c.pcap" -Y "wlan.ta==$REF && wlan.fc.type_subtype==8" \
          -T fields -e wlan.ssid 2>/dev/null | grep -m1 . || echo "<hidden>")
ok "reference: $REF  ($REFNAME)"

# ------------------------------------------------------------- live meter
step "Live signal - rotate the antenna and watch"
cat <<EOF
    ${DIM}A working directional swings 15-25 dB between pointed at the AP and
    pointed away. An omni, or a directional on a dead port, barely moves.
    Ctrl-C when done.${RST}

EOF
PEAK=-127; TROUGH=0
trap 'printf "\n\n"; step "Result";
      printf "    peak %s dBm   trough %s dBm   swing %s dB\n" "$PEAK" "$TROUGH" "$((PEAK-TROUGH))";
      if (( PEAK-TROUGH >= 12 )); then ok "directional is working - good front-to-back ratio";
      elif (( PEAK-TROUGH >= 6 )); then warn "weak directivity - check the connector is seated";
      else err "almost no swing - antenna not connected, or you did not rotate it"; fi
      TX1=$(cat "/sys/class/net/$IFACE/statistics/tx_packets" 2>/dev/null || echo 0);
      if (( TX1 - TX0 == 0 )); then ok "0 packets transmitted - verifiably passive";
      else err "$((TX1-TX0)) packets transmitted"; fi
      rm -rf "$TMP"; exit 0' INT

while true; do
    timeout 5 dumpcap -i "$IFACE" -a duration:1 -w "$TMP/l.pcap" -q >/dev/null 2>&1 || true
    read -r AVG CNT < <(tshark -r "$TMP/l.pcap" -Y "wlan.ta==$REF" \
        -T fields -e radiotap.dbm_antsignal 2>/dev/null \
        | awk -F, '$1!=""{s+=$1;n++} END{if(n)printf "%d %d",s/n,n; else printf "0 0"}')
    if (( CNT > 0 )); then
        (( AVG > PEAK )) && PEAK=$AVG
        (( TROUGH == 0 || AVG < TROUGH )) && TROUGH=$AVG
        FILL=$(( (AVG + 95) / 2 )); (( FILL < 0 )) && FILL=0; (( FILL > 32 )) && FILL=32
        BAR=$(printf '%*s' "$FILL" '' | tr ' ' '#')
        printf '\r    %4s dBm  [%-32s]  peak %s  n=%-3s ' "$AVG" "$BAR" "$PEAK" "$CNT"
    else
        printf '\r    %s no frames from reference AP%s                              ' "$YLW" "$RST"
    fi
done
