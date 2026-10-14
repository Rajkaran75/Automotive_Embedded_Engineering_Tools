#!/bin/bash
# start_canlog.sh — headless CAN logger for the truck.
#
# Runs as root from the truckdiag-canlog systemd service. It:
#   1. Probes 250000 then 500000 bps for real J1939 traffic.
#   2. Logs every frame with `candump -l` into /home/<user>/canlogs/.
#   3. Records what it did in logger-status.log.
#
# Zero interaction needed: power the Pi on at the truck, it logs;
# shut the Pi down, take the logs home.
set -u

PI_USER="${PI_USER:-kodi}"
IFACE="${IFACE:-can0}"
LOGDIR="/home/$PI_USER/canlogs"

mkdir -p "$LOGDIR"
chown "$PI_USER:$PI_USER" "$LOGDIR"

log() { echo "$(date '+%F %T') $*" >> "$LOGDIR/logger-status.log"; }

valid_frames() {
    timeout 3 stdbuf -oL -eL candump "$IFACE" 2>/dev/null \
        | awk '$3 ~ /^[01][0-9a-fA-F]{7}$/ {c++} END {print c+0}'
}

BR=""
for br in 250000 500000; do
    ip link set "$IFACE" down 2>/dev/null
    ip link set "$IFACE" up type can bitrate "$br" 2>/dev/null || continue
    n=$(valid_frames)
    log "probe $br bps -> ${n:-0} J1939 frames in 3s"
    if [ "${n:-0}" -gt 0 ]; then BR=$br; break; fi
done

if [ -z "$BR" ]; then
    BR=250000
    ip link set "$IFACE" down 2>/dev/null
    ip link set "$IFACE" up type can bitrate "$BR" 2>/dev/null || true
    log "no traffic heard; defaulting to $BR and logging anyway (bus may wake later)"
else
    log "logging at $BR bps"
fi

cd "$LOGDIR" || exit 1
# candump -l writes candump-YYYY-MM-DD_HHMMSS.log in this directory.
exec candump -l "$IFACE"
