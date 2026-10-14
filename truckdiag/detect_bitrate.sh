#!/bin/bash
# detect_bitrate.sh — find the working CAN bitrate instead of guessing.
#
# Tries each candidate bitrate on the interface, listens briefly, and picks
# the one that produces real J1939 frames (29-bit IDs). Error frames
# (wrong bitrate) don't count. Leaves the interface UP at the winner.
#
# Usage: ./detect_bitrate.sh [interface]     (default: can0)
# Prints the winning bitrate on stdout.
set -u

IFACE="${1:-can0}"
CANDIDATES="250000 500000"   # J1939 standard first, then the faster variant

# Count real J1939 frames in ~3 seconds. J1939 uses 29-bit IDs, which print
# as 8 hex digits starting with 0/1. Error frames (CAN_ERR_FLAG set) start
# with 2/3 and are ignored. stdbuf defeats pipe buffering so the count is live.
valid_frames() {
    timeout 3 stdbuf -oL -eL candump "$IFACE" 2>/dev/null \
        | awk '$3 ~ /^[01][0-9a-fA-F]{7}$/ {c++} END {print c+0}'
}

best_br=""
best_n=0
for br in $CANDIDATES; do
    sudo ip link set "$IFACE" down 2>/dev/null
    if ! sudo ip link set "$IFACE" up type can bitrate "$br" 2>/dev/null; then
        echo "  $br bps: interface would not come up" >&2
        continue
    fi
    n=$(valid_frames)
    echo "  $br bps -> ${n:-0} J1939 frames in 3s" >&2
    if [ "${n:-0}" -gt "$best_n" ]; then best_n=$n; best_br=$br; fi
done

if [ -z "$best_br" ]; then
    best_br=250000
    echo "No traffic heard at any bitrate; defaulting to $best_br (J1939 standard)." >&2
    echo "The bus may simply be asleep (key off) — re-run with the key on." >&2
else
    echo "Winner: $best_br bps ($best_n J1939 frames heard)." >&2
fi

sudo ip link set "$IFACE" down 2>/dev/null
sudo ip link set "$IFACE" up type can bitrate "$best_br"
echo "$best_br"
