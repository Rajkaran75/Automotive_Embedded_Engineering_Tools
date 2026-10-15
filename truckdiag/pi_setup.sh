#!/usr/bin/env bash
# truckdiag Raspberry Pi setup — run once on a fresh Raspberry Pi OS install.
#
#   1. Reflash the SD card with Raspberry Pi Imager (Raspberry Pi OS Lite is fine)
#   2. Copy this project folder to the Pi so it lives at ~/truckdiag
#      (scp -r truckdiag pi@<pi-ip>:~   or a USB stick)
#   3. On the Pi, run:  bash ~/truckdiag/pi_setup.sh
#
# What it does:
#   - installs system packages (python3, venv, can-utils)
#   - creates ~/truckdiag/.venv and installs python-can
#   - smoke-tests the decoder against the simulated ECU (no truck needed)
#   - optionally configures can0 to come up at boot at 250000 bps
set -euo pipefail

PROJ="$HOME/truckdiag"

if [ ! -f "$PROJ/requirements.txt" ]; then
    echo "ERROR: $PROJ/requirements.txt not found."
    echo "Copy the truckdiag project folder to $PROJ first, then re-run."
    exit 1
fi

echo "==> Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-venv python3-pip can-utils

echo "==> Creating virtualenv and installing dependencies..."
python3 -m venv "$PROJ/.venv"
"$PROJ/.venv/bin/pip" install -q --upgrade pip
"$PROJ/.venv/bin/pip" install -q -r "$PROJ/requirements.txt"

echo "==> Smoke test (simulated ECU, no truck needed)..."
(cd "$PROJ" && .venv/bin/python tests/test_decoder.py && .venv/bin/python tests/test_e2e.py)

read -r -p "Configure can0 to come up at boot at 250000 bps? [y/N] " ans
if [[ "$ans" =~ ^[Yy]$ ]]; then
    sudo tee /etc/network/interfaces.d/can0 >/dev/null <<'EOF'
auto can0
iface can0 inet manual
    pre-up /sbin/ip link set can0 up type can bitrate 250000
    up /sbin/ip link set can0 up
    down /sbin/ip link set can0 down
EOF
    echo "can0 will come up at boot. Activate now with: sudo ifup can0"
else
    echo "Skipped. Bring it up manually when the adapter is plugged in:"
    echo "  sudo ip link set can0 up type can bitrate 250000"
fi

echo
echo "Done."
echo "  Demo (no truck):   cd ~/truckdiag && .venv/bin/python monitor.py --demo"
echo "  On the truck:      .venv/bin/python monitor.py --socketcan can0"
