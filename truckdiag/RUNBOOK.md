# Truck Runbook — J1939 Session (Headless)

Goal: capture live data and fault codes from a real Class 8 truck.
**No screen or keyboard in the cab** — the Pi logs on its own, and your
phone is the screen if you want to watch live.

## How this works without a screen

Two modes, both set up once at home:

- **Mode A — auto-logging (zero interaction).** A service on the Pi starts
  on every boot: it finds the working bitrate, then records every CAN
  frame to `~/canlogs/`. At the truck you just connect and power on.
  Take the logs home and review them.
- **Mode B — phone as the screen.** Your phone's hotspot pretends to be
  your home Wi-Fi, the Pi joins it automatically, and you SSH in from the
  phone to run the live dashboard. Same commands as the bench, no monitor.

## Bring list

- Raspberry Pi 4 + SD card (project at `~/truckdiag`, logger installed)
- USB-C power, 5V / 3A preferred (2A works — watch for throttling)
- InnoMaker USB2CAN adapter — **termination jumper OFF**
- Your Deutsch 9-pin → DB9 cable (verified: Deutsch C → DB9 pin 7,
  Deutsch D → DB9 pin 2)
- Your phone (hotspot + an SSH app such as Termius, free on iOS)
- Optional: momentary push button + 2 jumper wires (clean shutdown
  without a screen — see below)

No monitor, no keyboard, no mouse needed in the cab.

## Rules for this session

1. **Listen-only.** Do NOT run `dtc_tool.py clear` today. Read codes,
   write them down, understand them first.
2. **Jumper stays OFF** on the USB2CAN the entire time. The truck already
   has both 120Ω bus terminators; a third drops the bus to ~40Ω and
   corrupts frames.
3. Only diagnose a truck you have permission to touch.
4. Never yank Pi power mid-log — shut down cleanly (SSH or button).

## Bitrate: why not hardcoded

SAE J1939 runs at **250,000 bps** — that's the standard, and it's what
nearly every Class 8 truck's 9-pin diagnostic port uses. But some newer
trucks/networks run at **500,000**, so guessing is wrong. Instead:

- `~/truckdiag/detect_bitrate.sh` tries 250000, then 500000, listens
  ~3 seconds on each, and picks the one with real J1939 frames
  (error frames from a wrong bitrate don't count). It leaves `can0`
  up at the winner and prints the number.
- The headless logger runs the same probe automatically on every boot.

If you ever need to set it by hand:
`sudo ip link set can0 up type can bitrate 250000` (or 500000).

## One-time setup at home

```bash
cd ~/truckdiag
chmod +x detect_bitrate.sh start_canlog.sh

# install the auto-logging service (starts on every boot)
sudo cp truckdiag-canlog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable truckdiag-canlog.service
```

Verify it works **before** the truck (adapter plugged into the Pi,
no truck needed):

```bash
sudo systemctl start truckdiag-canlog.service
sleep 8
systemctl status truckdiag-canlog.service   # should say: active (running)
cat ~/canlogs/logger-status.log             # probes at both bitrates, then defaults to 250000
ls ~/canlogs/                               # a candump-*.log exists (empty is fine — no truck)
ps aux | grep -v grep | grep candump        # logger process is alive
```

Expected at home: "no traffic heard; defaulting to 250000" — correct,
there's no truck. At the truck it will instead say "logging at 250000"
(or 500000) with a real frame count.

### Phone hotspot trick (for Mode B)

1. On the Pi at home, note your Wi-Fi network name and password.
2. On your iPhone: Settings → General → About → Name — set it to your
   **home Wi-Fi network name**; Settings → Personal Hotspot → Wi-Fi
   Password — set it to your **home Wi-Fi password**. Turn the hotspot on.
3. The Pi sees a familiar network and joins the phone automatically.
4. On the phone, open Termius (free), SSH to `kodi@raspberrypi.local`
   (password: your Pi password). If that name doesn't resolve, look in
   the hotspot settings for the Pi's IP and use that.

Test this at home first: SSH in over your real Wi-Fi with Termius and
run `sudo shutdown -h now` from the phone. If that works, Mode B works.

### Optional: shutdown button (no phone needed)

Add to `/boot/firmware/config.txt`:
```
dtoverlay=gpio-shutdown,gpio_pin=3
```
Wire a momentary push button between physical pins 5 (GPIO3) and 6
(GND). A press then triggers a clean shutdown. Reboot after editing.

## At the truck — Mode A (auto-logging)

1. Truck key **ON, engine OFF** first. Most ECUs broadcast with the key
   on. (Oil pressure, boost, and some temps need the engine running —
   that's a later session.)
2. Green 9-pin Deutsch port → your cable → DB9 → USB2CAN → Pi USB.
3. Power the Pi. Walk away — it's logging by itself.
4. Do your walkaround / drive. The logger keeps writing `~/canlogs/`.
5. **Shut down cleanly**: SSH from your phone (`sudo shutdown -h now`)
   or press the GPIO button. Wait for the green LED to stop, then
   remove power. Unplug the Deutsch cable last.

## At the truck — Mode B (watch it live from your phone)

Same physical hookup. Hotspot on, SSH in from Termius, then:

```bash
cd ~/truckdiag
./detect_bitrate.sh              # confirms the truck's speed, leaves can0 up
.venv/bin/python monitor.py --socketcan can0 --bitrate 250000
# use --bitrate 500000 if the detector said so
```

Fault codes:
```bash
.venv/bin/python dtc_tool.py read --socketcan can0
```

Write down every SPN/FMI pair and which lamps are on. **Do not clear.**

## At the truck — Mode C (web dashboard on your phone)

Same physical hookup and hotspot trick as Mode B, but instead of an SSH
terminal you get a glanceable page in your phone's browser: big critical
readings, health alerts with "what to do" lines, fault codes grouped by
ECU with plain-English FMI explanations, and an optional beep when a new
alert appears. Still listen-only — the server never transmits on the bus.

On the Pi (SSH in once, or start it before you leave home):

```bash
cd ~/truckdiag
./detect_bitrate.sh              # confirms the truck's speed, leaves can0 up
.venv/bin/python webdash.py --socketcan can0 --bitrate 250000 &
# use --bitrate 500000 if the detector said so; & keeps it running
# after you close the SSH session
```

On your phone (same hotspot): open `http://raspberrypi.local:8080/`
(or the Pi's IP from the hotspot screen, e.g. `http://172.20.10.4:8080/`).

- Green bar = live. Red "STALE / DISCONNECTED" = frames stopped or the
  page lost the Pi — check the hotspot and the cable.
- Tap the sound button once to allow beeps (browsers require a tap
  before a page may play audio). A new alert then beeps.
- `--profile dd15-older` if the truck is a pre-2021 DD15.
- Bench test at home first: `.venv/bin/python webdash.py --demo` and
  open `http://localhost:8080/` on any computer.

Note: python-can's virtual bus is per-process, so the old "sim in one
terminal, monitor in another" recipe does not work — use `--demo`
(in-process sim) for no-hardware testing of both monitor.py and
webdash.py.

## Back home — reading the logs

Copy `~/canlogs/` off the Pi (USB stick, or `scp`). Each
`candump-*.log` is plain text: timestamp, interface, ID, bytes.
`logger-status.log` tells you which bitrate that session used.

Quick sanity check on a log:
```bash
wc -l candump-2026-*.log     # frame count — thousands = healthy session
grep -c '^(' candump-*.log   # same thing, alternate form
```

Replay a log into the decoder later as the tool grows; for now the logs
are your raw evidence of what the truck said.

## Troubleshooting

- **Status log says "no traffic heard" at the truck:** key off / ECUs
  asleep — turn the key on and wait ~30s (the service retries every
  20s on its own). Reseat the Deutsch and DB9 connections.
- **Only error frames / detector finds nothing but key is on:** wiring
  — re-verify Deutsch C → DB9 pin 7, Deutsch D → DB9 pin 2. Check
  `ip -details -statistics link show can0` for rising bus-error counters
  (physical-layer problem).
- **Pi freezes/reboots:** underpowered. `vcgencmd get_throttled` —
  anything but `throttled=0x0` means starving. Use 5V/3A and a short,
  thick USB-C cable.
- **Adapter not detected:** another USB port; `dmesg | tail` for errors.
- **SSH can't reach the Pi:** hotspot name/password must *exactly*
  match home Wi-Fi (case-sensitive); hotspot toggle must be ON;
  try the IP from the hotspot screen instead of `raspberrypi.local`.

## If you do have a screen handy

The old path still works: micro-HDMI monitor + keyboard, then
`./detect_bitrate.sh` and the `monitor.py` / `dtc_tool.py` commands
above directly on the Pi. Headless is just the no-screen version of
the same thing.
