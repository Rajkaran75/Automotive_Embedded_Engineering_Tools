[![truckdiag CI](https://github.com/Rajkaran75/Automotive_Embedded_Engineering_Tools/actions/workflows/truckdiag-ci.yml/badge.svg)](https://github.com/Rajkaran75/Automotive_Embedded_Engineering_Tools/actions/workflows/truckdiag-ci.yml)

# truckdiag — DIY J1939 diagnostics for Class 8 trucks

Reads live engine/transmission/electrical parameters and diagnostic trouble
codes straight off the truck's CAN bus (SAE J1939). No subscriptions,
no OEM software needed for the standard data.

## Quickstart (no truck needed)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# live dashboard against the built-in simulated ECU:
.venv/bin/python monitor.py --demo

# read fault codes against the simulated ECU (incl. NACK + BAM demo):
.venv/bin/python dtc_tool.py read --demo

# run the test suite (unit + end-to-end over a virtual bus):
.venv/bin/python tests/test_decoder.py
.venv/bin/python tests/test_transport.py
.venv/bin/python tests/test_thresholds.py
.venv/bin/python tests/test_e2e.py
```

`dtc_tool.py read` / `dtc_tool.py clear` read and clear fault codes
(DM1/DM2/DM3/DM11). On the virtual bus they are exercised by the e2e test;
on real hardware they talk to the actual ECUs.

## Real hardware

You need two things between the laptop and the truck:

1. **CAN-USB adapter** (~$30–60 for a GS-USB/candleLight-style dongle,
   ~$750+ for a NEXIQ USB-Link 3). The 9-pin Deutsch cable alone is just
   wires — it cannot talk to a computer by itself.
2. **9-pin Deutsch cable** from the adapter to the truck's diagnostic port
   (under the dash, driver's side).

Then bring up the interface and run:

```bash
# Linux / Raspberry Pi (recommended):
./detect_bitrate.sh                  # finds the truck's speed (usually 250000), leaves can0 up
.venv/bin/python monitor.py --socketcan can0 --bitrate 250000
.venv/bin/python dtc_tool.py read --socketcan can0 --bitrate 250000
# use --bitrate 500000 if the detector picked it; see RUNBOOK.md for headless logging

# Windows (adapter must speak SLCAN; find its COM port in Device Manager):
.venv\Scripts\python monitor.py --slcan COM3
.venv\Scripts\python dtc_tool.py read --slcan COM3
```

Reading is passive and safe. Clearing codes (DM3/DM11) is fine on your own
truck, but it doesn't fix the underlying fault — it just resets the lamp.

## Which computer?

**Raspberry Pi in the truck is the best setup**: native SocketCAN, cheap,
and it can live in the cab permanently as a logger. Forgot the Pi login?
Don't fight it — just reflash the SD card with Raspberry Pi Imager
(https://www.raspberrypi.com/software/), boot fresh, and you're back in
~20 minutes.

Pi quickstart after reflashing:

```bash
# from your Windows laptop, copy the project to the Pi:
scp -r truckdiag pi@<pi-ip>:~
# then on the Pi:
bash ~/truckdiag/pi_setup.sh
```

The script installs everything, smoke-tests the decoder, and optionally
brings `can0` up at boot.

**Windows laptop works too** via the `--slcan` option, as long as the
adapter speaks the SLCAN serial protocol. The InnoMaker adapter is
Linux-first (native SocketCAN, no driver); on Windows you may need its
Windows driver or SLCAN firmware — the Pi route avoids all of that.

## Layout

- `truckdiag/j1939.py` — 29-bit CAN id encode/decode, request & clear frames,
  acknowledgment (ACK/NACK, PGN 59392) parsing
- `truckdiag/database.py` — PGN/SPN scalings (J1939-71), SPN names, FMI table,
  aftertreatment SPNs, DEF tank level (PGN 65110 / SPN 1761)
- `truckdiag/decoder.py` — frame → human-readable values
- `truckdiag/dtc.py` — DM1 parsing per J1939-73 (2-bit lamp states, FF padding skipped)
- `truckdiag/transport.py` — BAM multi-packet send/reassemble (TP.CM/TP.DT)
- `truckdiag/thresholds.py` — engine health profiles with source-labeled bands
- `truckdiag/bus.py` — virtual (test) vs SocketCAN (real) bus
- `sim_ecu.py` — simulated ECU for development without a truck
- `monitor.py` — live dashboard (`--demo` = simulated truck,
  `--profile dd15-older` for pre-Gen 5 engines)
- `dtc_tool.py` — `read` / `clear` fault codes; `read` reports NACKs vs silence

## Health alerts

The monitor checks live values against verified OEM bands, not guesses.
Two profiles are built in (default `dd15-gen5`, option `dd15-older` for
pre-2021 DD15 engines); every band carries its source and a confidence
grade, e.g. oil pressure 50 psi normal / 25 psi low / 0 psi very low on
Gen 5, coolant normal 175–195°F with a 234°F maximum, DEF warning ~10%.
Parameters with no verified band (boost, oil temp, fuel rate, ...) are
never flagged — the tool says nothing rather than invent a limit.

## Aftertreatment

DEF tank level decodes live from PGN 65110 (SPN 1761). DPF PGNs
(64891 soot/ash, 64892 regen control, 64946 differential pressure) are
recognized and named but **not byte-decoded** — their exact public-domain
byte layouts couldn't be verified from an authoritative source, so the
tool shows them as raw hex rather than guessing. DPF fault codes (e.g.
SPN 3719, 1761, 3697–3703) still decode with real names in DM1/DM2.

## Roadmap

- Day 2: transmission gear + fluid temp (verify byte layout on the real truck),
  verify DPF PGN byte layouts against a licensed SAE J1939 reference
- Day 3: trip logging to SQLite, PDF health report, VIN via transport protocol
- Later: freeze-frame (DM4) reader, RTS/CTS connection-mode transfers
