"""Simulated truck ECU: broadcasts realistic J1939 frames on a virtual bus.

Run this in one terminal, then run monitor.py / dtc_tool.py in another.
Lets you develop and test the whole tool with no truck and no hardware.

Simulates one active fault: SPN 100 (oil pressure) FMI 1 (below normal,
most severe) with the red stop lamp on - so the DTC reader has
something to find. DEF level broadcasts at 9% so the threshold alerts
have something to flag.

Frame layouts match truckdiag/database.py (audited 2026-09-11).
"""

import math
import time

import can

from truckdiag.bus import open_bus
from truckdiag.j1939 import (encode_can_id, decode_can_id, DM1, DM2,
                             PGN_REQUEST, acknowledgment_frame)
from truckdiag.transport import build_bam_frames

SA_ENGINE = 0x00
SA_TRANS = 0x03
# Exhaust Emission Controller (aftertreatment) -- J1939DA preferred
# source address 61. On a real truck the DPF PGNs and aftertreatment
# DM1 come from this ECU, not the engine.
SA_AFTERTREATMENT = 61


def le(value, length):
    return bytes((value >> (8 * i)) & 0xFF for i in range(length))


# DM1: red stop lamp on (2-bit encoding: bits 5-4 = 01), one DTC:
# SPN 100 FMI 1, 3 occurrences. Fits in a single 8-byte frame.
DM1_BYTES = bytes([0x10, 0xFF, 100, 0x00, 0x01, 0x03])

# DM1 from the aftertreatment ECU: amber lamp on (bits 3-2 = 01), one
# DTC: SPN 3719 (DPF 1 soot load) FMI 0, 1 occurrence. Exercises the
# monitor's per-ECU fault tracking.
DM1_AT_BYTES = bytes([0x04, 0xFF, 0x87, 0x0E, 0x00, 0x01])

# DM2: previously active faults -- 3 DTCs, 14 bytes, must go by BAM:
#   SPN 3719 FMI 31 x1 (DPF 1 soot load percent - stationary regen needed)
#   SPN 1761 FMI 18 x2 (DEF tank level low)
#   SPN 100  FMI 1  x3 (oil pressure below normal)
DM2_PAYLOAD = bytes([0x04, 0xFF,
                     0x87, 0x0E, 0x1F, 0x01,
                     0xE1, 0x06, 0x12, 0x02,
                     0x64, 0x00, 0x01, 0x03])


def build_frames(t):
    rpm = 700 + 120 * math.sin(t / 3.0)
    torque = 22 + 8 * math.sin(t / 5.0)
    pedal = 18 + 6 * math.sin(t / 4.0)
    frames = []

    # EEC1: torque mode (byte 1), demand + actual torque, rpm
    eec1 = (bytes([0xF0, int(torque + 125), int(torque + 125)])
            + le(int(rpm / 0.125), 2) + bytes([0xFF, 0xFF, 0xFF]))
    frames.append((encode_can_id(3, 61444, SA_ENGINE), eec1))

    # EEC2: (byte 1 switches n/a), pedal, load
    eec2 = bytes([0xFF, int(pedal / 0.4), int(torque),
                  0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    frames.append((encode_can_id(3, 61443, SA_ENGINE), eec2))

    # ET1: coolant / fuel temp / oil temp (2 bytes)
    et1 = (bytes([82 + 40, 45 + 40])
           + le(int((95 + 273) / 0.03125), 2) + bytes([0xFF] * 4))
    frames.append((encode_can_id(5, 65262, SA_ENGINE), et1))

    # EFL/P1: fuel pressure, (byte 2: SPN 22 crankcase blow-by n/a),
    #         oil level, oil pressure, (bytes 5-6: SPN 101 n/a),
    #         coolant pressure, coolant level
    efl = (bytes([int(380 / 4), 0xFF, int(100 / 0.4), int(340 / 4)])
           + bytes([0xFF, 0xFF]) + bytes([int(110 / 2), int(100 / 0.4)]))
    frames.append((encode_can_id(5, 65263, SA_ENGINE), efl))

    # FE: fuel rate + economy
    fe = le(int(28 / 0.05), 2) + le(int(3.1 * 512), 2) + le(int(2.9 * 512), 2) + bytes([0xFF, 0xFF])
    frames.append((encode_can_id(6, 65266, SA_ENGINE), fe))

    # IC1: (byte 1 n/a), boost, intake manifold temp
    ic1 = bytes([0xFF, int(185 / 2), 48 + 40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    frames.append((encode_can_id(5, 65270, SA_ENGINE), ic1))

    # VEP1: battery voltage (bytes 5-6)
    vep1 = bytes([0xFF] * 4) + le(int(14.1 / 0.05), 2) + bytes([0xFF] * 2)
    frames.append((encode_can_id(6, 65271, SA_ENGINE), vep1))

    # VD: trip distance (SPN 244) + total vehicle distance (SPN 245)
    vd = le(int(812.3 / 0.125), 4) + le(int(512340.5 / 0.125), 4)
    frames.append((encode_can_id(6, 65248, SA_ENGINE), vd))

    # HOURS: engine hours
    hours = le(int(9842.5 / 0.05), 4) + bytes([0xFF] * 4)
    frames.append((encode_can_id(6, 65253, SA_ENGINE), hours))

    # AT1T1I1: DEF tank level 9% (low -- exercises the alert path)
    at1 = bytes([int(9 / 0.4)] + [0xFF] * 7)
    frames.append((encode_can_id(6, 65110, SA_ENGINE), at1))

    # DM1: red stop lamp + SPN 100 FMI 1 (engine ECU)
    frames.append((encode_can_id(6, DM1, SA_ENGINE), DM1_BYTES))
    # DM1: amber lamp + SPN 3719 FMI 0 (aftertreatment ECU)
    frames.append((encode_can_id(6, DM1, SA_AFTERTREATMENT), DM1_AT_BYTES))

    return frames


def poll_requests(bus):
    """Answer PGN requests seen on the bus. Returns reply frames to send.

    DM1 -> direct reply. DM2 -> BAM multi-packet reply. Anything else ->
    NACK (PGN 59392), so the tool can distinguish "refused" from silence.
    """
    replies = []
    while True:
        msg = bus.recv(timeout=0)
        if msg is None:
            break
        if not msg.is_extended_id:
            continue
        info = decode_can_id(msg.arbitration_id)
        if info["pgn"] != PGN_REQUEST or len(msg.data) < 3:
            continue
        pgn = msg.data[0] | (msg.data[1] << 8) | (msg.data[2] << 16)
        if pgn == DM1:
            replies.append((encode_can_id(6, DM1, SA_ENGINE), DM1_BYTES))
            replies.append((encode_can_id(6, DM1, SA_AFTERTREATMENT),
                            DM1_AT_BYTES))
        elif pgn == DM2:
            replies.extend(build_bam_frames(DM2, SA_ENGINE, DM2_PAYLOAD))
        else:
            replies.append(acknowledgment_frame(1, pgn, SA_ENGINE,
                                                address=info["source"]))
    return replies


def main():
    bus = open_bus("virtual")
    print("Simulated ECU broadcasting on virtual bus 'truckdiag'. Ctrl-C to stop.")
    t = 0.0
    try:
        while True:
            for can_id, data in poll_requests(bus):
                bus.send(can.Message(arbitration_id=can_id, data=data,
                                     is_extended_id=True))
            for can_id, data in build_frames(t):
                bus.send(can.Message(arbitration_id=can_id, data=data,
                                     is_extended_id=True))
            time.sleep(0.1)
            t += 0.1
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
