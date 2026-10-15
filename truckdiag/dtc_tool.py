"""Fault-code tool: read active DTCs, clear inactive (or active) codes.

Usage:
  python dtc_tool.py read                     # virtual bus
  python dtc_tool.py read --socketcan can0    # real hardware
  python dtc_tool.py clear                     # clear inactive codes (DM3)
  python dtc_tool.py clear --active            # clear active codes (DM11)

Reading distinguishes three outcomes per requested PGN: data received,
an explicit NACK/refusal from the ECU (PGN 59392), or silence (timeout).
"""

import argparse
import time

import can

from truckdiag.bus import open_bus
from truckdiag.j1939 import (decode_can_id, request_pgn_frame, clear_dtcs_frame,
                             parse_acknowledgment,
                             DM1, DM2, DM3, DM11, ACKM, TP_CM, TP_DT)
from truckdiag.dtc import parse_dm1, format_dtc
from truckdiag.transport import BamReassembler


def collect(bus, requests, seconds=5.0):
    """Request PGNs and collect replies.

    Returns (dm1_by_src, dm2_by_src, notices). Multi-packet replies are
    reassembled via BAM; NACKs are reported as notices instead of being
    confused with silence.
    """
    for pgn in requests:
        can_id, data = request_pgn_frame(pgn)
        bus.send(can.Message(arbitration_id=can_id, data=data,
                             is_extended_id=True))
    reasm = BamReassembler()
    dm1, dm2, notices = {}, {}, []
    deadline = time.time() + seconds
    while time.time() < deadline:
        msg = bus.recv(timeout=0.2)
        if msg is None or not msg.is_extended_id:
            continue
        info = decode_can_id(msg.arbitration_id)
        pgn, src = info["pgn"], info["source"]
        if pgn == ACKM:
            ack = parse_acknowledgment(msg.data)
            if ack and ack["control"] != 0:
                notices.append("ECU 0x%02X: %s for requested PGN %d"
                               % (src, ack["control_name"], ack["pgn"]))
            continue
        if pgn in (TP_CM, TP_DT):
            done = reasm.feed(msg.arbitration_id, msg.data)
            if done:
                rpgn, rsrc, payload = done
                parsed = parse_dm1(payload)
                if parsed:
                    (dm1 if rpgn == DM1 else dm2)[rsrc] = parsed
            continue
        if pgn in (DM1, DM2):
            parsed = parse_dm1(msg.data)
            if parsed:
                (dm1 if pgn == DM1 else dm2)[src] = parsed
    return dm1, dm2, notices


def print_report(dm1, dm2, notices):
    if not dm1 and not dm2:
        print("No DM1/DM2 frames seen.")
    for src in sorted(set(dm1) | set(dm2)):
        print("Source address 0x%02X:" % src)
        rep = dm1.get(src)
        if rep:
            lamps = ", ".join(rep["lamps"]) or "none"
            print("  Lamps: %s" % lamps)
            if rep.get("flashing"):
                print("  Flashing: %s" % ", ".join(rep["flashing"]))
            for d in rep["dtcs"]:
                print("  ACTIVE: " + format_dtc(d))
            if not rep["dtcs"]:
                print("  No active fault codes.")
        else:
            print("  No active-fault (DM1) data.")
        rep2 = dm2.get(src)
        if rep2 and rep2["dtcs"]:
            for d in rep2["dtcs"]:
                print("  STORED: " + format_dtc(d))
    for n in notices:
        print("Note: " + n)
    if not dm1 and not dm2 and not notices:
        print("No response at all: check that an ECU/simulator is on the bus, "
              "or the request may have been ignored.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["read", "clear"])
    ap.add_argument("--active", action="store_true",
                    help="with 'clear': clear ACTIVE codes too (DM11)")
    ap.add_argument("--socketcan", metavar="IFACE",
                    help="use real SocketCAN interface on Linux (e.g. can0)")
    ap.add_argument("--slcan", metavar="PORT",
                    help="use SLCAN over a serial port, e.g. COM3 on Windows")
    ap.add_argument("--bitrate", type=int, default=250000,
                    help="CAN bitrate in bps (default 250000, the J1939 standard; "
                         "try 500000 on newer networks)")
    ap.add_argument("--demo", action="store_true",
                    help="run the simulated ECU in-process (no truck needed)")
    args = ap.parse_args()

    if args.demo:
        import sim_ecu
        import threading

        def _sim_loop():
            bus = open_bus("virtual")
            t = 0.0
            while True:
                for can_id, data in sim_ecu.poll_requests(bus):
                    bus.send(can.Message(arbitration_id=can_id, data=data,
                                         is_extended_id=True))
                for can_id, data in sim_ecu.build_frames(t):
                    bus.send(can.Message(arbitration_id=can_id, data=data,
                                         is_extended_id=True))
                time.sleep(0.1)
                t += 0.1

        threading.Thread(target=_sim_loop, daemon=True).start()
        time.sleep(0.3)

    if args.socketcan:
        bus = open_bus("socketcan", args.socketcan, bitrate=args.bitrate)
    elif args.slcan:
        bus = open_bus("slcan", args.slcan, bitrate=args.bitrate)
    else:
        bus = open_bus("virtual")
    try:
        if args.command == "read":
            # also explicitly request DM1 + DM2 in case nothing is broadcasting
            dm1, dm2, notices = collect(bus, (DM1, DM2))
            print_report(dm1, dm2, notices)
        else:
            which = "active" if args.active else "inactive"
            can_id, data = clear_dtcs_frame(which)
            bus.send(can.Message(arbitration_id=can_id, data=data,
                                 is_extended_id=True))
            print("Sent %s (%s). Re-reading in 2s..."
                  % ("DM11" if args.active else "DM3", which))
            time.sleep(2)
            dm1, dm2, notices = collect(bus, (DM1,), seconds=3.0)
            print_report(dm1, dm2, notices)
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
