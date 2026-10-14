"""Live J1939 monitor: decodes broadcast frames into a refreshing dashboard.

Usage:
  python monitor.py                      # virtual bus (with sim_ecu.py running)
  python monitor.py --socketcan can0     # real hardware on can0
  python monitor.py --profile dd15-older # threshold profile for pre-Gen 5 DD15
"""

import argparse
import sys
import threading
import time

import can

from truckdiag.bus import open_bus
from truckdiag.decoder import decode_frame, format_value
from truckdiag.j1939 import (DM1, DM2, ACKM, TP_CM, TP_DT, decode_can_id,
                             encode_can_id, parse_acknowledgment)
from truckdiag.dtc import parse_dm1, format_dtc
from truckdiag.transport import BamReassembler
from truckdiag.thresholds import check as check_threshold, PROFILES, DEFAULT_PROFILE
from truckdiag.health import action_for, check_soot, explain, fmi_guidance

WATCH = [
    (190, "Engine speed"), (513, "Actual engine percent torque"),
    (91, "Accelerator pedal position 1"), (92, "Engine percent load at current speed"),
    (100, "Engine oil pressure"), (110, "Engine coolant temperature"),
    (111, "Engine coolant level"), (175, "Engine oil temperature 1"),
    (102, "Engine turbocharger boost pressure"),
    (105, "Engine intake manifold 1 temperature"),
    (183, "Engine fuel rate"), (185, "Engine average fuel economy"),
    (168, "Battery potential / power input 1"),
    (1761, "DEF tank level"),
    (84, "Wheel-based vehicle speed"), (245, "Total vehicle distance"),
    (247, "Total engine hours"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socketcan", metavar="IFACE",
                    help="use real SocketCAN interface on Linux (e.g. can0)")
    ap.add_argument("--slcan", metavar="PORT",
                    help="use SLCAN over a serial port, e.g. COM3 on Windows")
    ap.add_argument("--bitrate", type=int, default=500000,
                    help="CAN bitrate in bps (default 500000; try 250000 on older trucks)")
    ap.add_argument("--demo", action="store_true",
                    help="run the simulated ECU in-process (no truck needed)")
    ap.add_argument("--profile", default=DEFAULT_PROFILE, choices=sorted(PROFILES),
                    help="engine profile for health thresholds (default %s)" % DEFAULT_PROFILE)
    args = ap.parse_args()

    if args.demo:
        # python-can's virtual bus is per-process, so the simulator must
        # run in a thread inside this process for the demo to work.
        import sim_ecu

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
    latest = {}
    alerts = {}
    dtc_state = {}
    notices = []
    reasm = BamReassembler()
    last_draw = 0.0

    print("Listening... Ctrl-C to stop.")
    print("Threshold profile: %s" % PROFILES[args.profile]["label"])
    try:
        while True:
            msg = bus.recv(timeout=0.2)
            if msg is not None and msg.is_extended_id:
                if msg.arbitration_id is None:
                    continue
                pgn = decode_can_id(msg.arbitration_id)["pgn"]
                src = decode_can_id(msg.arbitration_id)["source"]
                if pgn == ACKM:
                    ack = parse_acknowledgment(msg.data)
                    if ack:
                        notices.append("ECU 0x%02X: %s (PGN %d)"
                                       % (src, ack["control_name"], ack["pgn"]))
                        notices = notices[-5:]
                    continue
                if pgn in (TP_CM, TP_DT):
                    done = reasm.feed(msg.arbitration_id, msg.data)
                    if done:
                        rpgn, rsrc, payload = done
                        if rpgn in (DM1, DM2):
                            parsed = parse_dm1(payload)
                            if parsed:
                                dtc_state[rsrc] = parsed
                        else:
                            dec = decode_frame(
                                encode_can_id(6, rpgn, rsrc), payload)
                            for v in dec["values"]:
                                latest[v["spn"]] = v
                    continue
                if pgn == DM1:
                    parsed = parse_dm1(msg.data)
                    if parsed:
                        # DM1 arrives per ECU (engine, trans, ABS,
                        # aftertreatment...); keep each source separate so
                        # one ECU's report never wipes another's.
                        dtc_state[src] = parsed
                    continue
                dec = decode_frame(msg.arbitration_id, msg.data)
                for v in dec["values"]:
                    latest[v["spn"]] = v
            now = time.time()
            if now - last_draw >= 0.5:
                last_draw = now
                alerts = {}
                for spn, v in latest.items():
                    status, text = check_threshold(spn, v["value"], args.profile)
                    if status != "ok":
                        alerts[spn] = (status, text, v)
                # DPF soot vs the truck's own regen threshold (no external
                # spec needed): needs both SPN 3719 and SPN 5466.
                soot = latest.get(3719)
                thr = latest.get(5466)
                if soot and thr:
                    s_status, s_text = check_soot(soot["value"], thr["value"])
                    if s_status != "ok":
                        alerts[3719] = (s_status, s_text, soot)
                sys.stdout.write("\033[2J\033[H")  # clear screen
                print("=== TRUCKDIAG live ===\n")
                for spn, label in WATCH:
                    v = latest.get(spn)
                    print(("  %-38s %s" % (label + ":",
                                           "%.1f %s" % (v["value"], v["unit"])
                                           if v and v["value"] is not None else "--")))
                if alerts:
                    print("\n--- Health alerts (%s) ---" % PROFILES[args.profile]["label"])
                    for spn in sorted(alerts):
                        status, text, v = alerts[spn]
                        print("  [%s] %s" % (status.upper(), text))
                        act = action_for(spn)
                        if act:
                            print("       -> %s" % act)
                print("\n--- Active fault codes (DM1) ---")
                shown = 0
                for esrc in sorted(dtc_state):
                    st = dtc_state[esrc]
                    if not (st.get("dtcs") or st.get("lamps")
                            or st.get("flashing")):
                        continue  # ECU reporting clean
                    shown += 1
                    print("  ECU 0x%02X:" % esrc)
                    lamps = ", ".join(st["lamps"]) or "none"
                    print("    Lamps: %s" % lamps)
                    if st.get("flashing"):
                        print("    Flashing: %s" % ", ".join(st["flashing"]))
                    for d in st["dtcs"]:
                        print("    " + format_dtc(d))
                        fg = fmi_guidance(d["fmi"])
                        if fg:
                            print("       typically: %s" % fg)
                if not shown:
                    print("  none")
                if notices:
                    print("\n--- Bus notices ---")
                    for n in notices:
                        print("  " + n)
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()
