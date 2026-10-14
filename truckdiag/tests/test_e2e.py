"""End-to-end test: simulator in a thread, reader in main. Run: python tests/test_e2e.py"""

import sys
import os
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import can

from truckdiag.bus import open_bus
from truckdiag.j1939 import decode_can_id, DM1
from truckdiag.decoder import decode_frame
from truckdiag.dtc import parse_dm1
import sim_ecu


def test_e2e():
    stop = threading.Event()

    def run_sim():
        bus = open_bus("virtual")
        t = 0.0
        while not stop.is_set():
            for can_id, data in sim_ecu.build_frames(t):
                bus.send(can.Message(arbitration_id=can_id, data=data,
                                     is_extended_id=True))
            time.sleep(0.1)
            t += 0.1
        bus.shutdown()

    thread = threading.Thread(target=run_sim, daemon=True)
    thread.start()
    time.sleep(0.5)

    bus = open_bus("virtual")
    saw_rpm = saw_dtc_engine = saw_dtc_aftertreatment = False
    deadline = time.time() + 5.0
    while time.time() < deadline and not (saw_rpm and saw_dtc_engine
                                          and saw_dtc_aftertreatment):
        msg = bus.recv(timeout=0.2)
        if msg is None or not msg.is_extended_id:
            continue
        info = decode_can_id(msg.arbitration_id)
        pgn = info["pgn"]
        if pgn == DM1:
            parsed = parse_dm1(msg.data)
            if parsed and parsed["dtcs"]:
                d = parsed["dtcs"][0]
                if info["source"] == 0x00:
                    assert (d["spn"], d["fmi"]) == (100, 1), d
                    assert "Red stop lamp" in parsed["lamps"]
                    saw_dtc_engine = True
                elif info["source"] == 61:
                    assert (d["spn"], d["fmi"]) == (3719, 0), d
                    assert "Amber warning lamp" in parsed["lamps"]
                    saw_dtc_aftertreatment = True
        elif pgn == 61444:
            dec = decode_frame(msg.arbitration_id, msg.data)
            vals = {v["spn"]: v["value"] for v in dec["values"]}
            assert 600 < vals[190] < 900, vals[190]  # simulated idle rpm
            saw_rpm = True

    stop.set()
    thread.join(timeout=3)
    bus.shutdown()
    assert saw_rpm, "never decoded an EEC1 frame"
    assert saw_dtc_engine, "never parsed the engine DM1 fault"
    assert saw_dtc_aftertreatment, "never parsed the aftertreatment DM1 fault"
    print("PASS test_e2e: live decode + DM1 faults from both ECUs")


if __name__ == "__main__":
    test_e2e()
