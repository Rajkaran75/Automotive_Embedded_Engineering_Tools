"""Unit tests for the J1939 decode path. Run: python tests/test_decoder.py"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from truckdiag.j1939 import (decode_can_id, encode_can_id, request_pgn_frame,
                             clear_dtcs_frame, DM1, DM3)
from truckdiag.decoder import decode_frame
from truckdiag.dtc import parse_dm1


def test_can_id_roundtrip():
    # EEC1 from engine ECU: priority 3, PGN 61444, source 0 -> 0x0CF00400
    can_id = encode_can_id(3, 61444, 0x00)
    assert can_id == 0x0CF00400, hex(can_id)
    info = decode_can_id(can_id)
    assert info["pgn"] == 61444 and info["source"] == 0 and info["priority"] == 3


def test_eec1_decode():
    # torque mode nibble, demand 25% (raw 150), actual 25% (raw 150),
    # rpm 800 (raw 6400)
    can_id = encode_can_id(3, 61444, 0)
    data = bytes([0xF0, 150, 150, 0x00, 0x19, 0xFF, 0xFF, 0xFF])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[190]["value"] == 800.0, vals[190]
    assert vals[513]["value"] == 25.0, vals[513]
    assert vals[512]["value"] == 25.0, vals[512]


def test_not_available():
    # coolant temp raw 0xFF -> None, not -40+255
    can_id = encode_can_id(5, 65262, 0)
    data = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    dec = decode_frame(can_id, data)
    assert all(v["value"] is None for v in dec["values"])


def test_dm1_parse():
    # red stop lamp on (2-bit encoding: bits 5-4 = 01);
    # SPN 100, FMI 1, 3 occurrences
    parsed = parse_dm1(bytes([0x10, 0xFF, 100, 0x00, 0x01, 0x03]))
    assert parsed["lamps"] == ["Red stop lamp"], parsed["lamps"]
    assert len(parsed["dtcs"]) == 1
    d = parsed["dtcs"][0]
    assert (d["spn"], d["fmi"], d["occurrences"]) == (100, 1, 3)


def test_dm1_lamp_encoding():
    # 2-bit lamp states: 0x04 -> amber on (bits 3-2 = 01), red stop off
    parsed = parse_dm1(bytes([0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
    assert parsed["lamps"] == ["Amber warning lamp"], parsed["lamps"]
    assert parsed["dtcs"] == []  # all-FF slot is padding, not a DTC
    # flash byte: 0x04 in byte 1 -> amber flashing
    parsed = parse_dm1(bytes([0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]))
    assert parsed["lamps"] == []
    assert parsed["flashing"] == ["Amber warning lamp"], parsed["flashing"]


def test_dm1_multi():
    # two DTCs: (100/1) and (110/0 x2); lamp byte 0x10 = red stop
    parsed = parse_dm1(bytes([0x10, 0xFF,
                              100, 0x00, 0x01, 0x01,
                              110, 0x00, 0x00, 0x02]))
    assert parsed["lamps"] == ["Red stop lamp"]
    assert len(parsed["dtcs"]) == 2
    assert parsed["dtcs"][1]["spn"] == 110
    assert parsed["dtcs"][1]["occurrences"] == 2


def test_request_frame():
    can_id, data = request_pgn_frame(DM1)
    assert can_id == 0x18EAFFF9, hex(can_id)  # global request from tool addr 0xF9
    assert data == bytes([0xCA, 0xFE, 0x00])  # 65226 little-endian


def test_clear_frame():
    can_id, data = clear_dtcs_frame("inactive")
    info = decode_can_id(can_id)
    assert info["pgn"] == DM3 and data == b""


def test_unknown_pgn_passthrough():
    dec = decode_frame(encode_can_id(6, 12345, 0), bytes([1, 2, 3]))
    assert dec["values"] == [] and dec["raw"] == "010203"


def test_def_tank_decode():
    # PGN 65110 byte 1: SPN 1761, 0.4 %/bit -> raw 40 = 16%
    can_id = encode_can_id(6, 65110, 0)
    dec = decode_frame(can_id, bytes([40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[1761]["value"] == 16.0, vals[1761]


def test_eec2_and_vep1_positions():
    # EEC2: pedal SPN 91 byte 2 (raw 100 -> 40%), load SPN 92 byte 3
    can_id = encode_can_id(3, 61443, 0)
    dec = decode_frame(can_id, bytes([0xFF, 100, 42, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[91]["value"] == 40.0, vals[91]
    assert vals[92]["value"] == 42.0, vals[92]
    # VEP1: battery SPN 168 bytes 5-6 (raw 282 -> 14.1 V)
    can_id = encode_can_id(6, 65271, 0)
    dec = decode_frame(can_id, bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x01, 0xFF, 0xFF]))
    vals = {v["spn"]: v for v in dec["values"]}
    assert abs(vals[168]["value"] - 14.1) < 0.01, vals[168]


def test_oil_temp_two_bytes():
    # ET1: SPN 175 bytes 3-4, 0.03125 C/bit, offset -273.
    # 95 C -> raw (95+273)/0.03125 = 11776 = 0x2E00
    can_id = encode_can_id(5, 65262, 0)
    dec = decode_frame(can_id, bytes([122, 85, 0x00, 0x2E, 0xFF, 0xFF, 0xFF, 0xFF]))
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[110]["value"] == 82.0, vals[110]
    assert abs(vals[175]["value"] - 95.0) < 0.01, vals[175]


def test_aftertreatment_spn_names():
    from truckdiag.database import SPN_NAMES
    assert SPN_NAMES[3719] == "DPF 1 soot load percent"
    assert SPN_NAMES[1761] == "Aftertreatment 1 DEF tank level"
    assert SPN_NAMES[3700] == "DPF active regeneration status"
    # a DPF fault decodes with its real name
    parsed = parse_dm1(bytes([0x04, 0xFF, 0x87, 0x0E, 0x1F, 0x01]))
    d = parsed["dtcs"][0]
    assert (d["spn"], d["fmi"]) == (3719, 31), d
    assert d["spn_name"] == "DPF 1 soot load percent", d


def test_dpf_at1s1_decode():
    # PGN 64891: soot 65%, ash 40%, 3600 s since regen, 80% threshold
    # threshold raw = 80 / 0.0025 = 32000 = 0x7D00
    can_id = encode_can_id(6, 64891, 0)
    data = bytes([65, 40, 0x10, 0x0E, 0x00, 0x00, 0x00, 0x7D])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[3719]["value"] == 65.0, vals[3719]
    assert vals[3720]["value"] == 40.0, vals[3720]
    assert vals[3721]["value"] == 3600.0, vals[3721]
    assert abs(vals[5466]["value"] - 80.0) < 0.01, vals[5466]


def test_dpf_dpfc1_bitfields():
    # PGN 64892: lamp on-solid, regen ready, active regen, moderate soot,
    # inhibited by switch only, auto-regen enabled
    can_id = encode_can_id(6, 64892, 0)
    data = bytes([0x09, 0x24, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[3697]["state"] == "On - solid", vals[3697]
    assert vals[8857]["state"] == "Ready for initiation", vals[8857]
    assert vals[3699]["state"] == "not active", vals[3699]
    assert vals[3700]["state"] == "active", vals[3700]
    assert vals[3701]["state"] == "Regen needed - moderate level", vals[3701]
    assert vals[3702]["state"] == "not inhibited", vals[3702]
    assert vals[3703]["state"] == "inhibited", vals[3703]
    assert vals[3718]["state"] == "enabled", vals[3718]
    assert vals[3698]["state"] == "Off", vals[3698]
    assert vals[4175]["state"] == "Not Active", vals[4175]


def test_dpf_dpfc1_not_available():
    # lamp command 0b111 -> n/a, not a bogus state
    can_id = encode_can_id(6, 64892, 0)
    data = bytes([0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[3697]["value"] is None and vals[3697]["state"] is None


def test_dpf_at1img_decode():
    # PGN 64946: 300 C, 320 C, 4.5 kPa; preliminary FMIs 0/7/0
    can_id = encode_can_id(6, 64946, 0)
    data = bytes([0xA0, 0x47, 0x20, 0x4A, 0x2D, 0x00, 0xE0, 0x00])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert abs(vals[3249]["value"] - 300.0) < 0.01, vals[3249]
    assert abs(vals[3250]["value"] - 320.0) < 0.01, vals[3250]
    assert abs(vals[3251]["value"] - 4.5) < 0.01, vals[3251]
    # 3253 spans byte 7 bits 6-8 + byte 8 bits 1-2: 0b111 | 0 = 7
    assert vals[3252]["value"] == 0, vals[3252]
    assert vals[3253]["value"] == 7, vals[3253]
    assert vals[3254]["value"] == 0, vals[3254]


def test_eflp1_byte_positions():
    # J1939DA: oil level byte 3, oil pressure byte 4,
    # coolant pressure 1 byte at byte 7, coolant level byte 8
    can_id = encode_can_id(5, 65263, 0)
    data = bytes([95, 0xFF, 250, 85, 0xFF, 0xFF, 55, 250])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[94]["value"] == 380.0, vals[94]
    assert vals[98]["value"] == 100.0, vals[98]
    assert vals[100]["value"] == 340.0, vals[100]
    assert vals[109]["value"] == 110.0, vals[109]
    assert vals[111]["value"] == 100.0, vals[111]


def test_vd_byte_positions():
    # J1939DA: bytes 1-4 = SPN 244 trip, bytes 5-8 = SPN 245 total
    can_id = encode_can_id(6, 65248, 0)
    data = bytes([0x62, 0x19, 0x00, 0x00, 0xA4, 0x8A, 0x3E, 0x00])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert abs(vals[244]["value"] - 812.25) < 0.01, vals[244]
    assert abs(vals[245]["value"] - 512340.5) < 0.01, vals[245]


def test_def_tank_temperature():
    # PGN 65110 byte 2: SPN 3031, 1 C/bit, offset -40
    can_id = encode_can_id(6, 65110, 0)
    dec = decode_frame(can_id, bytes([40, 90, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[1761]["value"] == 16.0, vals[1761]
    assert vals[3031]["value"] == 50.0, vals[3031]


def test_scr_inducement_decode():
    # PGN 65110 bytes 5-6 bit fields: 5245 low-DEF inducement, 5246 severity.
    # byte 5 (0-based 4): 5245 = bits 6-8 = 0b001 (low DEF, solid)
    # byte 6 (0-based 5): 5246 = bits 6-8 = 0b011 (level 3 derate)
    can_id = encode_can_id(6, 65110, 61)
    data = bytes([40, 90, 0xFF, 0xFF, 0x20, 0x60, 0xFF, 0xFF])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[5245]["state"] == "On solid - low DEF", vals[5245]
    assert vals[5246]["state"] == "Level 3 - engine derate", vals[5246]


def test_egr_and_turbo_decode():
    # PGN 65188: EGR diff pressure 12 kPa -> raw (12+250)/0.0078125 = 33536
    # PGN 65245: turbo speed 80000 rpm -> raw 20000 = 0x4E20
    can_id = encode_can_id(5, 65188, 0)
    data = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x83, 0xFF, 0xFF])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert abs(vals[411]["value"] - 12.0) < 0.01, vals[411]
    can_id = encode_can_id(5, 65245, 0)
    data = bytes([0xFF, 0x20, 0x4E, 0x40, 0xFF, 0xFF, 0xFF, 0xFF])
    dec = decode_frame(can_id, data)
    vals = {v["spn"]: v for v in dec["values"]}
    assert vals[103]["value"] == 80000.0, vals[103]
    assert vals[1665]["state"] == "Oil present at turbocharger", vals[1665]


def test_format_state_value():
    from truckdiag.decoder import format_value
    assert format_value({"name": "DPF lamp command", "value": 1,
                         "unit": "", "state": "On - solid"}) == \
        "DPF lamp command: On - solid"
    assert format_value({"name": "X", "value": None,
                         "unit": "%", "state": None}) == "X: n/a"

def test_health_explanations():
    from truckdiag.health import explain, action_for, fmi_guidance, check_soot
    # Known SPN returns rationale with a labeled basis.
    g = explain(5246)
    assert g and g["basis"] in ("da-state", "verified-band", "general"), g
    assert "derate" in action_for(5246).lower()
    # Unknown SPN: no guidance invented.
    assert explain(999999) is None
    assert action_for(999999) == ""
    # FMI plain-English guidance.
    assert "urgent" in fmi_guidance(0)
    assert "harness" in fmi_guidance(3)
    assert fmi_guidance(99) == ""
    # Soot vs the truck's own threshold: ok / warn / alert / missing data.
    assert check_soot(50, 100)[0] == "ok"
    assert check_soot(85, 100)[0] == "warn"   # 80% heuristic
    assert check_soot(100, 100)[0] == "alert"
    assert check_soot(None, 100)[0] == "ok"
    assert check_soot(50, None)[0] == "ok"

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print("%d tests passed" % len(tests))

