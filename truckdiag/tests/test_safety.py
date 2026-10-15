"""Safety and edge-case tests: the bugs this audit found, locked in.

Run: python -m pytest tests/ -q   (from the truckdiag/ directory)
"""

import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from truckdiag.j1939 import (clear_dtcs_frame, decode_can_id, encode_can_id,
                             DM3, DM11)
from truckdiag.bus import open_bus
from truckdiag.database import PGN_DB, SPN_NAMES
from truckdiag.decoder import decode_frame
from truckdiag.dtc import parse_dm1
from truckdiag.transport import build_bam_frames, BamReassembler, TP_CM
from truckdiag.j1939 import encode_can_id as eci


def test_clear_frame_strict():
    # "inactive" -> DM3, "active" -> DM11, anything else must fail loudly.
    # A typo must never silently become "clear ACTIVE codes".
    cid, data = clear_dtcs_frame("inactive")
    assert decode_can_id(cid)["pgn"] == DM3 and data == b""
    cid, data = clear_dtcs_frame("active")
    assert decode_can_id(cid)["pgn"] == DM11 and data == b""
    with pytest.raises(ValueError):
        clear_dtcs_frame("inactve")   # the typo that used to clear actives
    with pytest.raises(ValueError):
        clear_dtcs_frame("")
    with pytest.raises(ValueError):
        clear_dtcs_frame(None)


def test_open_bus_rejects_unknown_interface():
    with pytest.raises(ValueError):
        open_bus("bogus-interface-name")


def test_spn_names_match_decoder_fields():
    # SPN_NAMES once had duplicate keys (5245/5246 defined twice); the
    # first definitions were silently dead. The DTC reader's names must
    # agree with the decoder's field names.
    assert SPN_NAMES[5245] == "DEF low level inducement"
    assert SPN_NAMES[5246] == "SCR inducement severity"
    fields_65110 = {f["spn"]: f["name"] for f in PGN_DB[65110]["fields"]}
    assert fields_65110[5245] == SPN_NAMES[5245]
    assert fields_65110[5246] == SPN_NAMES[5246]


def test_bam_rejects_inconsistent_announce():
    # Announce claims 100 bytes total but only 3 packets can ever arrive:
    # the session must never "complete" with a short payload.
    reasm = BamReassembler()
    bad_cm = (eci(6, TP_CM, 0x00, 0xFF),
              bytes([0x20, 100, 0, 3, 0xFF, 0xCA, 0xFE, 0x00]))
    assert reasm.feed(*bad_cm, now=1.0) is None
    frames = build_bam_frames(65226, 0x00, bytes(20))
    for f in frames[1:]:
        assert reasm.feed(*f, now=1.0) is None


def test_truncated_frame_decodes_available_fields():
    # A 3-byte EEC1: the rpm field is skipped, the torque fields decode.
    # Must never raise on short buffers.
    dec = decode_frame(encode_can_id(3, 61444, 0), bytes([0xF0, 150, 150]))
    vals = {v["spn"]: v["value"] for v in dec["values"]}
    assert vals[512] == 25.0 and vals[513] == 25.0
    assert 190 not in vals
    # Empty payload: no values, no crash.
    dec = decode_frame(encode_can_id(3, 61444, 0), b"")
    assert dec["values"] == []


def test_parse_dm1_too_short():
    assert parse_dm1(b"") is None
    assert parse_dm1(b"\x10") is None
