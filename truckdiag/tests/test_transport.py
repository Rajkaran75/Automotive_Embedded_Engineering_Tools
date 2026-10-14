"""Tests for ACK/NACK parsing and BAM multi-packet reassembly.
Run: python tests/test_transport.py"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from truckdiag.j1939 import (parse_acknowledgment, acknowledgment_frame,
                             encode_can_id, DM2)
from truckdiag.transport import build_bam_frames, BamReassembler


def test_ackm_parse():
    # NACK (control=1) for PGN 59904, built then parsed back
    can_id, data = acknowledgment_frame(1, 59904, 0x00, address=0xF9)
    ack = parse_acknowledgment(data)
    assert ack["control"] == 1, ack
    assert ack["pgn"] == 59904, ack
    assert "NACK" in ack["control_name"], ack
    assert ack["address"] == 0xF9, ack


def test_ackm_controls():
    for control, word in [(0, "ACK"), (2, "Access denied"), (3, "Cannot respond")]:
        _, data = acknowledgment_frame(control, 65226, 0x00)
        ack = parse_acknowledgment(data)
        assert ack["control"] == control and word in ack["control_name"], ack


def test_bam_roundtrip():
    payload = bytes(range(20))  # 20 bytes -> 3 DT packets
    frames = build_bam_frames(DM2, 0x00, payload)
    assert len(frames) == 4  # 1 CM + 3 DT
    reasm = BamReassembler()
    done = None
    for can_id, data in frames:
        done = reasm.feed(can_id, data, now=1000.0)
    assert done is not None, "BAM transfer never completed"
    pgn, src, out = done
    assert (pgn, src) == (DM2, 0x00), done
    assert out == payload, out


def test_bam_single_packet():
    payload = b"\x10\xff\x64\x00\x01\x03"  # 6 bytes -> 1 DT packet
    frames = build_bam_frames(65226, 0x00, payload)
    reasm = BamReassembler()
    done = None
    for can_id, data in frames:
        done = reasm.feed(can_id, data, now=1000.0)
    assert done[2] == payload, done


def test_bam_out_of_order_aborts():
    payload = bytes(range(14))  # 2 packets
    frames = build_bam_frames(DM2, 0x00, payload)
    cm, dt1, dt2 = frames
    reasm = BamReassembler()
    assert reasm.feed(*cm, now=1000.0) is None
    # sequence 2 arrives before sequence 1: no session matches -> dropped
    assert reasm.feed(*dt2, now=1000.0) is None
    # now seq 1 arrives and completes only a 1-packet session; the
    # announced 2-packet session never completes
    assert reasm.feed(*dt1, now=1000.0) is None


def test_bam_timeout_drops_session():
    payload = bytes(range(14))
    frames = build_bam_frames(DM2, 0x00, payload)
    cm, dt1, dt2 = frames
    reasm = BamReassembler(timeout=1.0)
    reasm.feed(*cm, now=1000.0)
    reasm.feed(*dt1, now=1000.0)
    # session times out before the last packet
    assert reasm.feed(*dt2, now=1002.5) is None


def test_bam_ignores_unrelated():
    reasm = BamReassembler()
    can_id = encode_can_id(3, 61444, 0)  # plain EEC1 frame
    assert reasm.feed(can_id, bytes([1] * 8), now=1000.0) is None


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print("%d tests passed" % len(tests))
