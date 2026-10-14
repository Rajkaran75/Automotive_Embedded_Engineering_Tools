"""J1939 transport protocol: multi-packet (BAM) send/receive.

Anything longer than 8 bytes (multi-fault DM1/DM2, VIN, component ID)
travels as a Broadcast Announce Message (BAM), per J1939-21:
  TP.CM (PGN 60416): byte 1 = 0x20 (BAM), bytes 2-3 = total message size
                     (little-endian), byte 4 = number of packets,
                     byte 5 = 0xFF reserved, bytes 6-8 = PGN (little-endian)
  TP.DT (PGN 60160): byte 1 = sequence number (1..N), bytes 2-8 = payload

Only BAM (broadcast) is implemented; the RTS/CTS connection mode used
for destination-specific transfers is future work and is flagged, not
silently mishandled.
"""

import time

from .j1939 import encode_can_id, decode_can_id, TP_CM, TP_DT

BAM_CONTROL = 0x20
DT_BYTES_PER_PACKET = 7


def build_bam_frames(pgn, source, payload, priority=6):
    """Split a payload into TP.CM + TP.DT frames for broadcast."""
    payload = bytes(payload)
    total = len(payload)
    n_packets = (total + DT_BYTES_PER_PACKET - 1) // DT_BYTES_PER_PACKET
    cm = bytes([BAM_CONTROL,
                total & 0xFF, (total >> 8) & 0xFF,
                n_packets, 0xFF,
                pgn & 0xFF, (pgn >> 8) & 0xFF, (pgn >> 16) & 0xFF])
    frames = [(encode_can_id(priority, TP_CM, source, 0xFF), cm)]
    for i in range(n_packets):
        chunk = payload[i * DT_BYTES_PER_PACKET:(i + 1) * DT_BYTES_PER_PACKET]
        dt = bytes([i + 1]) + chunk
        frames.append((encode_can_id(priority, TP_DT, source, 0xFF), dt))
    return frames


class BamReassembler:
    """Reassemble incoming BAM transfers. Feed every frame; a completed
    transfer is returned as (pgn, source_address, payload_bytes)."""

    def __init__(self, timeout=1.0):
        # timeout: seconds without progress before a session is dropped.
        # J1939-21 defines 750 ms (Tr) for connection mode; BAM has no
        # mandated timeout, so 1.0 s is our documented choice.
        self.timeout = timeout
        self.sessions = {}  # (source, pgn) -> session dict

    def _sweep(self, now):
        stale = [k for k, s in self.sessions.items()
                 if now - s["last"] > self.timeout]
        for k in stale:
            del self.sessions[k]

    def feed(self, can_id, data, now=None):
        now = time.time() if now is None else now
        self._sweep(now)
        data = bytes(data)
        info = decode_can_id(can_id)
        pgn, src = info["pgn"], info["source"]

        if pgn == TP_CM and len(data) >= 8 and data[0] == BAM_CONTROL:
            total = data[1] | (data[2] << 8)
            n_packets = data[3]
            msg_pgn = data[5] | (data[6] << 8) | (data[7] << 16)
            if total == 0 or n_packets == 0:
                return None  # malformed announce; ignore
            self.sessions[(src, msg_pgn)] = {
                "total": total, "n_packets": n_packets,
                "next_seq": 1, "chunks": [], "last": now,
            }
            return None

        if pgn == TP_DT and len(data) >= 1:
            seq = data[0]
            # TP.DT carries no PGN; match by source + expected sequence.
            match = None
            for (s, mp), sess in self.sessions.items():
                if s == src and sess["next_seq"] == seq:
                    match = (s, mp)
                    break
            if match is None:
                return None  # no session expecting this packet
            sess = self.sessions[match]
            sess["chunks"].append(data[1:])
            sess["next_seq"] += 1
            sess["last"] = now
            if sess["next_seq"] > sess["n_packets"]:
                payload = b"".join(sess["chunks"])[:sess["total"]]
                del self.sessions[match]
                if len(payload) != sess["total"]:
                    return None  # short transfer; treat as failed
                return (match[1], match[0], payload)
            return None

        return None
