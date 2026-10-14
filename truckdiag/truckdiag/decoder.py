"""Decode raw J1939 frames into human-readable values."""

from .j1939 import decode_can_id
from .database import PGN_DB, KNOWN_UNDECODED


def _read_le(data, start, length):
    value = 0
    for i in range(length):
        value |= data[start + i] << (8 * i)
    return value


def _read_bits(data, byte, bit, nbits):
    """Read nbits starting at 1-based LSB `bit` of 0-based `byte`.

    J1939 numbers bits within a byte 1 (LSB) .. 8 (MSB); a field that
    spans bytes runs little-endian, so byte N bits 6-8 followed by
    byte N+1 bits 1-2 is a 5-bit field with the byte-N part as the
    low 3 bits.
    """
    value = 0
    for i in range(nbits):
        b = byte + (bit - 1 + i) // 8
        bi = (bit - 1 + i) % 8
        if b < len(data) and (data[b] >> bi) & 1:
            value |= (1 << i)
    return value


def decode_frame(can_id, data):
    """Decode one frame. Returns dict with pgn, source, name, values, raw hex.

    Fields whose raw value is all-ones are reported as None ("not available"
    per J1939). Unknown PGNs come back with raw hex and no values.
    """
    data = bytes(data)
    info = decode_can_id(can_id)
    pgn = info["pgn"]
    entry = PGN_DB.get(pgn)

    if entry is None:
        name = KNOWN_UNDECODED.get(pgn, "Unknown PGN %d (0x%X)" % (pgn, pgn))
        return {"pgn": pgn, "source": info["source"], "name": name,
                "values": [], "raw": data.hex()}

    values = []
    for f in entry["fields"]:
        if "bits" in f:
            # bit field: "byte" is 0-based, "bit" is 1-based LSB
            last = f["byte"] + (f["bit"] - 1 + f["bits"] - 1) // 8
            if last >= len(data):
                continue
            raw = _read_bits(data, f["byte"], f["bit"], f["bits"])
            all_ones = (1 << f["bits"]) - 1
        else:
            if f["start"] + f["length"] > len(data):
                continue
            raw = _read_le(data, f["start"], f["length"])
            all_ones = (1 << (8 * f["length"])) - 1
        if raw == all_ones:
            value, state = None, None  # not available
        else:
            state = f.get("states", {}).get(raw)
            value = raw * f["scale"] + f["offset"]
        values.append({"spn": f["spn"], "name": f["name"],
                       "value": value, "unit": f["unit"], "state": state})
    return {"pgn": pgn, "source": info["source"], "name": entry["name"],
            "values": values, "raw": data.hex()}


def format_value(v):
    if v.get("state"):
        return "%s: %s" % (v["name"], v["state"])
    if v["value"] is None:
        return "%s: n/a" % v["name"]
    return "%s: %.1f %s" % (v["name"], v["value"], v["unit"])
