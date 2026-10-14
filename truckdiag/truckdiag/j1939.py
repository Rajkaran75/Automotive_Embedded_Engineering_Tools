"""SAE J1939 29-bit CAN identifier handling.

A J1939 CAN id packs: priority (3 bits) | EDP | DP | PF | PS | SA.
The PGN (parameter group number) is derived from DP/PF/PS:
  - PF < 240  -> PDU1, destination-specific: PGN = DP:PF, PS = destination
  - PF >= 240 -> PDU2, broadcast:             PGN = DP:PF:PS
"""

PGN_REQUEST = 59904   # 0xEA00 - request a PGN from an ECU
ACKM = 59392        # 0xE800 - acknowledgment (ACK/NACK/access-denied)
TP_CM = 60416       # 0xEC00 - transport protocol, connection management
TP_DT = 60160       # 0xEB00 - transport protocol, data transfer
DM1 = 65226           # 0xFECA - active diagnostic trouble codes (broadcast ~1/s)
DM2 = 65227           # 0xFECB - previously active DTCs (on request)
DM3 = 65228           # 0xFECC - clear inactive DTCs
DM4 = 65229           # 0xFECD - freeze frame
DM11 = 65235          # 0xFED3 - clear active DTCs

TOOL_SOURCE_ADDRESS = 0xF9  # 249, conventional pick for a service tool


def decode_can_id(can_id):
    """Split a 29-bit CAN id into its J1939 fields."""
    priority = (can_id >> 26) & 0x7
    dp = (can_id >> 24) & 0x1
    pf = (can_id >> 16) & 0xFF
    ps = (can_id >> 8) & 0xFF
    sa = can_id & 0xFF
    if pf < 240:
        pgn = (dp << 16) | (pf << 8)
        destination = ps
    else:
        pgn = (dp << 16) | (pf << 8) | ps
        destination = None
    return {
        "priority": priority,
        "pgn": pgn,
        "source": sa,
        "destination": destination,
    }


def encode_can_id(priority, pgn, source, destination=0xFF):
    """Build a 29-bit CAN id from J1939 fields."""
    dp = (pgn >> 16) & 0x1
    pf = (pgn >> 8) & 0xFF
    ps = destination if pf < 240 else (pgn & 0xFF)
    return (((priority & 0x7) << 26) | ((dp & 0x1) << 24)
            | (pf << 16) | (ps << 8) | (source & 0xFF))


def request_pgn_frame(pgn, source=TOOL_SOURCE_ADDRESS, destination=0xFF):
    """Build a PGN-request frame (PGN 59904, 3 data bytes = PGN, little-endian)."""
    can_id = encode_can_id(6, PGN_REQUEST, source, destination)
    data = bytes([pgn & 0xFF, (pgn >> 8) & 0xFF, (pgn >> 16) & 0xFF])
    return can_id, data


def clear_dtcs_frame(which="inactive", source=TOOL_SOURCE_ADDRESS):
    """Build a DTC-clear frame. 'inactive' -> DM3, 'active' -> DM11 (broadcast)."""
    pgn = DM3 if which == "inactive" else DM11
    return encode_can_id(6, pgn, source), b""


# PGN 59392 Acknowledgment, per J1939-21:
#   byte 1: control byte (0=ACK, 1=NACK, 2=access denied, 3=cannot respond)
#   byte 2: group function value (0xFF if not applicable)
#   bytes 3-4: reserved (0xFF)
#   byte 5: address acknowledged
#   bytes 6-8: PGN of the requested message, little-endian
ACK_CONTROLS = {
    0: "ACK - positive acknowledgment",
    1: "NACK - negative acknowledgment (PGN not supported / refused)",
    2: "Access denied",
    3: "Cannot respond at this time",
}


def parse_acknowledgment(data):
    """Parse a PGN 59392 acknowledgment frame."""
    data = bytes(data)
    if len(data) < 8:
        return None
    control = data[0]
    pgn = data[5] | (data[6] << 8) | (data[7] << 16)
    return {
        "control": control,
        "control_name": ACK_CONTROLS.get(control, "Unknown control byte %d" % control),
        "group_function": data[1],
        "address": data[4],
        "pgn": pgn,
    }


def acknowledgment_frame(control, pgn, source, address=0xFF):
    """Build a PGN 59392 acknowledgment frame (used by the simulator)."""
    can_id = encode_can_id(6, ACKM, source, address)
    data = bytes([control & 0xFF, 0xFF, 0xFF, 0xFF, address & 0xFF,
                  pgn & 0xFF, (pgn >> 8) & 0xFF, (pgn >> 16) & 0xFF])
    return can_id, data
