"""Diagnostic trouble codes: parse DM1, build clear requests.

DM1 layout (SAE J1939-73), verified 2026-09-11 against two independent
J1939 references:
  byte 0: lamp status, TWO bits per lamp --
          bits 7-6 = malfunction indicator lamp,
          bits 5-4 = red stop lamp,
          bits 3-2 = amber warning lamp,
          bits 1-0 = protect lamp.
          00 = off, 01 = on, 10/11 = reserved (treated as not reported).
  byte 1: flash lamp status, same bit positions (01 = flashing).
  then 4 bytes per DTC:
    byte 0: SPN bits 7:0
    byte 1: SPN bits 15:8
    byte 2: bits 7:5 = SPN bits 18:16, bits 4:0 = FMI
    byte 3: bit 7 = SPN conversion method, bits 6:0 = occurrence count
  A 4-byte slot of all 0xFF is padding ("no fault here"), not a DTC.
  More DTCs than fit in 8 bytes arrive via TP.BAM multi-packet transfer;
  the caller reassembles those first (see truckdiag.transport).
"""

from .database import FMI_DESCRIPTIONS, SPN_NAMES

# (bit shift, lamp name) -- 2 bits per lamp, value 0b01 means on.
LAMPS = [(6, "Malfunction indicator lamp"),
         (4, "Red stop lamp"),
         (2, "Amber warning lamp"),
         (0, "Protect lamp")]


def _lamp_states(byte):
    on, flashing_unknown = [], []
    for shift, name in LAMPS:
        state = (byte >> shift) & 0x3
        if state == 0x1:
            on.append(name)
        elif state not in (0x0, 0x3):
            flashing_unknown.append(name)  # 0b10: reserved, report oddity
    return on, flashing_unknown


def parse_dm1(data):
    """Parse a DM1 payload into lamps + list of DTC dicts."""
    data = bytes(data)
    if len(data) < 2:
        return None
    lamps, _ = _lamp_states(data[0])
    flashing, _ = _lamp_states(data[1])
    dtcs = []
    i = 2
    while i + 4 <= len(data):
        slot = data[i:i + 4]
        i += 4
        if slot == b"\xff\xff\xff\xff":
            continue  # padding, not a fault
        b0, b1, b2, b3 = slot
        spn = b0 | (b1 << 8) | ((b2 >> 5) << 16)
        fmi = b2 & 0x1F
        occurrences = b3 & 0x7F  # bit 7 is the SPN conversion method
        dtcs.append({
            "spn": spn,
            "spn_name": SPN_NAMES.get(spn, "Unknown SPN"),
            "fmi": fmi,
            "fmi_text": FMI_DESCRIPTIONS.get(fmi, "Unknown FMI"),
            "occurrences": occurrences,
        })
    return {"lamps": lamps, "flashing": flashing, "dtcs": dtcs}


def format_dtc(d):
    return ("SPN %d (%s) / FMI %d (%s) x%d"
            % (d["spn"], d["spn_name"], d["fmi"], d["fmi_text"], d["occurrences"]))
