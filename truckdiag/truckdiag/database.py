"""Parameter database: which bytes of which PGN mean what.

Field layouts per SAE J1939DA (Digital Annex, September 2023), extracted
2026-09-26 from the user's college course material (SAE-donated for
education). The DA spreadsheet is the machine-readable authority: every
SPN below was pulled with its byte/bit position, length, scaling,
offset, unit, and state enumerations, replacing the earlier layouts
that had been cross-checked 2026-09-11 against third-party simulator
docs. That upgrade caught two real errors the simulator spec had
introduced:
  * EFL/P1 (65263): oil level is byte 3, not byte 2 (byte 2 is SPN 22
    crankcase blow-by); coolant pressure is 1 byte at byte 7, not
    2 bytes at bytes 5-6 (those are SPN 101 crankcase pressure);
    coolant level is byte 8, not byte 7.
  * VD (65248): bytes 1-4 are SPN 244 trip distance and bytes 5-8 are
    SPN 245 total vehicle distance (SPN 250 was never in this PGN).
DPF PGNs 64891/64892/64946 are now fully decoded, including the bit-
level state fields of DPFC1 (64892) and AT1IMG (64946).

A raw value of all-ones means "not available" per the standard.
Bit positions within a byte are numbered 1 (LSB) .. 8 (MSB) per J1939.

PGN 65110 (DEF tank level) SPN 1761 at 0.4 %/bit is confirmed by the DA
(the 0.1 %/bit figure in one Woodward doc is inconsistent with the
1-byte 0-100% field and the SAE tank-level convention).
"""

# Shared state table for the DPFC1 regen-inhibit reasons (SPNs 3702-3717,
# 5629, 10153): 00 = not inhibited, 01 = inhibited, 10 = reserved,
# 11 = not available.
_INH = {0: "not inhibited", 1: "inhibited"}

PGN_DB = {
    61444: {
        "name": "EEC1 - Electronic Engine Controller 1",
        "fields": [
            {"spn": 512, "name": "Driver demand engine percent torque", "start": 1, "length": 1, "scale": 1, "offset": -125, "unit": "%"},
            {"spn": 513, "name": "Actual engine percent torque", "start": 2, "length": 1, "scale": 1, "offset": -125, "unit": "%"},
            {"spn": 190, "name": "Engine speed", "start": 3, "length": 2, "scale": 0.125, "offset": 0, "unit": "rpm"},
        ],
    },
    61443: {
        "name": "EEC2 - Electronic Engine Controller 2",
        "fields": [
            {"spn": 91, "name": "Accelerator pedal position 1", "start": 1, "length": 1, "scale": 0.4, "offset": 0, "unit": "%"},
            {"spn": 92, "name": "Engine percent load at current speed", "start": 2, "length": 1, "scale": 1, "offset": 0, "unit": "%"},
        ],
    },
    65262: {
        "name": "ET1 - Engine Temperature 1",
        "fields": [
            {"spn": 110, "name": "Engine coolant temperature", "start": 0, "length": 1, "scale": 1, "offset": -40, "unit": "C"},
            {"spn": 174, "name": "Engine fuel temperature 1", "start": 1, "length": 1, "scale": 1, "offset": -40, "unit": "C"},
            {"spn": 175, "name": "Engine oil temperature 1", "start": 2, "length": 2, "scale": 0.03125, "offset": -273, "unit": "C"},
        ],
    },
    65263: {
        # Byte 2 is SPN 22 (extended crankcase blow-by pressure) and
        # bytes 5-6 are SPN 101 (crankcase pressure) -- not decoded here.
        "name": "EFL/P1 - Engine Fluid Level/Pressure 1",
        "fields": [
            {"spn": 94, "name": "Engine fuel delivery pressure", "start": 0, "length": 1, "scale": 4, "offset": 0, "unit": "kPa"},
            {"spn": 98, "name": "Engine oil level", "start": 2, "length": 1, "scale": 0.4, "offset": 0, "unit": "%"},
            {"spn": 100, "name": "Engine oil pressure", "start": 3, "length": 1, "scale": 4, "offset": 0, "unit": "kPa"},
            {"spn": 109, "name": "Engine coolant pressure", "start": 6, "length": 1, "scale": 2, "offset": 0, "unit": "kPa"},
            {"spn": 111, "name": "Engine coolant level", "start": 7, "length": 1, "scale": 0.4, "offset": 0, "unit": "%"},
        ],
    },
    65266: {
        "name": "FE - Fuel Economy",
        "fields": [
            {"spn": 183, "name": "Engine fuel rate", "start": 0, "length": 2, "scale": 0.05, "offset": 0, "unit": "L/h"},
            {"spn": 184, "name": "Engine instantaneous fuel economy", "start": 2, "length": 2, "scale": 1 / 512, "offset": 0, "unit": "km/L"},
            {"spn": 185, "name": "Engine average fuel economy", "start": 4, "length": 2, "scale": 1 / 512, "offset": 0, "unit": "km/L"},
        ],
    },
    65270: {
        "name": "IC1 - Inlet/Exhaust Conditions 1",
        "fields": [
            {"spn": 102, "name": "Engine turbocharger boost pressure", "start": 1, "length": 1, "scale": 2, "offset": 0, "unit": "kPa"},
            {"spn": 105, "name": "Engine intake manifold 1 temperature", "start": 2, "length": 1, "scale": 1, "offset": -40, "unit": "C"},
        ],
    },
    65271: {
        "name": "VEP1 - Vehicle Electrical Power 1",
        "fields": [
            {"spn": 168, "name": "Battery potential / power input 1", "start": 4, "length": 2, "scale": 0.05, "offset": 0, "unit": "V"},
        ],
    },
    65265: {
        "name": "CCVS - Cruise Control / Vehicle Speed 1",
        "fields": [
            {"spn": 84, "name": "Wheel-based vehicle speed", "start": 1, "length": 2, "scale": 1 / 256, "offset": 0, "unit": "km/h"},
        ],
    },
    65248: {
        "name": "VD - Vehicle Distance",
        "fields": [
            {"spn": 244, "name": "Trip distance", "start": 0, "length": 4, "scale": 0.125, "offset": 0, "unit": "km"},
            {"spn": 245, "name": "Total vehicle distance", "start": 4, "length": 4, "scale": 0.125, "offset": 0, "unit": "km"},
        ],
    },
    65253: {
        "name": "HOURS - Engine Hours, Revolutions",
        "fields": [
            {"spn": 247, "name": "Total engine hours", "start": 0, "length": 4, "scale": 0.05, "offset": 0, "unit": "hr"},
        ],
    },
    65110: {
        # "AT1T1I1" - Aftertreatment 1 DEF Tank Information.
        # SPN 1761 at 0.4 %/bit confirmed by the J1939DA (Sep 2023).
        "name": "AT1T1I1 - Aftertreatment 1 DEF Tank Information",
        "fields": [
            {"spn": 1761, "name": "Aftertreatment 1 DEF tank level", "start": 0, "length": 1, "scale": 0.4, "offset": 0, "unit": "%"},
            {"spn": 3031, "name": "Aftertreatment 1 DEF tank temperature", "start": 1, "length": 1, "scale": 1, "offset": -40, "unit": "C"},
            {"spn": 5245, "name": "DEF low level inducement", "byte": 4, "bit": 6, "bits": 3, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "Off - adequate DEF", 1: "On solid - low DEF", 4: "Fast blink - DEF very low"}},
            {"spn": 5246, "name": "SCR inducement severity", "byte": 5, "bit": 6, "bits": 3, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "No inducement", 1: "Level 1 - DEF warning", 2: "Level 2 - DEF warning",
                        3: "Level 3 - engine derate", 4: "Level 4 - severe inducement pre-trigger",
                        5: "Level 5 - severe inducement", 6: "Temporary inducement override"}},
        ],
    },
    64891: {
        # "AT1S1" - Aftertreatment 1 Service 1 (on request): soot/ash.
        "name": "AT1S1 - Aftertreatment 1 DPF Information",
        "fields": [
            {"spn": 3719, "name": "DPF 1 soot load", "start": 0, "length": 1, "scale": 1, "offset": 0, "unit": "%"},
            {"spn": 3720, "name": "DPF 1 ash load", "start": 1, "length": 1, "scale": 1, "offset": 0, "unit": "%"},
            {"spn": 3721, "name": "DPF 1 time since last active regen", "start": 2, "length": 4, "scale": 1, "offset": 0, "unit": "s"},
            {"spn": 5466, "name": "DPF 1 soot load regen threshold", "start": 6, "length": 2, "scale": 0.0025, "offset": 0, "unit": "%"},
        ],
    },
    64892: {
        # "DPFC1" - DPF Control 1: lamp commands + regen inhibit reasons.
        # Bit fields: "byte" is 0-based, "bit" is 1-based LSB per J1939.
        "name": "DPFC1 - DPF Control 1",
        "fields": [
            {"spn": 3697, "name": "DPF lamp command", "byte": 0, "bit": 1, "bits": 3, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "Off", 1: "On - solid", 4: "On - fast blink (1 Hz)", 5: "On - very fast blink"}},
            {"spn": 8857, "name": "DPF active regen readiness", "byte": 0, "bit": 4, "bits": 2, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "Not ready for initiation", 1: "Ready for initiation"}},
            {"spn": 3699, "name": "DPF passive regen status", "byte": 1, "bit": 1, "bits": 2, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "not active", 1: "active"}},
            {"spn": 3700, "name": "DPF active regen status", "byte": 1, "bit": 3, "bits": 2, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "not active", 1: "active", 2: "regen needed - auto regen imminent"}},
            {"spn": 3701, "name": "DPF soot status", "byte": 1, "bit": 5, "bits": 3, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "Regeneration not needed", 1: "Regen needed - lowest level",
                        2: "Regen needed - moderate level", 3: "Regen needed - highest level"}},
            {"spn": 3702, "name": "Regen inhibited status", "byte": 2, "bit": 1, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3703, "name": "Regen inhibited - inhibit switch", "byte": 2, "bit": 3, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3704, "name": "Regen inhibited - clutch disengaged", "byte": 2, "bit": 5, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3705, "name": "Regen inhibited - service brake active", "byte": 2, "bit": 7, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3706, "name": "Regen inhibited - PTO active", "byte": 3, "bit": 1, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3707, "name": "Regen inhibited - accelerator off idle", "byte": 3, "bit": 3, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3708, "name": "Regen inhibited - out of neutral", "byte": 3, "bit": 5, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3709, "name": "Regen inhibited - speed above allowed", "byte": 3, "bit": 7, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3710, "name": "Regen inhibited - parking brake not set", "byte": 4, "bit": 1, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3711, "name": "Regen inhibited - low exhaust temp", "byte": 4, "bit": 3, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3712, "name": "Regen inhibited - system fault active", "byte": 4, "bit": 5, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3713, "name": "Regen inhibited - system timeout", "byte": 4, "bit": 7, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3714, "name": "Regen inhibited - temporary lockout", "byte": 5, "bit": 1, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3715, "name": "Regen inhibited - permanent lockout", "byte": 5, "bit": 3, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3716, "name": "Regen inhibited - engine not warmed up", "byte": 5, "bit": 5, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3717, "name": "Regen inhibited - speed below allowed", "byte": 5, "bit": 7, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3718, "name": "Auto active regen initiation", "byte": 6, "bit": 1, "bits": 2, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "not enabled", 1: "enabled"}},
            {"spn": 3698, "name": "Exhaust high temp lamp command", "byte": 6, "bit": 3, "bits": 3, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "Off", 1: "On - solid"}},
            {"spn": 4175, "name": "DPF active regen forced status", "byte": 6, "bit": 6, "bits": 3, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "Not Active", 1: "Forced by switch", 2: "Forced by service tool"}},
            {"spn": 5504, "name": "Hydrocarbon doser purging", "byte": 7, "bit": 1, "bits": 2, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "Purging not enabled", 1: "enabled - less urgent", 2: "enabled - urgent"}},
            {"spn": 5629, "name": "Regen inhibited (5629)", "byte": 7, "bit": 3, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
            {"spn": 3750, "name": "Regen conditions not met", "byte": 7, "bit": 5, "bits": 2, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "regen not inhibited", 1: "regen inhibited"}},
            {"spn": 10153, "name": "Regen inhibited (10153)", "byte": 7, "bit": 7, "bits": 2, "scale": 1, "offset": 0, "unit": "", "states": _INH},
        ],
    },
    65188: {
        # "ET2" - Engine Temperature 2 (1 s broadcast): EGR health.
        "name": "ET2 - Engine Temperature 2",
        "fields": [
            {"spn": 1135, "name": "Engine oil temperature 2", "start": 0, "length": 2, "scale": 0.03125, "offset": -273, "unit": "C"},
            {"spn": 1136, "name": "Engine ECU temperature", "start": 2, "length": 2, "scale": 0.03125, "offset": -273, "unit": "C"},
            {"spn": 411, "name": "EGR differential pressure", "start": 4, "length": 2, "scale": 0.0078125, "offset": -250, "unit": "kPa"},
            {"spn": 412, "name": "EGR temperature", "start": 6, "length": 2, "scale": 0.03125, "offset": -273, "unit": "C"},
        ],
    },
    65245: {
        # "TC" - Turbocharger (1 s broadcast).
        "name": "TC - Turbocharger",
        "fields": [
            {"spn": 104, "name": "Turbocharger lube oil pressure", "start": 0, "length": 1, "scale": 4, "offset": 0, "unit": "kPa"},
            {"spn": 103, "name": "Turbocharger 1 speed", "start": 1, "length": 2, "scale": 4, "offset": 0, "unit": "rpm"},
            {"spn": 1665, "name": "Turbocharger oil level switch", "byte": 3, "bit": 7, "bits": 2, "scale": 1, "offset": 0, "unit": "",
             "states": {0: "No oil at turbocharger", 1: "Oil present at turbocharger", 2: "Error"}},
            {"spn": 5980, "name": "Turbocharger differential speed", "start": 4, "length": 2, "scale": 4, "offset": 0, "unit": "rpm"},
        ],
    },
    64946: {        # "AT1IMG" - Aftertreatment 1 Intake Manifold Gas (temperatures +
        # DPF differential pressure).
        "name": "AT1IMG - Aftertreatment 1 DPF Temperatures/Pressure",
        "fields": [
            {"spn": 3249, "name": "Aftertreatment 1 exhaust temperature 2", "start": 0, "length": 2, "scale": 0.03125, "offset": -273, "unit": "C"},
            {"spn": 3250, "name": "DPF intermediate temperature", "start": 2, "length": 2, "scale": 0.03125, "offset": -273, "unit": "C"},
            {"spn": 3251, "name": "DPF differential pressure", "start": 4, "length": 2, "scale": 0.1, "offset": 0, "unit": "kPa"},
            {"spn": 3252, "name": "Exhaust temp 2 preliminary FMI", "byte": 6, "bit": 1, "bits": 5, "scale": 1, "offset": 0, "unit": ""},
            {"spn": 3253, "name": "DPF diff pressure preliminary FMI", "byte": 6, "bit": 6, "bits": 5, "scale": 1, "offset": 0, "unit": ""},
            {"spn": 3254, "name": "DPF intermediate temp preliminary FMI", "byte": 7, "bit": 3, "bits": 5, "scale": 1, "offset": 0, "unit": ""},
        ],
    },
}

# Recognized but not yet decoded: the PGN number is verified, but the
# byte layout is not in our reference set, so these stay raw rather
# than guessed.
KNOWN_UNDECODED = {
    61442: "ETC1 - Electronic Transmission Controller 1",
    61445: "ETC2 - Electronic Transmission Controller 2 (selected/current gear)",
    65272: "TF1 - Transmission Fluids (oil temp/pressure)",
    65260: "VI - Vehicle Identification (VIN, multi-packet)",
    65227: "DM2 - Previously active DTCs",
    65229: "DM4 - Freeze frame",
}

# Common SPN names for the DTC reader.
SPN_NAMES = {
    84: "Wheel-based vehicle speed", 91: "Accelerator pedal position 1",
    92: "Engine percent load at current speed", 94: "Engine fuel delivery pressure",
    96: "Fuel level 1", 98: "Engine oil level", 100: "Engine oil pressure",
    102: "Engine turbocharger boost pressure", 105: "Engine intake manifold 1 temperature",
    108: "Barometric pressure", 109: "Engine coolant pressure",
    110: "Engine coolant temperature", 111: "Engine coolant level",
    168: "Battery potential / power input 1", 174: "Engine fuel temperature 1",
    175: "Engine oil temperature 1", 177: "Transmission oil temperature",
    183: "Engine fuel rate", 184: "Engine instantaneous fuel economy",
    185: "Engine average fuel economy", 190: "Engine speed",
    247: "Total engine hours", 512: "Driver demand engine percent torque",
    513: "Actual engine percent torque",
    # Aftertreatment (verified SPN names; used by the DTC reader -- this
    # is how DPF/DEF problems actually surface on the bus).
    1761: "Aftertreatment 1 DEF tank level",
    3031: "Aftertreatment 1 DEF tank temperature",
    103: "Engine turbocharger 1 speed",
    104: "Engine turbocharger lube oil pressure",
    411: "EGR differential pressure",
    412: "EGR temperature",
    1135: "Engine oil temperature 2",
    1136: "Engine ECU temperature",
    1665: "Turbocharger oil level switch",
    5245: "DEF low level inducement",
    5246: "SCR operator inducement severity",
    5980: "Turbocharger differential speed",
    3216: "Aftertreatment 1 intake NOx",
    3226: "Aftertreatment 1 outlet NOx",
    3249: "Aftertreatment 1 exhaust temperature 2",
    3250: "DPF intermediate temperature",
    3251: "DPF differential pressure",
    3252: "Exhaust temp 2 preliminary FMI",
    3253: "DPF diff pressure preliminary FMI",
    3254: "DPF intermediate temp preliminary FMI",
    3364: "DEF quality",
    3697: "DPF lamp command",
    3698: "Exhaust system high temperature lamp command",
    3699: "DPF passive regeneration status",
    3700: "DPF active regeneration status",
    3701: "DPF regeneration needed",
    3702: "DPF active regeneration inhibited status",
    3703: "DPF regen inhibited - inhibit switch",
    3704: "DPF regen inhibited - clutch disengaged",
    3705: "DPF regen inhibited - service brake active",
    3706: "DPF regen inhibited - PTO active",
    3707: "DPF regen inhibited - accelerator off idle",
    3708: "DPF regen inhibited - out of neutral",
    3709: "DPF regen inhibited - speed above allowed",
    3710: "DPF regen inhibited - parking brake not set",
    3711: "DPF regen inhibited - low exhaust temp",
    3712: "DPF regen inhibited - system fault active",
    3713: "DPF regen inhibited - system timeout",
    3714: "DPF regen inhibited - temporary lockout",
    3715: "DPF regen inhibited - permanent lockout",
    3716: "DPF regen inhibited - engine not warmed up",
    3717: "DPF regen inhibited - speed below allowed",
    3718: "DPF auto active regen initiation",
    3719: "DPF 1 soot load percent",
    3720: "DPF 1 ash load percent",
    3721: "DPF 1 time since last active regeneration",
    3750: "DPF active regen conditions not met",
    4175: "DPF active regen forced status",
    5245: "SCR inducement (DEF)",
    5246: "SCR inducement severity",
    5466: "DPF 1 soot load threshold",
    5504: "Hydrocarbon doser purging",
    5629: "DPF regen inhibited (5629)",
    8857: "DPF active regen readiness",
    10153: "DPF regen inhibited (10153)",
}

# FMI = Failure Mode Identifier, per SAE J1939-73.
FMI_DESCRIPTIONS = {
    0: "Data valid but above normal operating range - most severe",
    1: "Data valid but below normal operating range - most severe",
    2: "Data erratic, intermittent, or incorrect",
    3: "Voltage above normal, or shorted to high source",
    4: "Voltage below normal, or shorted to low source",
    5: "Current below normal, or open circuit",
    6: "Current above normal, or grounded circuit",
    7: "Mechanical system not responding or out of adjustment",
    8: "Abnormal frequency or pulse width or period",
    9: "Abnormal update rate",
    10: "Abnormal rate of change",
    11: "Root cause not known",
    12: "Bad intelligent device or component",
    13: "Out of calibration",
    14: "Special instructions",
    15: "Data valid but above normal operating range - least severe",
    16: "Data valid but above normal operating range - moderately severe",
    17: "Data valid but below normal operating range - least severe",
    18: "Data valid but below normal operating range - moderately severe",
    19: "Received network data in error",
    20: "Data drifted high",
    21: "Data drifted low",
    31: "Condition exists",
}
