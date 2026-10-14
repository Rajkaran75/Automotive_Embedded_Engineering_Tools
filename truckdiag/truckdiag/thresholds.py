"""Health thresholds: verified OEM bands for the DD15, labeled by source.

Every band carries its source and a confidence grade. Anything without a
verified band (boost pressure, oil temperature, fuel rate, ...) gets no
threshold at all -- the tool says nothing rather than invent a limit.

Units are the decoded units used elsewhere in the tool (kPa, C, %, V).
Source documents used imperial units; conversions are shown in comments.

Profiles: pick the one matching the engine. When in doubt, the monitor
defaults to dd15-gen5 and says so on screen.
"""

PROFILES = {
    "dd15-gen5": {
        "label": "Detroit DD15 Gen 5 (GHG21+, roughly 2021 and newer)",
        "thresholds": {
            # SPN 100, engine oil pressure. Gen 5 operator manual: 50 psi
            # normal, 25 psi = low (check lamp), 0 psi = very low (stop lamp).
            100: {"param": "Engine oil pressure", "unit": "kPa",
                  "warn_low": 276,    # 40 psi, interpolated; medium confidence
                  "alert_low": 172,   # 25 psi, check-lamp threshold; high
                  "source": "Detroit DD Platform Gen 5 operator manual "
                            "(50 psi normal / 25 psi low / 0 psi very low)",
                  "confidence": "high"},
            # SPN 110, coolant temperature. Freightliner/Detroit: normal
            # 175-195 F (79-91 C); DD13/15/16 max 234 F (112 C).
            110: {"param": "Engine coolant temperature", "unit": "C",
                  "warn_high": 100,   # 212 F, interpolated; medium
                  "alert_high": 112,  # 234 F, published maximum; high
                  "source": "Freightliner/Detroit driver literature "
                            "(normal 175-195 F; max 234 F)",
                  "confidence": "high"},
            # SPN 1761, DEF tank level. Low-DEF warning at ~10%; running
            # dry risks derate.
            1761: {"param": "DEF tank level", "unit": "%",
                   "warn_low": 15,
                   "alert_low": 10,
                   "source": "Freightliner operator manual (low-DEF warning "
                             "at approx 10%)",
                   "confidence": "medium"},
            # SPN 168, battery potential. Generic 12 V charging band --
            # NOT a Detroit-published threshold.
            168: {"param": "Battery potential", "unit": "V",
                  "warn_low": 12.0, "warn_high": 15.0,
                  "source": "generic 12 V automotive charging band; "
                            "not DD15-specific",
                  "confidence": "low"},
        },
    },
    "dd15-older": {
        "label": "Detroit DD15 pre-Gen 5 (GHG14/GHG17, roughly pre-2021)",
        "thresholds": {
            # Older Detroit literature: hot minimums ~14 psi at idle and
            # ~55 psi at rated speed. Without rpm context we alert at the
            # idle minimum; under load, expect ~55 psi.
            100: {"param": "Engine oil pressure", "unit": "kPa",
                  "warn_low": 138,    # 20 psi; medium
                  "alert_low": 97,    # 14 psi hot-idle minimum; high
                  "note": "rated-speed minimum is ~55 psi (379 kPa)",
                  "source": "Detroit pre-Gen 5 literature (14 psi hot idle "
                            "min / 55 psi rated min)",
                  "confidence": "medium"},
            110: {"param": "Engine coolant temperature", "unit": "C",
                  "warn_high": 100,
                  "alert_high": 112,
                  "source": "Freightliner/Detroit driver literature "
                            "(normal 175-195 F; DD13/15/16 max 234 F)",
                  "confidence": "high"},
            1761: {"param": "DEF tank level", "unit": "%",
                   "warn_low": 15,
                   "alert_low": 10,
                   "source": "Freightliner operator manual (low-DEF warning "
                             "at approx 10%)",
                   "confidence": "medium"},
            168: {"param": "Battery potential", "unit": "V",
                  "warn_low": 12.0, "warn_high": 15.0,
                  "source": "generic 12 V automotive charging band; "
                            "not DD15-specific",
                  "confidence": "low"},
        },
    },
}

DEFAULT_PROFILE = "dd15-gen5"


def check(spn, value, profile=DEFAULT_PROFILE):
    """Check a decoded value against the profile.

    Returns (status, message); status is "ok", "warn", or "alert".
    SPNs with no verified band always return "ok" with an empty message.
    """
    if value is None:
        return ("ok", "")
    band = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])["thresholds"].get(spn)
    if band is None:
        return ("ok", "")
    name = band["param"]
    unit = band["unit"]
    if "warn_low" in band and value < band["warn_low"]:
        alert_at = band.get("alert_low")
        level = "alert" if alert_at is not None and value < alert_at else "warn"
        limit = alert_at if level == "alert" else band["warn_low"]
        return (level, "%s %.1f %s below %s threshold %.0f %s (%s)" %
                (name, value, unit, level, limit, unit, band["source"]))
    if "warn_high" in band and value > band["warn_high"]:
        alert_at = band.get("alert_high")
        level = "alert" if alert_at is not None and value > alert_at else "warn"
        limit = alert_at if level == "alert" else band["warn_high"]
        return (level, "%s %.1f %s above %s threshold %.0f %s (%s)" %
                (name, value, unit, level, limit, unit, band["source"]))
    return ("ok", "")
