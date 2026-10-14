"""Tests for the health-threshold profiles. Run: python tests/test_thresholds.py"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from truckdiag.thresholds import check, PROFILES


def test_oil_pressure_gen5():
    ok, _ = check(100, 345, "dd15-gen5")      # ~50 psi
    assert ok == "ok", ok
    s, _ = check(100, 240, "dd15-gen5")       # ~35 psi
    assert s == "warn", s
    s, msg = check(100, 150, "dd15-gen5")     # ~22 psi
    assert s == "alert", s
    assert "25" in msg or "172" in msg, msg


def test_oil_pressure_older_profile_differs():
    # 120 kPa (~17 psi) is an alert on Gen 5 but only a warn pre-Gen 5
    assert check(100, 120, "dd15-gen5")[0] == "alert"
    assert check(100, 120, "dd15-older")[0] == "warn"


def test_coolant_temp():
    assert check(110, 85, "dd15-gen5")[0] == "ok"
    assert check(110, 105, "dd15-gen5")[0] == "warn"
    s, _ = check(110, 115, "dd15-gen5")
    assert s == "alert", s


def test_def_level():
    assert check(1761, 62, "dd15-gen5")[0] == "ok"
    assert check(1761, 12, "dd15-gen5")[0] == "warn"
    assert check(1761, 9, "dd15-gen5")[0] == "alert"


def test_battery():
    assert check(168, 14.1)[0] == "ok"
    assert check(168, 11.5)[0] == "warn"
    assert check(168, 15.5)[0] == "warn"


def test_no_band_no_opinion():
    # boost pressure has no verified band: never flagged
    assert check(102, 10) == ("ok", "")
    assert check(102, 400) == ("ok", "")
    assert check(175, 200) == ("ok", "")  # oil temp: no verified band
    assert check(190, None) == ("ok", "")


def test_bands_carry_sources():
    for profile in PROFILES.values():
        for spn, band in profile["thresholds"].items():
            assert band.get("source"), (spn, band)
            assert band.get("confidence") in ("high", "medium", "low"), band


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print("%d tests passed" % len(tests))
