"""Health rationale: what a value means and what to do about it.

Two kinds of knowledge live here, kept strictly separate:

  VERIFIED BANDS (thresholds.py) -- numeric normal/abnormal limits with a
      cited source and a confidence grade. Only a few SPNs have these.

  EXPLANATIONS (this module) -- plain-English "what it means / what to do".
      Every entry carries a "basis":
        "da-state"       -- meaning taken directly from the J1939DA state
                            table for that SPN; not an interpretation.
        "verified-band"  -- restates a cited band from thresholds.py.
        "general"        -- general diesel-engine knowledge. Sound but not
                            a cited OEM limit; never a numeric threshold.

Nothing here invents a numeric limit. When no verified band exists, the
entry says what to watch for (trends, context) instead of a number.
"""

# spn -> {"normal": ..., "abnormal": ..., "action": ..., "basis": ...}
SPN_GUIDE = {
    100: {"normal": "Varies with rpm and oil temperature; DD15 Gen 5 ~50 psi hot at rated speed.",
          "abnormal": "Below 25 psi hot = check lamp; 0 psi = stop lamp.",
          "action": "Alert: stop the engine, check oil level, do not drive. No oil pressure kills an engine in minutes.",
          "basis": "verified-band"},
    110: {"normal": "175-195 F (79-91 C) in normal operation.",
          "abnormal": "Above 212 F warn; 234 F is the published maximum.",
          "action": "Alert: stop safely, check coolant level and fan operation. Driving overheated warps heads and blows gaskets.",
          "basis": "verified-band"},
    98: {"normal": "Near 100%; small consumption between changes is normal.",
         "abnormal": "Steady decline = leak or burning oil; sudden drop = active leak.",
         "action": "Top up with the correct spec oil; if it keeps dropping, find the leak or check for blow-by before it becomes low pressure.",
         "basis": "general"},
    111: {"normal": "Near 100% and stable.",
          "abnormal": "Any steady drop = leak: hoses, radiator, EGR cooler, or head gasket.",
          "action": "Do not just keep topping up -- find the leak. Low coolant leads to overheating, which leads to head damage.",
          "basis": "general"},
    109: {"normal": "Builds as the engine warms; the pressure cap regulates it.",
          "abnormal": "Zero when hot = bad cap or leak; abnormally high = combustion gas entering the cooling system (head gasket).",
          "action": "High pressure with coolant loss and no visible leak: suspect head gasket -- get it tested, do not ignore.",
          "basis": "general"},
    94: {"normal": "Steady at a given load; the engine needs stable supply pressure.",
         "abnormal": "Low or sagging under load = fuel starvation: plugged filters, weak pump, air in fuel.",
         "action": "Replace fuel filters first -- cheapest fix and the most common cause. Then check for supply-side faults.",
         "basis": "general"},
    175: {"normal": "Tracks coolant, usually 10-20 C above it when working.",
          "abnormal": "Sustained far above coolant temp = cooling problem or chronic overloading.",
          "action": "Cross-check coolant temp and load; sustained high oil temp thins the oil film.",
          "basis": "general"},
    1135: {"normal": "Second oil temp sensor; should agree roughly with SPN 175.",
           "abnormal": "Large disagreement between the two oil temp readings = one sensor has failed.",
           "action": "Suspect the sensor, not the oil, when the two disagree.",
           "basis": "general"},
    1136: {"normal": "Near underhood temperature.",
           "abnormal": "Very high = airflow/cooling problem at the ECM.",
           "action": "Check ECM mounting and cooling airflow; heat kills electronics.",
           "basis": "general"},
    102: {"normal": "Near zero at idle, rises with load.",
          "abnormal": "Low under load = boost leak, turbo or actuator issue; check for related DTCs.",
          "action": "Inspect charge-air piping and clamps for leaks; then suspect turbo/actuator.",
          "basis": "general"},
    105: {"normal": "Above ambient; higher under sustained boost.",
          "abnormal": "Very high = charge air cooler not cooling (plugged or leaking).",
          "action": "Check the charge air cooler for blockage or leaks.",
          "basis": "general"},
    103: {"normal": "Varies enormously with load; near zero at idle, tens of thousands of rpm under load.",
          "abnormal": "No rise under load = turbo or actuator not responding (cross-check boost SPN 102 and DTCs).",
          "action": "If boost is also low, inspect turbo and VGT actuator; check for DTCs first.",
          "basis": "general"},
    104: {"normal": "Present whenever the engine runs.",
          "abnormal": "Low while engine oil pressure is fine = restricted turbo oil feed line.",
          "action": "Check the turbo oil supply line for kinking or blockage; turbo bearings die quickly without oil.",
          "basis": "general"},
    1665: {"normal": "'Oil present at turbocharger'.",
           "abnormal": "'No oil at turbocharger' or 'Error'.",
           "action": "'No oil': stop the engine -- the turbo will fail without oil. 'Error': check the switch circuit.",
           "basis": "da-state"},
    411: {"normal": "Varies with EGR flow.",
          "abnormal": "Stuck at zero while EGR should be flowing, or EGR-related DTCs present = plugged EGR path or failed sensor.",
          "action": "Cross-check EGR DTCs; a plugged EGR raises NOx and can trigger derate.",
          "basis": "general"},
    412: {"normal": "Hot when EGR is flowing -- several hundred C under load.",
          "abnormal": "Cold when it should be hot = EGR valve stuck closed; overheating = EGR cooler failing.",
          "action": "A failing EGR cooler leaks coolant into the intake -- watch coolant level (SPN 111) alongside this.",
          "basis": "general"},
    3719: {"normal": "Below the truck's own regen threshold (SPN 5466).",
           "abnormal": "At or above threshold = regeneration needed; climbing fast between regens = excess soot (oil consumption, injector issue, or failed regens).",
           "action": "Drive at highway speed/load to let an automatic regen complete; do not shut down mid-regen.",
           "basis": "general"},
    3720: {"normal": "Low and rising only very slowly over years -- ash is permanent.",
           "abnormal": "High = DPF near the end of its service life; regens getting frequent is the symptom.",
           "action": "Plan a DPF cleaning or replacement; this is a maintenance budget item, not a roadside fix.",
           "basis": "general"},
    3721: {"normal": "Hours to days between regens depending on duty cycle.",
           "abnormal": "Very short intervals = excessive soot production or regens not completing.",
           "action": "Check for incomplete-regen inhibit reasons and for engine faults causing excess soot.",
           "basis": "general"},
    3251: {"normal": "Low at idle, rising with exhaust flow and soot loading.",
           "abnormal": "High at idle or low flow = physically plugged DPF.",
           "action": "Compare with soot load %; if both high, the DPF needs service, not just a regen.",
           "basis": "general"},
    3249: {"normal": "Roughly 200-400 C in normal driving; 500-650 C during active regen.",
           "abnormal": "No temperature rise when a regen is commanded = dosing or ignition failure.",
           "action": "Check DEF/hydrocarbon dosing DTCs if regen is commanded but temps stay low.",
           "basis": "general"},
    3250: {"normal": "Follows exhaust temp 2; rises strongly during regen.",
           "abnormal": "Stays cold during regen = DPF not lighting off.",
           "action": "Same as SPN 3249 -- dosing or thermal problem.",
           "basis": "general"},
    3697: {"normal": "'Off' -- no lamp commanded.",
           "abnormal": "'On - solid' = regen needed soon; 'On - slow/fast blink' = regen needed now or a regen failed.",
           "action": "Solid: plan a highway run. Blinking: regen is overdue -- address immediately, check inhibit reasons.",
           "basis": "da-state"},
    3698: {"normal": "'Off'.",
           "abnormal": "On = exhaust is hot because of regen activity.",
           "action": "Caution around dry grass/debris; normal during regen, not a fault by itself.",
           "basis": "da-state"},
    3699: {"normal": "'No active regeneration'.",
           "abnormal": "n/a -- states describe which regen type is running.",
           "action": "If a regen runs very often, check soot/ash and inhibit reasons.",
           "basis": "da-state"},
    3700: {"normal": "'No regeneration needed'.",
           "abnormal": "'Regeneration needed -- will be initiated automatically' or '...imminent and automatic'.",
           "action": "Keep driving at load; the truck will handle it. Avoid shutting down.",
           "basis": "da-state"},
    3701: {"normal": "'No action required'.",
           "abnormal": "'Driver action required' = the truck needs a parked regen or a highway run.",
           "action": "Follow the dash prompt: parked regen in a safe spot or sustained highway driving.",
           "basis": "da-state"},
    3703: {"normal": "'Regeneration not inhibited by switch'.",
           "abnormal": "'Inhibited - inhibit switch'.",
           "action": "Someone flipped the dash regen-inhibit switch -- check its position. Common after shop visits.",
           "basis": "da-state"},
    3711: {"normal": "'Regeneration not inhibited by low exhaust temperature'.",
           "abnormal": "'Inhibited - low exhaust gas temperature'.",
           "action": "Duty cycle is too cold/light for regen; needs a highway run or a parked regen.",
           "basis": "da-state"},
    3712: {"normal": "'Regeneration not inhibited by system fault'.",
           "abnormal": "'Inhibited - system fault active'.",
           "action": "An active fault is blocking regen -- read DM1 faults first; fixing the fault unblocks regen.",
           "basis": "da-state"},
    3716: {"normal": "'Regeneration not inhibited by warm-up'.",
           "abnormal": "'Inhibited - warm-up mode'.",
           "action": "Normal when cold; should clear as the engine warms. If it never clears, check thermostat/coolant temp.",
           "basis": "da-state"},
    3750: {"normal": "'Regeneration conditions not inhibited'.",
           "abnormal": "'Inhibited - conditions not met for regeneration'.",
           "action": "Work through the specific inhibit reasons one by one; this is the summary flag.",
           "basis": "da-state"},
    4175: {"normal": "'No forced regeneration'.",
           "abnormal": "'Forced regeneration active' (by switch or tool).",
           "action": "Let it finish; do not shut down. Parked, parking brake set, away from combustibles.",
           "basis": "da-state"},
    1761: {"normal": "Above ~15%; low-DEF warning around 10%.",
           "abnormal": "Below 15% warn, below 10% alert -- running dry triggers derate.",
           "action": "Refill DEF. Never run dry: derate follows, and running dry can damage the SCR system.",
           "basis": "verified-band"},
    3031: {"normal": "Near ambient temperature.",
           "abnormal": "Near or below freezing without heater activity = frozen DEF; very high = heater stuck on.",
           "action": "Frozen DEF: the tank heaters should thaw it once running -- wait before demanding full power.",
           "basis": "general"},
    5245: {"normal": "'Off - adequate DEF'.",
           "abnormal": "'On solid - low DEF' or 'Fast blink - DEF very low'.",
           "action": "Refill DEF now; fast blink means derate is imminent.",
           "basis": "da-state"},
    5246: {"normal": "'No inducement'.",
           "abnormal": "Level 1-2 = warnings; Level 3 = engine derate; Level 4-5 = severe inducement; Temporary override = fault still present.",
           "action": "Level 1-2: diagnose the DEF/SCR fault before it escalates. Level 3+: power and speed are limited -- fix the underlying fault; the derate clears when the fault clears.",
           "basis": "da-state"},
    168: {"normal": "Roughly 12-15 V with the engine running.",
          "abnormal": "Below 12 V running = charging problem; above 15 V = regulator fault.",
          "action": "Low: check alternator, belts, and cable connections. High: regulator -- overvoltage damages electronics.",
          "basis": "verified-band"},
    247: {"normal": "Informational -- compare against odometer.",
          "abnormal": "High hours with low miles = heavy idling: more wear per mile than the odometer suggests.",
          "action": "Buying used: divide miles by hours; under ~30 mph average means a hard-idled life.",
          "basis": "general"},
    183: {"normal": "Tracks load; near zero at idle.",
          "abnormal": "High at idle or not rising with load = fuel system issue; compare with expected for the duty cycle.",
          "action": "Cross-check with boost, rail pressure faults, and fuel filter age.",
          "basis": "general"},
}

# Inhibit reasons 3702-3717, 5629, 10153 not individually listed above share
# this generic rationale: the DA state text already says what is inhibiting.
_INHIBIT_SPNS = (3702, 3704, 3705, 3706, 3707, 3708, 3709, 3710,
                 3713, 3714, 3715, 3717, 5629, 10153)
for _spn in _INHIBIT_SPNS:
    SPN_GUIDE.setdefault(_spn, {
        "normal": "Not inhibited by this condition.",
        "abnormal": "Inhibited -- the decoded state text names the exact condition.",
        "action": "Fix or wait out the named condition (e.g. release the brake, finish warm-up, clear the fault), then regen can proceed.",
        "basis": "da-state"})


def explain(spn, state=None):
    """Return the rationale dict for an SPN, or None if we have none.

    We never invent guidance: unknown SPNs return None and the caller
    prints nothing rather than guessing.
    """
    return SPN_GUIDE.get(spn)


def action_for(spn):
    """One-line 'what to do' for an SPN, or '' when we have no guidance."""
    g = SPN_GUIDE.get(spn)
    return g["action"] if g else ""


# FMI -> plain-English "what this usually means". FMIs are standardized in
# J1939-73; this is general diagnostic knowledge, worded as "typically".
FMI_GUIDE = {
    0: "Reading above the worst limit (e.g. overheating, overpressure, overspeed). Treat as urgent.",
    1: "Reading below the worst limit (e.g. lost oil pressure). Treat as urgent.",
    2: "Signal jumping around -- typically wiring, a connector, or a dying sensor rather than the part itself.",
    3: "Shorted to high / voltage too high -- electrical: check the harness and power feed.",
    4: "Shorted to low / voltage too low -- electrical: check the harness and grounds.",
    5: "Open circuit -- broken wire, unplugged connector, or a failed actuator coil.",
    6: "Too much current / shorted to ground -- wiring or a shorted actuator.",
    7: "Part not responding to commands -- e.g. stuck valve, jammed actuator. Mechanical.",
    8: "Signal frequency wrong -- usually a speed or timing sensor issue.",
    9: "ECU stopped hearing from another ECU -- network wiring, or the other ECU is down.",
    10: "Changing faster than physically possible -- usually a failing sensor.",
    11: "ECU knows something is wrong but cannot pinpoint it -- needs deeper diagnosis.",
    12: "The smart component itself has failed -- replace the component.",
    13: "Out of calibration -- needs a relearn/service procedure.",
    14: "Special case -- follow the service literature for this SPN.",
    15: "Above normal, least severe -- early warning; watch the trend.",
    16: "Above normal, moderately severe -- investigate soon.",
    17: "Below normal, least severe -- early warning; watch the trend.",
    18: "Below normal, moderately severe -- investigate soon.",
    19: "Bad data received over the network -- wiring or the sending ECU.",
    20: "Sensor drifted high -- aging sensor; verify against a known-good reading.",
    21: "Sensor drifted low -- aging sensor; verify against a known-good reading.",
    31: "Condition exists -- informational flag; the SPN context says what.",
}


def fmi_guidance(fmi):
    """Plain-English meaning of an FMI, or '' when unknown."""
    return FMI_GUIDE.get(fmi, "")


def check_soot(soot_pct, threshold_pct):
    """DPF soot vs the truck's own regen threshold (SPN 5466).

    No external spec needed: the truck reports its own limit. The 80%
    early-warning line is a heuristic and is labeled as one.
    Returns (status, message); status is "ok", "warn", or "alert".
    """
    if soot_pct is None or threshold_pct is None or threshold_pct <= 0:
        return ("ok", "")
    if soot_pct >= threshold_pct:
        return ("alert",
                "DPF soot %.0f%% at/above the truck's regen threshold %.0f%%: "
                "regeneration needed (basis: truck's own SPN 5466)" %
                (soot_pct, threshold_pct))
    if soot_pct >= 0.8 * threshold_pct:
        return ("warn",
                "DPF soot %.0f%% approaching regen threshold %.0f%% "
                "(80%% early-warning heuristic)" % (soot_pct, threshold_pct))
    return ("ok", "")
