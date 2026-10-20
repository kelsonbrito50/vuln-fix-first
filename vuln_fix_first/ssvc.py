"""CISA SSVC decision and deadline tables, and the triage of one CVE."""
from __future__ import annotations

import datetime
from typing import Any

# CISA Coordinator decision table, SSVC v2.0.3 (CERT/CC SSVC project, data/csv/cisa/cisa_coordinator_2_0_3.csv).
# Copyright Carnegie Mellon University, MIT (SEI)-style license: see THIRD_PARTY_NOTICES.md.
# Order: Exploitation, Automatable, Technical Impact, Mission and Well-Being -> decision.
_TABLE = """
none,no,partial,track,track,track
none,no,total,track,track,track*
none,yes,partial,track,track,attend
none,yes,total,track,track,attend
public poc,no,partial,track,track,track*
public poc,no,total,track,track*,attend
public poc,yes,partial,track,track,attend
public poc,yes,total,track,track*,attend
active,no,partial,track,track,attend
active,no,total,track,attend,act
active,yes,partial,attend,attend,act
active,yes,total,attend,act,act
"""
MISSION = ("low", "medium", "high")
SSVC: dict[tuple[str, str, str, str], str] = {}
for _line in _TABLE.strip().splitlines():
    _e, _a, _t, *_out = _line.split(",")
    for _m, _d in zip(MISSION, _out):
        SSVC[(_e, _a, _t, _m)] = _d

RANK = {"act": 0, "attend": 1, "track*": 2, "track": 3}

# CISA BOD 26-04 remediation timelines, SSVC (CERT/CC SSVC project, data/csv/cisa/cisa_bod_26_04_1_0_0.csv).
# Same Carnegie Mellon University license as above: see THIRD_PARTY_NOTICES.md.
# Key: In KEV, Publicly Exposed, Automatable, Technical Impact -> days to fix (None = next scheduled upgrade).
_BOD = """
no,no,no,partial,
yes,no,no,partial,14
no,yes,no,partial,60
no,no,yes,partial,60
no,no,no,total,
yes,yes,no,partial,14
yes,no,yes,partial,14
no,yes,yes,partial,14
yes,no,no,total,14
no,yes,no,total,14
no,no,yes,total,60
yes,yes,yes,partial,3
yes,yes,no,total,3f
yes,no,yes,total,3f
no,yes,yes,total,3
yes,yes,yes,total,3f
"""
DEADLINE: dict[tuple[str, str, str, str], str | None] = {}
for _line in _BOD.strip().splitlines():
    _k, _x, _a, _t, _d = _line.split(",")
    DEADLINE[(_k, _x, _a, _t)] = _d or None


def decide(exploitation: str, automatable: str, impact: str, mission: str) -> str:
    return SSVC[(exploitation, automatable, impact, mission)]


def deadline(in_kev: bool, exposed: bool, automatable: str, impact: str,
             today: datetime.date | None = None) -> tuple[str, str | None]:
    """Return (label, due_date) from the BOD 26-04 table; due_date is None for 'next upgrade'."""
    code = DEADLINE[("yes" if in_kev else "no", "yes" if exposed else "no", automatable, impact)]
    if code is None:
        return "at next system upgrade", None
    days = int(code.rstrip("f"))
    due = (today or datetime.date.today()) + datetime.timedelta(days=days)
    label = f"within {days} days" + (" + check for compromise" if code.endswith("f") else "")
    return label, due.isoformat()


def triage(cve: str, info: dict[str, Any], epss: float | None, in_kev: bool, mission: str,
           exposed: bool = False, ransomware: bool = False, percentile: float | None = None) -> dict[str, Any]:
    """Missing automatable/impact default to the worst case; missing exploitation defaults to none
    (KEV already catches known exploitation). Every default is listed in "assumed"."""
    s, assumed = info["ssvc"], []

    def pick(name: str, allowed: tuple[str, ...], worst: str) -> str:
        value = s.get(name)
        if value in allowed:
            return str(value)
        assumed.append(name)
        return worst

    # KEV listing is proof of active exploitation, whatever the CVE record says.
    exploitation = "active" if in_kev else pick("exploitation", ("none", "public poc", "active"), "none")
    automatable = pick("automatable", ("yes", "no"), "yes")
    impact = pick("technical impact", ("partial", "total"), "total")
    fix_within, due = deadline(in_kev, exposed, automatable, impact)
    return {
        "cve": cve,
        "decision": decide(exploitation, automatable, impact, mission),
        "fix_within": fix_within,
        "due_date": due,
        "product": info["product"],
        "in_kev": in_kev,
        "ransomware": ransomware,
        "epss": epss,
        "epss_percentile": percentile,
        "cvss": info["cvss"],
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": impact,
        "assumed": assumed,
    }


def sort_key(r: dict[str, Any]) -> tuple[int, bool, bool, float]:
    return (RANK[r["decision"]], not r["in_kev"], not r.get("ransomware"), -(r["epss"] or 0))
