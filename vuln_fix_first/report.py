"""Turn triaged rows into the text table, package summary and JSON output."""
from __future__ import annotations

import json
from typing import Any

from . import __version__
from .ssvc import RANK

Row = dict[str, Any]

SARIF_LEVEL = {"act": "error", "attend": "error", "track*": "warning", "track": "note"}
# GitHub turns security-severity into critical/high/medium/low. Use the decision, not CVSS:
# a CVSS 9.8 can be TRACK, and the point of this tool is to show what to fix first.
SARIF_SEVERITY = {"act": "9.5", "attend": "8.0", "track*": "5.0", "track": "2.0"}


def reason(r: Row) -> str:
    if r["in_kev"]:
        parts = ["on KEV (actively exploited" + (", used by ransomware)" if r["ransomware"] else ")")]
    else:
        parts = [f"exploitation: {r['exploitation']}"]
    parts.append(f"fix {r['fix_within']}" + (f" (by {r['due_date']})" if r["due_date"] else ""))
    if r["epss"] is not None:
        top = f" (top {max(1 - r['epss_percentile'], 0.001):.1%})" if r.get("epss_percentile") is not None else ""
        parts.append(f"EPSS {r['epss']:.1%}{top}")
    if r["cvss"]:
        parts.append(f"CVSS {r['cvss'][0]} {r['cvss'][1]}")
    parts.append(f"automatable: {r['automatable']}, impact: {r['technical_impact']}")
    if r["assumed"]:
        parts.append("no CISA SSVC data, assumed: " + ", ".join(r["assumed"]))
    return "; ".join(parts)


def by_package(results: list[Row]) -> list[tuple[str, list[Row]]]:
    """One upgrade often fixes many CVEs: group by product, most urgent package first."""
    groups: dict[str, tuple[str, list[Row]]] = {}
    for r in results:  # results are already sorted, so the first row of each group is its worst
        name = r["product"] or "(unknown product)"
        # "Lodash" = "lodash", "axios/axios" = "axios"
        groups.setdefault(name.lower().split("/")[-1], (name, []))[1].append(r)
    return sorted(groups.values(), key=lambda g: (RANK[g[1][0]["decision"]], -len(g[1])))


def expected_attacked(rows: list[Row]) -> float:
    """Sum of EPSS = expected number of these CVEs that see exploitation activity in the next 30 days."""
    return float(sum(r["epss"] or 0 for r in rows))


def print_json(results: list[Row]) -> None:
    print(json.dumps(results, indent=2))


def sarif(results: list[Row], source: str | None) -> dict[str, Any]:
    """SARIF 2.1.0 for GitHub Code Scanning. Every result points at the scanned file (line 1),
    since the CVE is in a dependency, not in a line of code."""
    uri = (source or "vuln-fix-first-input").replace("\\", "/")
    rules, findings = [], []
    for r in results:
        title = f"{r['cve']} in {r['product']}" if r["product"] else r["cve"]
        rules.append({
            "id": r["cve"],
            "shortDescription": {"text": title},
            "helpUri": f"https://www.cve.org/CVERecord?id={r['cve']}",
            "properties": {"security-severity": SARIF_SEVERITY[r["decision"]], "tags": ["security", r["decision"]]},
        })
        findings.append({
            "ruleId": r["cve"],
            "level": SARIF_LEVEL[r["decision"]],
            "message": {"text": f"{r['decision'].upper()}: {title}. {reason(r)}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}],
            "partialFingerprints": {"vulnFixFirstCve/v1": r["cve"]},
            "properties": {k: r[k] for k in ("decision", "fix_within", "due_date", "in_kev", "epss")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vuln-fix-first", "version": __version__,
                                "informationUri": "https://github.com/kelsonbrito50/vuln-fix-first", "rules": rules}},
            "results": findings,
        }],
    }


def print_text(results: list[Row], mission: str, exposed: bool, cap: int | None, has_epss: bool,
               skipped: list[str], ignores: dict[str, tuple[str, str]], ignore_file: str | None) -> None:
    for r in results:
        print(f"{r['decision'].upper():7} {r['cve']:16} {r['product'][:24]:24} {reason(r)}")
    counts = {d: sum(r["decision"] == d for r in results) for d in RANK}
    print("\n" + "  ".join(f"{d.upper()}: {n}" for d, n in counts.items())
          + f"  (mission: {mission}, exposed: {'yes' if exposed else 'no'})")

    groups = by_package(results)
    shown = groups[:cap] if cap else groups
    if cap:
        fixed = sum(len(rows) for _, rows in shown)
        print(f"\nYour capacity: {cap} upgrade(s). Do these first, they fix {fixed} of {len(results)} CVEs:")
    elif len(groups) > 1:
        print("\nBy package (one upgrade fixes all its CVEs):")
    if cap or len(groups) > 1:
        for name, rows in shown:
            soonest = min(rows, key=lambda r: r["due_date"] or "9999")  # decision and deadline can differ per CVE
            due = f" by {soonest['due_date']}" if soonest["due_date"] else ""
            n = f"{len(rows)} CVE" + ("s" if len(rows) > 1 else "")
            print(f"  {rows[0]['decision'].upper():7} {name[:30]:30} {n:>8}, fix {soonest['fix_within']}{due}")

    if has_epss:
        if cap:
            done, after = {id(r) for _, rows in shown for r in rows}, f"after these {len(shown)} upgrade(s)"
        else:
            done, after = {id(r) for r in results if r["decision"] in ("act", "attend")}, "after fixing ACT + ATTEND"
        left = [r for r in results if id(r) not in done]
        print(f"\nExpected to see attacks in the next 30 days (sum of EPSS): {expected_attacked(results):.2f} "
              f"of these {len(results)} CVEs; {after}: {expected_attacked(left):.2f}")
    if skipped:
        print(f"\nAccepted risk, not ranked ({ignore_file}):")
        for c in skipped:
            print(f"  {c:16} until {ignores[c][0]}  {ignores[c][1]}")
