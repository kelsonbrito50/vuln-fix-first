#!/usr/bin/env python3
"""Rank CVEs by what to fix first, using CISA KEV, FIRST EPSS and the CISA SSVC decision table.

Input: CVE or GHSA IDs as arguments, or any text/JSON on stdin or in a file
(scanner output from Trivy, Grype, pip-audit, npm audit, Dependabot...).
Standard library only.
"""
import argparse
import datetime
import json
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
CVE_URL = "https://cveawg.mitre.org/api/cve/"
OSV_URL = "https://api.osv.dev/v1/vulns/"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
IGNORE_RE = re.compile(r"(CVE-\d{4}-\d{4,})\s+(\S+)\s*(.*)", re.I)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)

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
SSVC = {}
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
DEADLINE = {}
for _line in _BOD.strip().splitlines():
    _k, _x, _a, _t, _d = _line.split(",")
    DEADLINE[(_k, _x, _a, _t)] = _d or None


def decide(exploitation, automatable, impact, mission):
    return SSVC[(exploitation, automatable, impact, mission)]


def deadline(in_kev, exposed, automatable, impact, today=None):
    """Return (label, due_date) from the BOD 26-04 table; due_date is None for 'next upgrade'."""
    code = DEADLINE[("yes" if in_kev else "no", "yes" if exposed else "no", automatable, impact)]
    if code is None:
        return "at next system upgrade", None
    days = int(code.rstrip("f"))
    due = (today or datetime.date.today()) + datetime.timedelta(days=days)
    label = f"within {days} days" + (" + check for compromise" if code.endswith("f") else "")
    return label, due.isoformat()


def get_json(url):
    headers = {"User-Agent": "vuln-fix-first", "Accept": "application/json"}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        return json.load(r)


def decode(data):
    """Windows PowerShell 5.1 writes `>` redirects as UTF-16, so honor a BOM before falling back to UTF-8."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    return data.decode("utf-8-sig", errors="replace")


def extract_ids(text):
    """Return (cve_ids, ghsa_ids) found in any text, deduplicated, in first-seen order."""
    cves = list(dict.fromkeys(m.upper() for m in CVE_RE.findall(text)))
    ghsas = list(dict.fromkeys("GHSA" + m[4:].lower() for m in GHSA_RE.findall(text)))
    return cves, ghsas


def ghsa_to_cve(ghsa):
    try:
        aliases = get_json(OSV_URL + ghsa).get("aliases", [])
        return next((a for a in aliases if a.upper().startswith("CVE-")), None)
    except Exception as e:
        print(f"warning: could not resolve {ghsa}: {e}", file=sys.stderr)
        return None


def load_ignores(text, today=None):
    """Parse an accepted-risk file: one 'CVE-ID YYYY-MM-DD reason' per line, '#' starts a comment line.
    Return (active, expired): active maps CVE -> (until, reason); expired lists CVEs past their date."""
    today = today or datetime.date.today()
    active, expired = {}, []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = IGNORE_RE.fullmatch(line)
        try:
            until = datetime.date.fromisoformat(m[2]) if m else None
        except ValueError:
            until = None
        if until is None:
            raise ValueError(f"line {n}: expected 'CVE-ID YYYY-MM-DD reason', got {line!r}")
        cve = m[1].upper()
        if until < today:
            expired.append(cve)
        else:
            active[cve] = (until.isoformat(), m[3])
    return active, expired


def fetch_epss(cves):
    """Map each CVE to (EPSS probability, percentile among all scored CVEs)."""
    scores = {}
    for i in range(0, len(cves), 100):  # API caps a request at 100 CVEs
        data = get_json(EPSS_URL + ",".join(cves[i:i + 100]))
        for row in data.get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return scores


def fetch_kev():
    """Map each KEV CVE to whether CISA knows it is used in ransomware campaigns."""
    return {v["cveID"]: v.get("knownRansomwareCampaignUse") == "Known" for v in get_json(KEV_URL)["vulnerabilities"]}


def parse_record(record):
    """Pull product, CVSS score and CISA SSVC options out of a CVE JSON 5 record."""
    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    affected = cna.get("affected") or [{}]
    a = affected[0]
    product = next((v for v in (a.get("product"), a.get("packageName"), a.get("vendor")) if v and v.lower() != "n/a"), "")
    product = "".join(c for c in str(product) if c.isprintable())  # records are third-party text: no terminal escapes
    info = {"product": product, "cvss": None, "ssvc": {}}
    metrics = list(cna.get("metrics", []))
    for adp in containers.get("adp", []):
        metrics += adp.get("metrics", [])
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):  # newest CVSS version wins
        score = next((m[key]["baseScore"] for m in metrics if key in m), None)
        if score is not None:
            info["cvss"] = (key[5:].replace("_", "."), score)
            break
    for m in metrics:
        other = m.get("other", {})
        if other.get("type") == "ssvc":
            for opt in other["content"].get("options", []):
                info["ssvc"].update({k.lower(): v.lower() for k, v in opt.items()})
    if info["ssvc"].get("exploitation") == "poc":  # CISA records say "poc", the table says "public poc"
        info["ssvc"]["exploitation"] = "public poc"
    return info


def fetch_record(cve):
    try:
        return parse_record(get_json(CVE_URL + cve))
    except Exception as e:
        print(f"warning: no CVE record for {cve}: {e}", file=sys.stderr)
        return {"product": "", "cvss": None, "ssvc": {}}


def triage(cve, info, epss, in_kev, mission, exposed=False, ransomware=False, percentile=None):
    """Missing automatable/impact default to the worst case; missing exploitation defaults to none
    (KEV already catches known exploitation). Every default is listed in "assumed"."""
    s, assumed = info["ssvc"], []

    def pick(name, allowed, worst):
        value = s.get(name)
        if value in allowed:
            return value
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


def sort_key(r):
    return (RANK[r["decision"]], not r["in_kev"], not r.get("ransomware"), -(r["epss"] or 0))


def reason(r):
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


def by_package(results):
    """One upgrade often fixes many CVEs: group by product, most urgent package first."""
    groups = {}
    for r in results:  # results are already sorted, so the first row of each group is its worst
        name = r["product"] or "(unknown product)"
        groups.setdefault(name.lower().split("/")[-1], (name, []))[1].append(r)  # "Lodash" = "lodash", "axios/axios" = "axios"
    return sorted(groups.values(), key=lambda g: (RANK[g[1][0]["decision"]], -len(g[1])))


def expected_attacked(rows):
    """Sum of EPSS = expected number of these CVEs that see exploitation activity in the next 30 days."""
    return sum(r["epss"] or 0 for r in rows)


def capacity(n):
    value = int(n)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("ids", nargs="*", help="CVE or GHSA IDs (default: read stdin)")
    p.add_argument("-f", "--file", help="scanner output or any text file to pull IDs from")
    p.add_argument("-m", "--mission", choices=MISSION, default="medium",
                   help="how much the affected system matters to you (default: medium)")
    p.add_argument("-x", "--exposed", action="store_true",
                   help="the system is reachable from the internet or other untrusted networks")
    p.add_argument("-c", "--capacity", type=capacity, metavar="N",
                   help="how many package upgrades you can do now: show the N that matter most")
    p.add_argument("-i", "--ignore", metavar="FILE",
                   help="accepted-risk file, one 'CVE-ID YYYY-MM-DD reason' per line; skipped until that date")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = p.parse_args(argv)

    ignores, expired = {}, []
    if args.ignore:
        try:
            with open(args.ignore, "rb") as fh:
                ignores, expired = load_ignores(decode(fh.read()))
        except OSError as e:
            p.error(f"cannot read {args.ignore}: {e.strerror}")
        except ValueError as e:
            p.error(f"{args.ignore}: {e}")

    if args.file:
        try:
            with open(args.file, "rb") as fh:
                text = decode(fh.read())
        except OSError as e:
            p.error(f"cannot read {args.file}: {e.strerror}")
    elif args.ids:
        text = " ".join(args.ids)
    elif sys.stdin.isatty():
        p.error("give CVE/GHSA IDs, a file with -f, or pipe scanner output in")
    else:
        text = decode(sys.stdin.buffer.read())

    cves, ghsas = extract_ids(text)
    with ThreadPoolExecutor(8) as pool:
        cves += [c for c in pool.map(ghsa_to_cve, ghsas) if c and c not in cves]
    if not cves:
        sys.exit("no CVE or GHSA IDs found in the input")
    for c in cves:
        if c in expired:
            print(f"warning: accepted risk for {c} has expired, ranking it again", file=sys.stderr)
    skipped = [c for c in cves if c in ignores]
    cves = [c for c in cves if c not in ignores]
    if not cves:
        print(f"all {len(skipped)} CVEs are in the accepted-risk file, nothing to rank")
        return

    try:
        kev = fetch_kev()
    except Exception as e:  # without KEV the ranking would hide exploited CVEs, so stop
        sys.exit(f"error: could not download CISA KEV: {e}")
    try:
        epss = fetch_epss(cves)
    except Exception as e:
        print(f"warning: EPSS unavailable, ranking without it: {e}", file=sys.stderr)
        epss = {}
    with ThreadPoolExecutor(8) as pool:
        records = dict(zip(cves, pool.map(fetch_record, cves)))
    results = []
    for c in cves:
        score, pct = epss.get(c, (None, None))
        results.append(triage(c, records[c], score, c in kev, args.mission, args.exposed, kev.get(c, False), pct))
    results.sort(key=sort_key)

    if args.json:
        print(json.dumps(results, indent=2))
        return
    for r in results:
        print(f"{r['decision'].upper():7} {r['cve']:16} {r['product'][:24]:24} {reason(r)}")
    counts = {d: sum(r["decision"] == d for r in results) for d in RANK}
    print("\n" + "  ".join(f"{d.upper()}: {n}" for d, n in counts.items())
          + f"  (mission: {args.mission}, exposed: {'yes' if args.exposed else 'no'})")

    groups = by_package(results)
    shown = groups[:args.capacity] if args.capacity else groups
    if args.capacity:
        fixed = sum(len(rows) for _, rows in shown)
        print(f"\nYour capacity: {args.capacity} upgrade(s). Do these first, they fix {fixed} of {len(results)} CVEs:")
    elif len(groups) > 1:
        print("\nBy package (one upgrade fixes all its CVEs):")
    if args.capacity or len(groups) > 1:
        for name, rows in shown:
            soonest = min(rows, key=lambda r: r["due_date"] or "9999")  # decision and deadline can differ per CVE
            due = f" by {soonest['due_date']}" if soonest["due_date"] else ""
            n = f"{len(rows)} CVE" + ("s" if len(rows) > 1 else "")
            print(f"  {rows[0]['decision'].upper():7} {name[:30]:30} {n:>8}, fix {soonest['fix_within']}{due}")

    if epss:
        if args.capacity:
            done, after = {id(r) for _, rows in shown for r in rows}, f"after these {len(shown)} upgrade(s)"
        else:
            done, after = {id(r) for r in results if r["decision"] in ("act", "attend")}, "after fixing ACT + ATTEND"
        left = [r for r in results if id(r) not in done]
        print(f"\nExpected to see attacks in the next 30 days (sum of EPSS): {expected_attacked(results):.2f} "
              f"of these {len(results)} CVEs; {after}: {expected_attacked(left):.2f}")
    if skipped:
        print(f"\nAccepted risk, not ranked ({args.ignore}):")
        for c in skipped:
            print(f"  {c:16} until {ignores[c][0]}  {ignores[c][1]}")


if __name__ == "__main__":
    main()
