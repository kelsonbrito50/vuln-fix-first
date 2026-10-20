"""Rank CVEs by what to fix first, using CISA KEV, FIRST EPSS and the CISA SSVC decision table.

Input: CVE or GHSA IDs as arguments, or any text/JSON on stdin or in a file
(scanner output from Trivy, Grype, pip-audit, npm audit, Dependabot...).
Standard library only.
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

from . import report, sources
from .parse import decode, extract_ids, load_ignores
from .ssvc import MISSION, sort_key, triage


def capacity(n: str) -> int:
    value = int(n)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def main(argv: list[str] | None = None) -> None:
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
    cache = p.add_mutually_exclusive_group()
    cache.add_argument("--no-cache", action="store_true", help="always download, and do not read or write the cache")
    cache.add_argument("--offline", action="store_true",
                       help="use only cached data (no network); warns how old it is. EPSS is not cached")
    args = p.parse_args(argv)
    sources.mode = "offline" if args.offline else "no-cache" if args.no_cache else "online"
    sources.ages.clear()

    ignores: dict[str, tuple[str, str]] = {}
    expired: list[str] = []
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
        cves += [c for c in pool.map(sources.ghsa_to_cve, ghsas) if c and c not in cves]
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
        kev, kev_version = sources.fetch_kev()
    except Exception as e:  # without KEV the ranking would hide exploited CVEs, so stop
        sys.exit(f"error: could not get CISA KEV: {e}")
    try:
        epss, epss_date = sources.fetch_epss(cves)
    except Exception as e:
        print(f"warning: EPSS unavailable, ranking without it: {e}", file=sys.stderr)
        epss, epss_date = {}, None
    with ThreadPoolExecutor(8) as pool:  # map keeps input order
        records = dict(zip(cves, pool.map(sources.fetch_record, cves)))
    if args.offline:
        for kind, age in sorted(sources.ages.items()):
            print(f"warning: offline, oldest cached {kind.upper()} data is {age / 86400:.1f} days old", file=sys.stderr)
    results = []
    for c in cves:
        score, pct = epss.get(c, (None, None))
        results.append(triage(c, records[c], score, c in kev, args.mission, args.exposed, kev.get(c, False), pct))
    results.sort(key=sort_key)
    for r in results:  # on every row, so --json stays a plain list
        r.update(kev_version=kev_version, epss_date=epss_date)

    if args.json:
        report.print_json(results)
        return
    report.print_text(results, args.mission, args.exposed, args.capacity, bool(epss), skipped, ignores, args.ignore)
