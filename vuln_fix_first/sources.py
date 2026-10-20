"""Download data from CISA KEV, FIRST EPSS, the CVE.org (MITRE) record service and OSV.dev."""
from __future__ import annotations

import json
import sys
import urllib.request
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
CVE_URL = "https://cveawg.mitre.org/api/cve/"
OSV_URL = "https://api.osv.dev/v1/vulns/"


def get_json(url: str) -> Any:
    headers = {"User-Agent": "vuln-fix-first", "Accept": "application/json"}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        return json.load(r)


def ghsa_to_cve(ghsa: str) -> str | None:
    try:
        aliases = get_json(OSV_URL + ghsa).get("aliases", [])
        return next((a for a in aliases if a.upper().startswith("CVE-")), None)
    except Exception as e:
        print(f"warning: could not resolve {ghsa}: {e}", file=sys.stderr)
        return None


def fetch_epss(cves: list[str]) -> dict[str, tuple[float, float]]:
    """Map each CVE to (EPSS probability, percentile among all scored CVEs)."""
    scores = {}
    for i in range(0, len(cves), 100):  # API caps a request at 100 CVEs
        data = get_json(EPSS_URL + ",".join(cves[i:i + 100]))
        for row in data.get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return scores


def fetch_kev() -> dict[str, bool]:
    """Map each KEV CVE to whether CISA knows it is used in ransomware campaigns."""
    return {v["cveID"]: v.get("knownRansomwareCampaignUse") == "Known" for v in get_json(KEV_URL)["vulnerabilities"]}


def parse_record(record: dict[str, Any]) -> dict[str, Any]:
    """Pull product, CVSS score and CISA SSVC options out of a CVE JSON 5 record."""
    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    affected = cna.get("affected") or [{}]
    a = affected[0]
    product = next((v for v in (a.get("product"), a.get("packageName"), a.get("vendor")) if v and v.lower() != "n/a"), "")
    product = "".join(c for c in str(product) if c.isprintable())  # records are third-party text: no terminal escapes
    info: dict[str, Any] = {"product": product, "cvss": None, "ssvc": {}}
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


def fetch_record(cve: str) -> dict[str, Any]:
    try:
        return parse_record(get_json(CVE_URL + cve))
    except Exception as e:
        print(f"warning: no CVE record for {cve}: {e}", file=sys.stderr)
        return {"product": "", "cvss": None, "ssvc": {}}
