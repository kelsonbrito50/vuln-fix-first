"""Download data from CISA KEV, FIRST EPSS, the CVE.org (MITRE) record service and OSV.dev."""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
CVE_URL = "https://cveawg.mitre.org/api/cve/"
OSV_URL = "https://api.osv.dev/v1/vulns/"
TRIES = 3

DAY = 24 * 3600
KEV_TTL, CVE_TTL, GHSA_TTL = DAY, 7 * DAY, 30 * DAY

# "online" reads fresh cache entries and refreshes old ones, "no-cache" never touches the cache,
# "offline" never touches the network. Set once by the CLI before any download.
mode = "online"
# Oldest cached entry used per kind ("kev", "cve", "ghsa"), in seconds, so --offline can say how old its data is.
ages: dict[str, float] = {}
_ages_lock = threading.Lock()


def cache_dir() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "vuln-fix-first"


def cached(key: str, ttl: int, fetch: Callable[[], Any]) -> Any:
    """Return the cached data for key ("kev", "cve/CVE-...", "ghsa/GHSA-...") while younger than ttl seconds,
    else fetch and store it. Errors from fetch are not cached."""
    path = cache_dir() / f"{key}.json"
    if mode != "no-cache":
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            age = time.time() - float(entry["fetched"])
            if mode == "offline" or age < ttl:
                with _ages_lock:
                    kind = key.split("/")[0]
                    ages[kind] = max(ages.get(kind, 0.0), age)
                return entry["data"]
        except (OSError, ValueError, KeyError, TypeError):
            pass  # missing or damaged entry: fetch it again
    if mode == "offline":
        raise LookupError(f"--offline and no cached copy of {key}")
    data = fetch()
    if mode != "no-cache":
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            tmp.write_text(json.dumps({"fetched": time.time(), "data": data}), encoding="utf-8")
            os.replace(tmp, path)  # atomic, so a parallel run never reads half a file
        except OSError as e:  # a read-only home must not stop the ranking
            print(f"warning: could not write cache {path}: {e}", file=sys.stderr)
    return data


def retryable(e: Exception) -> bool:
    """Rate limits (429), server errors (5xx) and timeouts are worth another try; anything else is not."""
    if isinstance(e, urllib.error.HTTPError):
        return e.code == 429 or e.code >= 500
    reason = e.reason if isinstance(e, urllib.error.URLError) else e
    return isinstance(reason, (socket.timeout, TimeoutError))


def _get_json(url: str) -> Any:
    if mode == "offline":
        raise LookupError("--offline, no network")
    headers = {"User-Agent": "vuln-fix-first", "Accept": "application/json"}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        return json.load(r)


def get_json(url: str) -> Any:
    for attempt in range(TRIES - 1):
        try:
            return _get_json(url)
        except Exception as e:
            if not retryable(e):
                raise
            time.sleep(2 ** attempt)  # 1 s, then 2 s
    return _get_json(url)


def ghsa_to_cve(ghsa: str) -> str | None:
    try:
        aliases = cached(f"ghsa/{ghsa}", GHSA_TTL, lambda: get_json(OSV_URL + ghsa).get("aliases", []))
    except Exception as e:
        print(f"warning: could not resolve {ghsa}: {e}", file=sys.stderr)
        return None
    cve = next((str(a).upper() for a in aliases if str(a).upper().startswith("CVE-")), None)
    if cve is None:
        print(f"warning: {ghsa} has no CVE ID, skipped", file=sys.stderr)
    return cve


def fetch_epss(cves: list[str]) -> tuple[dict[str, tuple[float, float]], str | None]:
    """Map each CVE to (EPSS probability, percentile among all scored CVEs); also return the scores' date."""
    scores, date = {}, None
    for i in range(0, len(cves), 100):  # API caps a request at 100 CVEs
        data = get_json(EPSS_URL + ",".join(cves[i:i + 100]))
        for row in data.get("data", []):
            scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            date = date or row.get("date")
    return scores, date


def fetch_kev() -> tuple[dict[str, bool], str | None]:
    """Map each KEV CVE to whether CISA knows it is used in ransomware campaigns; also return the catalog version."""
    catalog = cached("kev", KEV_TTL, lambda: get_json(KEV_URL))
    kev = {v["cveID"]: v.get("knownRansomwareCampaignUse") == "Known" for v in catalog["vulnerabilities"]}
    return kev, catalog.get("catalogVersion")


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
        return parse_record(cached(f"cve/{cve}", CVE_TTL, lambda: get_json(CVE_URL + cve)))
    except Exception as e:
        print(f"warning: no CVE record for {cve}: {e}", file=sys.stderr)
        return {"product": "", "cvss": None, "ssvc": {}}
