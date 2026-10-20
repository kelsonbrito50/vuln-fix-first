"""Pull CVE/GHSA IDs out of any text, decode input files, read accepted-risk files."""
from __future__ import annotations

import datetime
import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
IGNORE_RE = re.compile(r"(CVE-\d{4}-\d{4,})\s+(\S+)\s*(.*)", re.I)
GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.I)


def decode(data: bytes) -> str:
    """Windows PowerShell 5.1 writes `>` redirects as UTF-16, so honor a BOM before falling back to UTF-8."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16")
    return data.decode("utf-8-sig", errors="replace")


def extract_ids(text: str) -> tuple[list[str], list[str]]:
    """Return (cve_ids, ghsa_ids) found in any text, deduplicated, in first-seen order."""
    cves = list(dict.fromkeys(m.upper() for m in CVE_RE.findall(text)))
    ghsas = list(dict.fromkeys("GHSA" + m[4:].lower() for m in GHSA_RE.findall(text)))
    return cves, ghsas


def load_ignores(text: str, today: datetime.date | None = None) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Parse an accepted-risk file: one 'CVE-ID YYYY-MM-DD reason' per line, '#' starts a comment line.
    Return (active, expired): active maps CVE -> (until, reason); expired lists CVEs past their date."""
    today = today or datetime.date.today()
    active: dict[str, tuple[str, str]] = {}
    expired: list[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = IGNORE_RE.fullmatch(line)
        try:
            until = datetime.date.fromisoformat(m[2]) if m else None
        except ValueError:
            until = None
        if m is None or until is None:
            raise ValueError(f"line {n}: expected 'CVE-ID YYYY-MM-DD reason', got {line!r}")
        cve = m[1].upper()
        if until < today:
            expired.append(cve)
        else:
            active[cve] = (until.isoformat(), m[3])
    return active, expired
