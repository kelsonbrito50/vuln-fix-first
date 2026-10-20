"""Rank CVEs by what to fix first, using CISA KEV, FIRST EPSS and the CISA SSVC decision table."""
__version__ = "1.1.0"  # before the imports: report.py reads it while this file is still loading

from .cli import capacity, main
from .parse import decode, extract_ids, load_ignores
from .report import by_package, expected_attacked, reason
from .sources import fetch_epss, fetch_kev, fetch_record, get_json, ghsa_to_cve, parse_record
from .ssvc import DEADLINE, MISSION, RANK, SSVC, deadline, decide, sort_key, triage

__all__ = [
    "DEADLINE", "MISSION", "RANK", "SSVC", "by_package", "capacity", "deadline", "decide", "decode",
    "expected_attacked", "extract_ids", "fetch_epss", "fetch_kev", "fetch_record", "get_json", "ghsa_to_cve",
    "load_ignores", "main", "parse_record", "reason", "sort_key", "triage",
]
