#!/usr/bin/env python3
"""Thin wrapper so `python scripts/vuln_fix_first.py` (used by SKILL.md) keeps working.
The code lives in the vuln_fix_first package next to this folder."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root first, so the package wins over this file
from vuln_fix_first.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
