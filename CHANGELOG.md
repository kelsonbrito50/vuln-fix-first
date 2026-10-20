# Changelog

All notable changes to this project are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-19

First public release.

### Added

- Rank CVE and GHSA IDs from any scanner output (npm audit, pip-audit, Trivy, Grype, Dependabot) as ACT, ATTEND, TRACK\* or TRACK, using CISA KEV, FIRST EPSS and the CISA SSVC Coordinator table v2.0.3.
- Fix-by deadlines from the CISA BOD 26-04 SSVC table, with a "check for compromise" flag for bugs already being attacked.
- `--mission low|medium|high` and `--exposed` to describe the affected system.
- Ransomware flag from the KEV catalog, used in the ordering.
- "By package" summary: which single upgrade clears the most CVEs.
- `--capacity N`: show only the N upgrades that matter most.
- `--ignore FILE`: accepted-risk list with an expiry date per CVE.
- EPSS percentile next to each EPSS score.
- Expected number of attacked CVEs in the next 30 days (sum of EPSS), before and after the suggested fixes.
- `--json` output.
- GHSA to CVE conversion through OSV.dev.
- UTF-16 input files (Windows PowerShell 5.1 redirects).
- Skill packaging for Claude Code, Codex and other Agent Skills hosts, plus a zip for the Claude app.
