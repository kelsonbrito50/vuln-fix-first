# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-20

### Added

- Disk cache in `~/.cache/vuln-fix-first/` (or `$XDG_CACHE_HOME`): KEV for 24 hours, CVE records for 7 days, GHSA to CVE results for 30 days.
- `--no-cache` to skip the cache, and `--offline` to use only the cache, with a warning about the data's age.
- `--format sarif` for GitHub Code Scanning, and `--format text|json` (`--json` still works).
- `--fail-on ACT|ATTEND`: exit code 1 when a CVE is at that level or higher, for CI.
- `kev_version` and `epss_date` on every `--json` row.
- 3 tries with backoff (1 s, 2 s) on HTTP 429, 5xx and timeouts.
- A warning for GHSA IDs that have no CVE.
- `pyproject.toml` with a `vuln-fix-first` command, still with no runtime dependencies.
- `docs/ci-example.yml`: a GitHub Actions workflow using `--format sarif` and `--fail-on`.
- CI: `mypy --strict` and `ruff`, and a release job that attaches `vuln-fix-first.zip` to each tagged release.
- Tests: real npm audit, pip-audit, Trivy and Grype output; every row of both CISA tables checked against the official CERT/CC CSV files; network, encoding and accepted-risk edge cases. No test reaches the network.

### Changed

- The code moved into the `vuln_fix_first` package (`sources`, `ssvc`, `parse`, `report`, `cli`). `scripts/vuln_fix_first.py` is now a thin wrapper, so existing commands keep working.
- Type hints on all public functions.
- The KEV error now reads "could not get CISA KEV", since it also covers a missing cache with `--offline`.

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

[Unreleased]: https://github.com/kelsonbrito50/vuln-fix-first/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/kelsonbrito50/vuln-fix-first/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/kelsonbrito50/vuln-fix-first/releases/tag/v1.0.0
