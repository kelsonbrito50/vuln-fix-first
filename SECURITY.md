# Security policy

## Supported versions

Only the latest release gets fixes.

## Reporting a vulnerability

Please don't open a public issue for a security problem in this project.

Use GitHub's private reporting instead: open the **Security** tab of this repository and click **Report a vulnerability**. Include:

- what the problem is and where (file and line, if you know),
- how to reproduce it,
- what an attacker could do with it.

You'll get a first answer within 7 days. Once a fix is released, the report can be made public, with credit to you if you want it.

## Scope

In scope:

- The script `scripts/vuln_fix_first.py`, for example unsafe parsing of input files or of data from the 4 sites it calls.
- A wrong ranking caused by a bug in the code, for example a KEV bug labeled TRACK.

Out of scope:

- Wrong or missing data at the sources (CISA KEV, FIRST EPSS, CVE.org, OSV.dev). Report those to the source.
- Vulnerabilities in the projects you scan. This tool only ranks them.
