# Third-party notices

vuln-fix-first is MIT licensed (see `LICENSE`). It also contains, or uses, the third-party material below.

## Included in this repo

### SSVC decision tables (CERT/CC, Carnegie Mellon University)
`vuln_fix_first/ssvc.py` embeds two decision tables from the [SSVC project](https://github.com/CERTCC/SSVC), and `tests/fixtures/` holds unchanged copies of both CSV files so the tests can compare every row:
- `data/csv/cisa/cisa_coordinator_2_0_3.csv` (CISA Coordinator decisions)
- `data/csv/cisa/cisa_bod_26_04_1_0_0.csv` (CISA BOD 26-04 remediation timelines)

They are covered by the SSVC repository's `data/LICENSE`, reproduced in full here:

```
Copyright 2026 Carnegie Mellon University.
 
Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.
 
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 
This Software includes and/or can make use of certain third party software ("Third Party Software"). The Third Party Software that is used by the software is dependent upon your system configuration, but typically includes the software identified in this license.txt file, and/or described in the documentation and/or read me file. By using this software, you agree to comply with any and all relevant Third Party Software terms and conditions contained in any such Third Party Software or separate license file distributed with such Third Party Software. The parties who own the Third Party Software ("Third Party Licensors") are intended third party beneficiaries to this License with respect to the terms applicable to their Third Party Software. Third Party Software licenses only apply to the Third Party Software and not any other portion of SEI Software or this software as a whole.
 
This material is based upon work funded and supported by the Department of Defense under Contract No. FA8702-15-D-0002 with Carnegie Mellon University for the operation of the Software Engineering Institute, a federally funded research and development center. 
 
The view, opinions, and/or findings contained in this material are those of the author(s) and should not be construed as an official Government position, policy, or decision, unless designated by other documentation. 
 
References herein to any specific commercial product, process, or service by trade name, trade mark, manufacturer, or otherwise, does not necessarily constitute or imply its endorsement, recommendation, or favoring by Carnegie Mellon University or its Software Engineering Institute.
 
NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 
[DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.  Please see Copyright notice for non-US Government use and distribution.
 
DM24-0278
```

## Used at runtime (downloaded, not included)

| Source | Terms |
|---|---|
| [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CC0 1.0 ([cisagov/kev-data](https://github.com/cisagov/kev-data)) |
| CISA Vulnrichment (SSVC data in CVE records) | CC0 1.0 ([cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)) |
| [FIRST EPSS](https://www.first.org/epss/) | Free to use, attribution requested. Jacobs, J., Romanosky, S., Edwards, B., Roytman, M., Adjerid, I. (2021). Exploit Prediction Scoring System (EPSS). *Digital Threats: Research and Practice*, 2(3). |
| [CVE.org](https://www.cve.org/) records | [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse). CVE® is a registered trademark of The MITRE Corporation. |
| [OSV.dev](https://osv.dev/) | Per-source data licenses, listed on osv.dev |

The test fixture `tests/fixtures/sample-record.json` is invented and contains no real CVE data.

## Not affiliated
This project is not affiliated with or endorsed by CISA, FIRST, MITRE, Carnegie Mellon University, Google (OSV), Anthropic or OpenAI. Product names are used only to describe compatibility.
