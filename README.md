# SOC Automation Lab

**Author:** Brandon Imperati | CySA+ | PenTest+ | SSCP
**Tools:** Python · Splunk · MITRE ATT&CK · ConnectWise
**Focus:** Automated Incident Response · SIEM Detection Engineering · Alert Triage

---

## Overview

A collection of SOC automation scripts and Splunk/Sentinel detection rules built to demonstrate the automation patterns I use professionally — reducing alert fatigue and accelerating triage and incident response.

---

## Repository Structure

```
soc-automation-lab/
├── detection-rules/     # Splunk correlation rules & Sentinel KQL detections, MITRE ATT&CK-mapped
├── ir-playbooks/         # Automated IR playbook orchestrator + response playbooks
├── triage-tools/         # IOC enrichment and alert triage utilities
└── README.md
```

> Note: this is an active learning/portfolio repo — structure and contents are being expanded over time. Below reflects what's currently in the repo.

---

## What's Here

### `detection-rules/`
Splunk correlation rules and Sentinel KQL detections mapped to MITRE ATT&CK, covering:

| Rule Name                       | MITRE Tactic      | Technique |
| -------------------------------- | ------------------ | --------- |
| Brute Force Login Spike          | Credential Access   | T1110     |
| Lateral Movement via PsExec      | Lateral Movement    | T1570     |
| Suspicious PowerShell Execution  | Execution           | T1059.001 |
| Data Exfil via DNS Tunneling     | Exfiltration        | T1048.003 |
| Persistence via Scheduled Task   | Persistence         | T1053.005 |
| Defense Evasion – Log Clearing   | Defense Evasion     | T1070.001 |

### `ir-playbooks/`
`playbook_runner.py` — automated incident response orchestrator that ingests SIEM/ConnectWise alert payloads and executes containment steps (endpoint isolation, account disable, IOC blocking) with a logged audit trail.

### `triage-tools/`
IOC enrichment utilities that query threat intel sources (VirusTotal, AbuseIPDB) to speed up analyst triage before manual review.

---

## Setup & Usage

```bash
git clone https://github.com/Imperatib/soc-automation-lab.git
cd soc-automation-lab
pip install -r requirements.txt
```

See individual scripts in `ir-playbooks/` and `triage-tools/` for usage flags and sample inputs.

---

## Roadmap

- [ ] Add `docs/architecture.md` and `docs/setup_guide.md`
- [ ] Add Splunk dashboard XML for SOC operations metrics
- [ ] Expand alert deduplication / noise-reduction tooling

---

## Certifications & Alignment

- **CompTIA CySA+** — Threat detection & response
- **CompTIA PenTest+** — Offensive TTP mapping to defensive rules
- **ISC2 SSCP** — Security operations and incident handling
