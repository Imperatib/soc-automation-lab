# SOC Automation Lab

**Author:** Brandon Imperati | CySA+ | PenTest+ | SSCP  
**Tools:** Python · Splunk · MITRE ATT&CK · ConnectWise  
**Focus:** Automated Incident Response · SIEM Detection Engineering · Alert Triage

---

## Overview

A collection of production-inspired SOC automation scripts and Splunk detection rules designed to reduce alert fatigue, accelerate triage, and automate response workflows. Built from real-world patterns encountered in managed security service environments.

These tools mirror the automation layer I engineered professionally — reducing MTTR by 35% in an enterprise environment monitoring 500+ endpoints.

---

## Repository Structure

```
soc-automation-lab/
├── detection-rules/
│   ├── splunk_correlation_rules.conf     # Splunk savedsearches for APT TTPs
│   ├── sentinel_kql_detections.kql       # Microsoft Sentinel KQL queries
│   └── rule_tuning_guide.md              # Alert fatigue reduction methodology
├── ir-playbooks/
│   ├── playbook_runner.py                # Automated IR playbook orchestrator
│   ├── playbooks/
│   │   ├── ransomware_response.json
│   │   ├── phishing_response.json
│   │   └── lateral_movement_response.json
│   └── evidence_collector.py            # Forensic evidence preservation script
├── triage-tools/
│   ├── log_parser.py                     # Multi-source log normalization
│   ├── ioc_enricher.py                   # IOC enrichment via VirusTotal/AbuseIPDB
│   └── alert_deduplicator.py            # Noise reduction / alert correlation
├── splunk-dashboards/
│   └── soc_operations_dashboard.xml     # Splunk dashboard for SOC metrics
└── docs/
    ├── architecture.md
    └── setup_guide.md
```

---

## Featured Scripts

### 1. `playbook_runner.py` — IR Playbook Orchestrator
Automated incident response engine that ingests SIEM alerts and executes the appropriate playbook based on alert type, severity, and affected asset classification.

**Capabilities:**
- Parses alerts from Splunk/ConnectWise webhook payloads
- Maps alert to playbook via rule engine (severity + TTP tag)
- Executes containment steps: endpoint isolation, account disable, block IOC
- Logs all actions with timestamps for chain-of-custody / audit trail
- Sends structured notifications to Slack/Teams channels

### 2. `ioc_enricher.py` — IOC Enrichment Engine
Enriches raw IOCs (IPs, domains, hashes) from SIEM alerts against threat intelligence APIs before analyst review — reducing manual lookups by ~70%.

**Supported Feeds:** VirusTotal · AbuseIPDB · Shodan · AlienVault OTX

### 3. `alert_deduplicator.py` — Alert Fatigue Reducer
Correlates and deduplicates repetitive alerts across a rolling time window. Groups related events into single incidents with a unified context summary.

---

## Splunk Detection Rules (MITRE ATT&CK Mapped)

| Rule Name | MITRE Tactic | Technique |
|-----------|-------------|-----------|
| Brute Force Login Spike | Credential Access | T1110 |
| Lateral Movement via PsExec | Lateral Movement | T1570 |
| Suspicious PowerShell Execution | Execution | T1059.001 |
| Data Exfil via DNS Tunneling | Exfiltration | T1048.003 |
| Persistence via Scheduled Task | Persistence | T1053.005 |
| Defense Evasion - Log Clearing | Defense Evasion | T1070.001 |

---

## Setup & Usage

```bash
# Clone the repository
git clone https://github.com/[yourusername]/soc-automation-lab.git
cd soc-automation-lab

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your API keys

# Run IOC enrichment
python triage-tools/ioc_enricher.py --input alerts.csv --output enriched_alerts.csv

# Execute IR playbook
python ir-playbooks/playbook_runner.py --alert-id 12345 --source splunk
```

---

## Impact Metrics (Production-Derived)

- **35% reduction** in alert fatigue through correlation rule tuning
- **~70% reduction** in manual IOC lookup time via automated enrichment
- **MTTR improvement** through playbook automation vs. manual triage
- Covers **6 MITRE ATT&CK tactics** across detection rule library

---

## Certifications & Alignment

This project aligns with skills validated by:
- **CompTIA CySA+** — Threat detection & response
- **CompTIA PenTest+** — Offensive TTP mapping to defensive rules
- **ISC2 SSCP** — Security operations and incident handling
