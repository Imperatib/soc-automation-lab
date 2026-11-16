#!/usr/bin/env python3
"""
playbook_runner.py — Automated Incident Response Playbook Orchestrator
Author: Brandon Imperati | SOC Automation Lab
Description:
    Ingests SIEM alerts (Splunk/ConnectWise webhook format) and executes
    the appropriate incident response playbook based on alert classification.
    Logs all actions for chain-of-custody / audit trail compliance.
"""

import json
import logging
import argparse
import datetime
from pathlib import Path

# ── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("ir_actions.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ── Playbook Registry ─────────────────────────────────────────────────────────
PLAYBOOK_MAP = {
    "ransomware":        "playbooks/ransomware_response.json",
    "phishing":          "playbooks/phishing_response.json",
    "lateral_movement":  "playbooks/lateral_movement_response.json",
    "brute_force":       "playbooks/phishing_response.json",   # reuse auth playbook
    "data_exfil":        "playbooks/ransomware_response.json", # containment-first
}

SEVERITY_THRESHOLD = 7  # Minimum severity (0-10) to trigger auto-response


class PlaybookRunner:
    def __init__(self, alert: dict):
        self.alert = alert
        self.alert_id = alert.get("alert_id", "UNKNOWN")
        self.severity = alert.get("severity", 0)
        self.alert_type = alert.get("type", "").lower()
        self.affected_host = alert.get("host", "")
        self.affected_user = alert.get("user", "")
        self.iocs = alert.get("iocs", [])
        self.timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        self.actions_taken = []

    def load_playbook(self) -> dict | None:
        """Load the appropriate playbook JSON based on alert type."""
        playbook_path = PLAYBOOK_MAP.get(self.alert_type)
        if not playbook_path:
            log.warning(f"[{self.alert_id}] No playbook mapped for alert type: {self.alert_type}")
            return None
        try:
            with open(playbook_path, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            log.error(f"[{self.alert_id}] Playbook file not found: {playbook_path}")
            return None

    def execute_step(self, step: dict) -> bool:
        """Execute a single playbook step and record the action."""
        action = step.get("action")
        description = step.get("description", "")
        log.info(f"[{self.alert_id}] EXECUTING: {action} — {description}")

        # SIMULATED execution: logs the action and audit trail only. Replace with real EDR/AD/firewall API calls.
        result = {
            "step": action,
            "description": description,
            "status": "completed",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "target": self.affected_host or self.affected_user
        }

        if action == "isolate_endpoint":
            result["detail"] = f"Endpoint isolation signal sent to EDR for host: {self.affected_host}"
        elif action == "disable_account":
            result["detail"] = f"Account disable request sent to AD/AAD for user: {self.affected_user}"
        elif action == "block_ioc":
            result["detail"] = f"Blocking {len(self.iocs)} IOC(s) at firewall/proxy: {self.iocs}"
        elif action == "preserve_evidence":
            result["detail"] = f"Memory dump + log collection initiated on: {self.affected_host}"
        elif action == "notify_team":
            result["detail"] = "Alert summary sent to SOC Slack channel #incidents"

        self.actions_taken.append(result)
        return True

    def run(self):
        """Main execution logic."""
        log.info(f"[{self.alert_id}] ── Playbook Runner Initiated ──")
        log.info(f"[{self.alert_id}] Alert Type: {self.alert_type} | Severity: {self.severity}/10 | Host: {self.affected_host}")

        # Severity gate
        if self.severity < SEVERITY_THRESHOLD:
            log.info(f"[{self.alert_id}] Severity {self.severity} below threshold {SEVERITY_THRESHOLD}. Logging only.")
            return self._generate_report(skipped=True)

        playbook = self.load_playbook()
        if not playbook:
            return self._generate_report(skipped=True)

        log.info(f"[{self.alert_id}] Loaded playbook: {playbook.get('name')}")

        # Execute steps in order
        for step in playbook.get("steps", []):
            success = self.execute_step(step)
            if not success and step.get("critical", False):
                log.error(f"[{self.alert_id}] Critical step failed. Halting playbook.")
                break

        return self._generate_report()

    def _generate_report(self, skipped: bool = False) -> dict:
        """Generate a structured incident report for audit trail."""
        report = {
            "incident_report": {
                "alert_id": self.alert_id,
                "alert_type": self.alert_type,
                "severity": self.severity,
                "affected_host": self.affected_host,
                "affected_user": self.affected_user,
                "iocs": self.iocs,
                "execution_timestamp": self.timestamp,
                "playbook_skipped": skipped,
                "actions_taken": self.actions_taken,
                "total_steps_executed": len(self.actions_taken)
            }
        }
        report_path = f"reports/incident_{self.alert_id}_{self.timestamp[:10]}.json"
        Path("reports").mkdir(exist_ok=True)
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        log.info(f"[{self.alert_id}] Incident report saved: {report_path}")
        log.info(f"[{self.alert_id}] ── Playbook Complete: {len(self.actions_taken)} steps executed ──")
        return report


# ── CLI Entry Point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SOC IR Playbook Runner")
    parser.add_argument("--alert-file", help="Path to JSON alert file")
    parser.add_argument("--alert-id", help="Alert ID (for inline test)")
    parser.add_argument("--source", default="splunk", choices=["splunk", "connectwise", "sentinel"])
    args = parser.parse_args()

    if args.alert_file:
        with open(args.alert_file) as f:
            alert = json.load(f)
    else:
        # Demo alert for testing
        alert = {
            "alert_id": args.alert_id or "DEMO-001",
            "type": "lateral_movement",
            "severity": 9,
            "host": "CORP-WKS-047",
            "user": "jsmith",
            "iocs": ["10.0.1.55", "malicious-c2.example.com"],
            "source": args.source
        }

    runner = PlaybookRunner(alert)
    report = runner.run()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
