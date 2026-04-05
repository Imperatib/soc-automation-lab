#!/usr/bin/env python3
"""
ioc_enricher.py — Automated IOC Enrichment Engine
Author: [Your Name] | SOC Automation Lab
Description:
    Enriches raw IOCs (IPs, domains, file hashes) from SIEM alerts against
    multiple threat intelligence APIs. Produces a structured report for
    analyst review — eliminating manual lookups and accelerating triage.

Supported feeds:
    - VirusTotal (IPs, domains, hashes)
    - AbuseIPDB (IP reputation)
    - AlienVault OTX (pulse/indicator lookup)
"""

import csv
import json
import time
import hashlib
import logging
import argparse
import ipaddress
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Config (set via env vars or config.yaml in production) ───────────────────
VT_API_KEY    = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_API_KEY"
OTX_API_KEY   = "YOUR_OTX_API_KEY"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

RISK_COLORS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}


# ── IOC Type Detection ────────────────────────────────────────────────────────
def detect_ioc_type(ioc: str) -> str:
    """Classify an IOC as IP, domain, MD5, SHA1, or SHA256."""
    ioc = ioc.strip()
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^[a-fA-F0-9]{64}$", ioc): return "sha256"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc): return "sha1"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc): return "md5"
    if re.match(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$", ioc): return "domain"
    return "unknown"


# ── Mock Enrichment (replace with real API calls) ────────────────────────────
def enrich_virustotal(ioc: str, ioc_type: str) -> dict:
    """
    Query VirusTotal for the given IOC.
    In production: requests.get(f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}", headers=headers)
    """
    log.info(f"  [VT] Querying VirusTotal for {ioc_type}: {ioc}")
    time.sleep(0.2)  # Rate limit simulation

    # Simulated response structure matching VT API v3
    return {
        "source": "VirusTotal",
        "malicious_votes": 12,
        "harmless_votes": 45,
        "suspicious_votes": 3,
        "last_analysis_date": "2024-11-15",
        "community_score": -12,
        "tags": ["malware", "c2"],
        "note": "Replace with live API call using VT_API_KEY"
    }


def enrich_abuseipdb(ip: str) -> dict:
    """
    Query AbuseIPDB for IP reputation.
    In production: requests.get("https://api.abuseipdb.com/api/v2/check", headers=..., params={"ipAddress": ip})
    """
    log.info(f"  [ABUSEIPDB] Querying AbuseIPDB for IP: {ip}")
    time.sleep(0.2)

    return {
        "source": "AbuseIPDB",
        "abuse_confidence_score": 87,
        "total_reports": 34,
        "country_code": "RU",
        "isp": "Hosting Provider LLC",
        "usage_type": "Data Center/Web Hosting/Transit",
        "is_tor": False,
        "note": "Replace with live API call using ABUSEIPDB_KEY"
    }


def enrich_otx(ioc: str, ioc_type: str) -> dict:
    """
    Query AlienVault OTX for threat intelligence pulses.
    In production: OTXv2(OTX_API_KEY).get_indicator_details_full(IndicatorTypes.IP_ADDR, ioc)
    """
    log.info(f"  [OTX] Querying OTX for {ioc_type}: {ioc}")
    time.sleep(0.2)

    return {
        "source": "AlienVault OTX",
        "pulse_count": 7,
        "pulse_names": ["APT Campaign Q3 2024", "Cobalt Strike C2 Infrastructure"],
        "malware_families": ["CobaltStrike", "Metasploit"],
        "note": "Replace with live API call using OTX_API_KEY"
    }


# ── Risk Scoring ──────────────────────────────────────────────────────────────
def calculate_risk(vt_result: dict, abuse_result: Optional[dict] = None) -> str:
    """Derive a composite risk level from multi-source enrichment data."""
    score = 0
    if vt_result.get("malicious_votes", 0) >= 10: score += 40
    elif vt_result.get("malicious_votes", 0) >= 5:  score += 20
    if abuse_result and abuse_result.get("abuse_confidence_score", 0) >= 75: score += 35
    elif abuse_result and abuse_result.get("abuse_confidence_score", 0) >= 40: score += 15
    if vt_result.get("community_score", 0) < -5: score += 15

    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    if score > 0:   return "LOW"
    return "UNKNOWN"


# ── Main Enrichment Pipeline ──────────────────────────────────────────────────
def enrich_ioc(ioc: str) -> dict:
    """Run full enrichment pipeline for a single IOC."""
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    log.info(f"[+] Enriching {ioc_type.upper()}: {ioc}")

    result = {
        "ioc": ioc,
        "type": ioc_type,
        "enrichment_timestamp": datetime.utcnow().isoformat() + "Z",
        "sources": {}
    }

    vt = enrich_virustotal(ioc, ioc_type)
    result["sources"]["virustotal"] = vt

    abuse = None
    if ioc_type == "ip":
        abuse = enrich_abuseipdb(ioc)
        result["sources"]["abuseipdb"] = abuse

    otx = enrich_otx(ioc, ioc_type)
    result["sources"]["otx"] = otx

    result["risk_level"] = calculate_risk(vt, abuse)
    result["risk_indicator"] = RISK_COLORS[result["risk_level"]]
    log.info(f"  → Risk: {result['risk_indicator']} {result['risk_level']}")

    return result


def process_file(input_path: str, output_path: str):
    """Process a CSV or newline-delimited file of IOCs."""
    iocs = []
    path = Path(input_path)

    if path.suffix == ".csv":
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                ioc_val = row.get("ioc") or row.get("indicator") or list(row.values())[0]
                if ioc_val: iocs.append(ioc_val.strip())
    else:
        iocs = [line.strip() for line in path.read_text().splitlines() if line.strip()]

    log.info(f"[*] Processing {len(iocs)} IOC(s) from {input_path}")
    results = [enrich_ioc(ioc) for ioc in iocs]

    # Summary stats
    risk_counts = {}
    for r in results:
        risk_counts[r["risk_level"]] = risk_counts.get(r["risk_level"], 0) + 1

    output = {
        "enrichment_run": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_iocs": len(results),
            "risk_summary": risk_counts,
            "results": results
        }
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    log.info(f"[✓] Enrichment complete. Report saved: {output_path}")
    log.info(f"    Summary: {risk_counts}")


def main():
    parser = argparse.ArgumentParser(description="IOC Enrichment Engine")
    parser.add_argument("--input",  required=True, help="Input file (CSV or .txt, one IOC per line)")
    parser.add_argument("--output", default="reports/enriched_iocs.json", help="Output JSON report path")
    args = parser.parse_args()
    process_file(args.input, args.output)


if __name__ == "__main__":
    main()
