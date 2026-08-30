"""
MITRE ATT&CK mapping for detected cybersecurity events.

This module maps the attack labels produced by the existing
AI Cybersecurity Analyzer to MITRE ATT&CK techniques.

The mapper is intentionally kept separate from the ML model so
that MITRE mappings can be updated without retraining the model.
"""

from typing import Any


# backend/app/security/mitre_mapper.py

MITRE_MAPPINGS = {

    "BENIGN": {
        "mapped": False,
        "attack_type": "BENIGN",
        "technique_id": None,
        "technique": "None",
        "tactic": "None",
        "description": "Benign network activity.",
        "recommendation": "No immediate security action required."
    },

    "PORT_SCAN": {
        "mapped": True,
        "attack_type": "PORT_SCAN",
        "technique_id": "T1046",
        "technique": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may scan network services to identify available systems and services.",
        "recommendation": "Investigate the source IP and monitor repeated connection attempts."
    },

    "PORTSCAN": {
        "mapped": True,
        "attack_type": "PortScan",
        "technique_id": "T1046",
        "technique": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may scan network services to identify available systems and services.",
        "recommendation": "Investigate the source IP and monitor repeated connection attempts."
    },

    "DDOS": {
        "mapped": True,
        "attack_type": "DDoS",
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform denial-of-service attacks against network resources.",
        "recommendation": "Investigate traffic sources and apply network filtering or rate limiting."
    },

    "BRUTE_FORCE": {
        "mapped": True,
        "attack_type": "BRUTE_FORCE",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use repeated attempts to obtain valid credentials.",
        "recommendation": "Investigate authentication attempts and consider account protection measures."
    },

    "FTP-PATATOR": {
        "mapped": True,
        "attack_type": "FTP-Patator",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "FTP-Patator represents repeated attempts against FTP authentication.",
        "recommendation": "Investigate the source IP, review FTP authentication logs, and consider blocking repeated failed attempts."
    },

    "SSH-PATATOR": {
        "mapped": True,
        "attack_type": "SSH-Patator",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "SSH-Patator represents repeated attempts against SSH authentication.",
        "recommendation": "Investigate SSH authentication logs and restrict repeated login attempts."
    },

    "WEB ATTACK - BRUTE FORCE": {
        "mapped": True,
        "attack_type": "Web Attack - Brute Force",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": "Repeated authentication attempts against a web application.",
        "recommendation": "Review web authentication logs and implement rate limiting."
    },

    "SQL_INJECTION": {
        "mapped": True,
        "attack_type": "SQL_INJECTION",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Attackers may exploit vulnerable public-facing applications using SQL injection.",
        "recommendation": "Inspect application logs and validate database input handling."
    },

    "WEB ATTACK - SQL INJECTION": {
        "mapped": True,
        "attack_type": "Web Attack - SQL Injection",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "SQL injection activity targeting a web application.",
        "recommendation": "Review application requests and implement parameterized database queries."
    },

    "XSS": {
        "mapped": True,
        "attack_type": "XSS",
        "technique_id": "T1189",
        "technique": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Cross-site scripting may be used to execute malicious content in a victim's browser.",
        "recommendation": "Review web requests and implement appropriate input validation and output encoding."
    },

    "WEB ATTACK - XSS": {
        "mapped": True,
        "attack_type": "Web Attack - XSS",
        "technique_id": "T1189",
        "technique": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": "Cross-site scripting activity detected against a web application.",
        "recommendation": "Review malicious web requests and strengthen application input validation."
    },

    "PRIVILEGE_ESCALATION": {
        "mapped": True,
        "attack_type": "PRIVILEGE_ESCALATION",
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges.",
        "recommendation": "Investigate affected systems and review privilege escalation activity."
    }
}


def get_mitre_mapping(attack_type: str) -> dict:

    if not attack_type:
        attack_type = "UNKNOWN"

    normalized = (
        str(attack_type)
        .strip()
        .upper()
    )

    return MITRE_MAPPINGS.get(
        normalized,
        {
            "mapped": False,
            "attack_type": attack_type,
            "technique_id": None,
            "technique": "Unknown",
            "tactic": "Unknown",
            "description": "No MITRE ATT&CK mapping is currently configured for this detection label.",
            "recommendation": "Review the alert manually and consider adding an appropriate ATT&CK mapping."
        }
    )

