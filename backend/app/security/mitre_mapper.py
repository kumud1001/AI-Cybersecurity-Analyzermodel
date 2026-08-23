"""
MITRE ATT&CK mapping for detected cybersecurity events.

This module maps the attack labels produced by the existing
AI Cybersecurity Analyzer to MITRE ATT&CK techniques.

The mapper is intentionally kept separate from the ML model so
that MITRE mappings can be updated without retraining the model.
"""

from typing import Any


MITRE_ATTACK_MAP: dict[str, dict[str, Any]] = {
    "PORT_SCAN": {
        "technique_id": "T1046",
        "technique": "Network Service Scanning",
        "tactic": "Discovery",
        "description": (
            "The attacker may scan network services and ports "
            "to discover accessible services on a target."
        ),
        "recommendation": (
            "Investigate the source host, review contacted ports, "
            "and check for additional reconnaissance activity."
        ),
    },

    "PORT SCAN": {
        "technique_id": "T1046",
        "technique": "Network Service Scanning",
        "tactic": "Discovery",
        "description": (
            "The attacker may scan network services and ports "
            "to discover accessible services on a target."
        ),
        "recommendation": (
            "Investigate the source host, review contacted ports, "
            "and check for additional reconnaissance activity."
        ),
    },

    "BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "The attacker repeatedly attempts authentication "
            "in order to obtain valid credentials."
        ),
        "recommendation": (
            "Review authentication logs, identify the targeted "
            "account, and consider rate limiting or temporary blocking."
        ),
    },

    "BRUTE FORCE ATTACK": {
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Repeated authentication attempts may indicate "
            "credential guessing or brute-force activity."
        ),
        "recommendation": (
            "Review authentication failures and investigate "
            "the originating host."
        ),
    },

    "DDOS": {
        "technique_id": "T1498",
        "technique": "Network Denial of Service",
        "tactic": "Impact",
        "description": (
            "The attacker attempts to make network resources "
            "unavailable by overwhelming them with traffic."
        ),
        "recommendation": (
            "Investigate traffic volume and source distribution, "
            "then consider rate limiting and upstream mitigation."
        ),
    },

    "DOS": {
        "technique_id": "T1499",
        "technique": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": (
            "The attacker attempts to exhaust resources or "
            "otherwise make an endpoint unavailable."
        ),
        "recommendation": (
            "Review resource utilization and traffic patterns "
            "and apply appropriate rate limiting."
        ),
    },

    "SQL_INJECTION": {
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "The detected activity may represent exploitation "
            "of a publicly accessible application."
        ),
        "recommendation": (
            "Review application logs and input validation, "
            "and investigate the affected endpoint."
        ),
    },

    "XSS": {
        "technique_id": "T1189",
        "technique": "Drive-by Compromise",
        "tactic": "Initial Access",
        "description": (
            "Malicious web content may be used to compromise "
            "a user's browser or application context."
        ),
        "recommendation": (
            "Review the affected web application and apply "
            "appropriate output encoding and input validation."
        ),
    },

    "MALWARE": {
        "technique_id": "T1204",
        "technique": "User Execution",
        "tactic": "Execution",
        "description": (
            "Malicious activity may require user interaction "
            "or execution of a malicious file or content."
        ),
        "recommendation": (
            "Investigate the affected endpoint and examine "
            "associated files, processes, and user activity."
        ),
    },

    "UNAUTHORIZED_ACCESS": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": (
            "The activity may involve the use of valid or "
            "compromised credentials to access a resource."
        ),
        "recommendation": (
            "Review authentication events and verify whether "
            "the account activity is legitimate."
        ),
    },

    "PRIVILEGE_ESCALATION": {
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": (
            "The attacker may exploit a vulnerability to obtain "
            "higher privileges."
        ),
        "recommendation": (
            "Investigate the affected host, review process and "
            "authentication activity, and patch known vulnerabilities."
        ),
    },

    "AI_ANOMALY": {
        "technique_id": None,
        "technique": "Anomalous Network Activity",
        "tactic": "Unknown",
        "description": (
            "The machine-learning model detected behavior that "
            "differs from the expected traffic pattern."
        ),
        "recommendation": (
            "Investigate the associated network flow and correlate "
            "the alert with other security events."
        ),
    },

    "BENIGN": {
        "technique_id": None,
        "technique": "No ATT&CK technique",
        "tactic": "None",
        "description": "The traffic was classified as benign.",
        "recommendation": "No security response is required.",
    },
}


def normalize_attack_type(attack_type: str | None) -> str:
    """
    Normalize attack labels before looking them up.
    """

    if not attack_type:
        return "UNKNOWN"

    normalized = str(attack_type).strip().upper()

    normalized = normalized.replace("-", "_")
    normalized = normalized.replace("/", "_")

    return normalized


def get_mitre_mapping(attack_type: str | None) -> dict[str, Any]:
    """
    Return MITRE ATT&CK information for an attack type.

    Unknown attack labels are handled safely rather than causing
    the API request to fail.
    """

    key = normalize_attack_type(attack_type)

    mapping = MITRE_ATTACK_MAP.get(key)

    if mapping:
        return {
            "mapped": True,
            "attack_type": attack_type,
            **mapping,
        }

    return {
        "mapped": False,
        "attack_type": attack_type,
        "technique_id": None,
        "technique": "Unknown",
        "tactic": "Unknown",
        "description": (
            "No MITRE ATT&CK mapping is currently configured "
            "for this detection label."
        ),
        "recommendation": (
            "Review the alert manually and consider adding an "
            "appropriate ATT&CK mapping."
        ),
    }