from mcp.server import MCPServer


mcp = MCPServer(
    "AI Cybersecurity Analyzer",
    instructions="MCP server providing cybersecurity analysis tools."
)


# ---------------------------------------------------------
# TOOL 1: Analyze Network Event
# ---------------------------------------------------------

def analyze_security_event(
    source_ip: str,
    destination_ip: str,
    protocol: str,
    destination_port: int,
    packet_count: int
) -> dict:

    threats = []

    if packet_count >= 100:
        threats.append("DDOS")

    if destination_port in [22, 23, 3389]:
        threats.append("SUSPICIOUS_SERVICE")

    if packet_count >= 20:
        threats.append("PORT_SCAN")

    if protocol.upper() not in ["TCP", "UDP", "ICMP"]:
        threats.append("UNKNOWN_PROTOCOL")

    if "DDOS" in threats:
        severity = "CRITICAL"
    elif threats:
        severity = "HIGH"
    else:
        severity = "LOW"

    risk_score = min(100, len(threats) * 30)

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "destination_port": destination_port,
        "packet_count": packet_count,
        "threats": threats,
        "severity": severity,
        "risk_score": risk_score
    }


# ---------------------------------------------------------
# TOOL 2: MITRE ATT&CK
# ---------------------------------------------------------
def map_mitre_attack(threat: str) -> dict:

    mappings = {

        "PORT_SCAN": {
            "technique_id": "T1046",
            "technique": "Network Service Scanning"
        },

        "PORTSCAN": {
            "technique_id": "T1046",
            "technique": "Network Service Scanning"
        },

        "DDOS": {
            "technique_id": "T1498",
            "technique": "Network Denial of Service"
        },

        "BRUTE_FORCE": {
            "technique_id": "T1110",
            "technique": "Brute Force"
        },

        "FTP-PATATOR": {
            "technique_id": "T1110",
            "technique": "Brute Force"
        },

        "SSH-PATATOR": {
            "technique_id": "T1110",
            "technique": "Brute Force"
        },

        "WEB ATTACK - BRUTE FORCE": {
            "technique_id": "T1110",
            "technique": "Brute Force"
        },

        "SQL_INJECTION": {
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application"
        },

        "WEB ATTACK - SQL INJECTION": {
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application"
        },

        "XSS": {
            "technique_id": "T1189",
            "technique": "Drive-by Compromise"
        },

        "WEB ATTACK - XSS": {
            "technique_id": "T1189",
            "technique": "Drive-by Compromise"
        },

        "PRIVILEGE_ESCALATION": {
            "technique_id": "T1068",
            "technique": "Exploitation for Privilege Escalation"
        }
    }

    normalized_threat = (
        threat.strip().upper()
    )

    return mappings.get(
        normalized_threat,
        {
            "technique_id": "UNKNOWN",
            "technique": "No MITRE mapping available"
        }
    )





# ---------------------------------------------------------
# TOOL 3: Risk Calculation
# ---------------------------------------------------------

def calculate_risk(
    severity: str,
    confidence: float
) -> dict:

    severity_weights = {
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 100
    }

    base_score = severity_weights.get(
        severity.upper(),
        25
    )

    risk_score = round(
        base_score * confidence,
        2
    )

    if risk_score >= 80:
        level = "CRITICAL"
    elif risk_score >= 60:
        level = "HIGH"
    elif risk_score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "severity": severity,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": level
    }


# ---------------------------------------------------------
# TOOL 4: Security Summary
# ---------------------------------------------------------

def generate_security_summary(
    threat: str,
    severity: str,
    confidence: float,
    mitre_technique: str,
    risk_score: float
) -> str:

    return (
        f"Security Alert Summary\n"
        f"----------------------\n"
        f"Threat: {threat}\n"
        f"Severity: {severity}\n"
        f"Confidence: {confidence:.2%}\n"
        f"Risk Score: {risk_score}\n"
        f"MITRE ATT&CK: {mitre_technique}\n\n"
        f"Recommended Action:\n"
        f"Investigate the source IP, review affected systems, "
        f"and monitor subsequent network activity."
    )


# ---------------------------------------------------------
# REGISTER TOOLS
# ---------------------------------------------------------

mcp.add_tool(
    analyze_security_event,
    name="analyze_security_event",
    description="Analyze a network event and identify potential threats."
)

mcp.add_tool(
    map_mitre_attack,
    name="map_mitre_attack",
    description="Map a detected threat to a MITRE ATT&CK technique."
)

mcp.add_tool(
    calculate_risk,
    name="calculate_risk",
    description="Calculate cybersecurity risk from severity and confidence."
)

mcp.add_tool(
    generate_security_summary,
    name="generate_security_summary",
    description="Generate a concise SOC-style security summary."
)


# ---------------------------------------------------------
# START MCP SERVER
# ---------------------------------------------------------

if __name__ == "__main__":
    mcp.run()