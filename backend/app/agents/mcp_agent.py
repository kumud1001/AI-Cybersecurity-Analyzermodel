from app.mcp.server import (
    analyze_security_event,
    calculate_risk,
    generate_security_summary,
)

from app.security.mitre_mapper import get_mitre_mapping


class MCPBasedSecurityAgent:
    """
    AI Cybersecurity Agent using MCP-exposed security capabilities.
    """

    def analyze(self, alert: dict) -> dict:

        # -------------------------------------------------
        # Step 1: Analyze network event
        # -------------------------------------------------

        event_result = analyze_security_event(
            source_ip=alert.get("source_ip") or "unknown",
            destination_ip=alert.get("destination_ip") or "unknown",
            protocol=alert.get("protocol") or "UNKNOWN",
            destination_port=alert.get("destination_port") or 0,
            packet_count=alert.get("packet_count", 1),
        )

        # -------------------------------------------------
        # Preserve the ML-detected threat
        # -------------------------------------------------

        detected_threat = alert.get("threat")

        if detected_threat:

            existing_threats = [
                threat.upper()
                for threat in event_result["threats"]
            ]

            if detected_threat.upper() not in existing_threats:
                event_result["threats"].append(
                    detected_threat
                )

            # Keep event severity consistent with ML result
            event_result["severity"] = alert.get(
                "severity",
                event_result["severity"]
            )

            # Keep the strongest risk score
            event_result["risk_score"] = max(
                event_result["risk_score"],
                float(alert.get("risk_score", 0))
            )

        # -------------------------------------------------
        # Step 2: Calculate risk
        # -------------------------------------------------

        risk_result = calculate_risk(
            severity=alert.get(
                "severity",
                event_result["severity"]
            ),
            confidence=float(
                alert.get("confidence", 0.0)
            ),
        )

        # -------------------------------------------------
        # Step 3: MITRE ATT&CK mapping
        # -------------------------------------------------

        threat = alert.get("threat")

        if not threat and event_result["threats"]:
            threat = event_result["threats"][0]

        if not threat:
            threat = "UNKNOWN"

        # Use the shared MITRE mapper
        mitre_result = get_mitre_mapping(threat)

        # -------------------------------------------------
        # Step 4: Generate SOC summary
        # -------------------------------------------------

        technique_id = mitre_result.get(
            "technique_id"
        )

        technique_name = mitre_result.get(
            "technique",
            "Unknown"
        )

        if technique_id:
            mitre_technique = (
                f"{technique_id} - "
                f"{technique_name}"
            )
        else:
            mitre_technique = "Unknown"

        summary = generate_security_summary(
            threat=threat,
            severity=risk_result["risk_level"],
            confidence=float(
                alert.get("confidence", 0.0)
            ),
            mitre_technique=mitre_technique,
            risk_score=risk_result["risk_score"],
        )

        # -------------------------------------------------
        # Final agent result
        # -------------------------------------------------

        return {
            "agent": "MCP Cybersecurity Agent",

            "workflow": [
                "analyze_security_event",
                "calculate_risk",
                "map_mitre_attack",
                "generate_security_summary",
            ],

            "event_analysis": event_result,

            "risk_analysis": risk_result,

            "mitre_attack": mitre_result,

            "summary": summary,
        }