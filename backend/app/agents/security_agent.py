class SecurityAgent:

    def analyze_alert(self, alert: dict) -> str:

        threat = alert.get("threat")
        severity = alert.get("severity")
        confidence = alert.get("confidence")
        risk_score = alert.get("risk_score")

        recommendations = {
            "PORT_SCAN": "Investigate the source IP and monitor connection attempts.",
            "DDOS": "Check traffic volume and consider rate limiting or network filtering.",
            "BRUTE_FORCE": "Review authentication logs and consider account protection.",
            "SQL_INJECTION": "Inspect application inputs and apply parameterized queries.",
            "XSS": "Review input validation and output encoding."
        }

        recommendation = recommendations.get(
            threat,
            "Investigate the alert and monitor the affected system."
        )

        return f"""
AI Cybersecurity Analysis

Threat: {threat}
Severity: {severity}
Confidence: {confidence}
Risk Score: {risk_score}

Assessment:
The security analyzer identified {threat} activity
with {severity} severity.

Recommended Action:
{recommendation}
"""