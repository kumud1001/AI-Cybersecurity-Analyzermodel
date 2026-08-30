from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.agents.security_agent import SecurityAgent


router = APIRouter(
    prefix="/agent",
    tags=["AI Agent"]
)


class SecurityAlert(BaseModel):

    threat: str
    severity: str
    confidence: float
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    destination_port: int | None = None
    risk_score: int


@router.post("/analyze")
def analyze_with_agent(alert: SecurityAlert):

    agent = SecurityAgent()

    result = agent.analyze_alert(
        alert.model_dump()
    )

    return {
        "agent": "AI Cybersecurity Analyst",
        "status": "completed",
        "analysis": result
    }