from fastapi import APIRouter
from pydantic import BaseModel

from app.agents.mcp_agent import MCPBasedSecurityAgent


router = APIRouter(
    prefix="/agent",
    tags=["AI Agent"]
)


class SecurityAlert(BaseModel):

    threat: str | None = None
    severity: str | None = None
    confidence: float = 0.0
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str | None = None
    destination_port: int | None = None
    packet_count: int = 1
    risk_score: int | float = 0


@router.post("/analyze")
def analyze_with_agent(alert: SecurityAlert):

    agent = MCPBasedSecurityAgent()

    result = agent.analyze(
        alert.model_dump()
    )

    return {
        "agent": "MCP Cybersecurity Agent",
        "status": "completed",
        "analysis": result
    }