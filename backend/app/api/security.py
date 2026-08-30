from fastapi import APIRouter

from backend.app.detection.rule_engine import run_rule_engine


router = APIRouter(
    prefix="/security",
    tags=["Security Analysis"]
)


@router.post("/analyze")
def analyze_packet(packet: dict):

    alerts = run_rule_engine(packet)

    if alerts:

        return {
            "status": "THREAT_DETECTED",
            "alerts": alerts
        }

    return {
        "status": "SAFE",
        "alerts": []
    }