from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Alert


router = APIRouter(
    prefix="/api",
    tags=["Analysis"]
)


@router.post("/analyze")
def analyze_alert(
    payload: dict,
    db: Session = Depends(get_db)
):

    alert = Alert(
        attack_type=payload.get("attack_type", "UNKNOWN"),
        confidence=float(payload.get("confidence", 0)),
        severity=payload.get("severity", "LOW"),
        risk_score=float(payload.get("risk_score", 0)),
        predicted_class=int(payload.get("predicted_class", 0)),
        source="XGBoost",
        created_at=datetime.now()
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return {
        "success": True,
        "database": {
            "saved": True,
            "alert_id": alert.id
        }
    }