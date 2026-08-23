from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Alert
from app.security.mitre_mapper import get_mitre_mapping


router = APIRouter(
    prefix="/api",
    tags=["Analysis"]
)


@router.post("/analyze")
def analyze_alert(
    payload: dict,
    db: Session = Depends(get_db)
):
    attack_type = payload.get("attack_type", "UNKNOWN")

    # Get MITRE ATT&CK mapping for the detected attack
    mitre_attack = get_mitre_mapping(attack_type)

    alert = Alert(
    attack_type=attack_type,
    confidence=float(payload.get("confidence", 0)),
    severity=payload.get("severity", "LOW"),
    risk_score=float(payload.get("risk_score", 0)),
    predicted_class=int(payload.get("predicted_class", 0)),
    source="XGBoost",

    mitre_technique_id=mitre_attack.get("technique_id"),
    mitre_technique=mitre_attack.get("technique"),
    mitre_tactic=mitre_attack.get("tactic"),
    mitre_description=mitre_attack.get("description"),
    mitre_recommendation=mitre_attack.get("recommendation"),

    created_at=datetime.now()
)
    db.add(alert)
    db.commit()
    db.refresh(alert)

    return {
        "success": True,

        "prediction": {
            "attack_type": attack_type,
            "confidence": float(payload.get("confidence", 0)),
            "severity": payload.get("severity", "LOW"),
            "risk_score": float(payload.get("risk_score", 0)),
            "predicted_class": int(payload.get("predicted_class", 0))
        },

        "mitre_attack": mitre_attack,

        "database": {
            "saved": True,
            "alert_id": alert.id
        }
    }