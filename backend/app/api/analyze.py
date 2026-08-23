from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Alert
from app.ml.predictor import predict_attack
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
    # =========================================================
    # XGBOOST PREDICTION
    # =========================================================

    prediction = predict_attack(payload)

    attack_type = prediction["attack_type"]

    confidence = float(
        prediction["confidence"]
    )

    severity = prediction["severity"]

    risk_score = float(
        prediction["risk_score"]
    )

    predicted_class = int(
        prediction["predicted_class"]
    )

    # =========================================================
    # MITRE ATT&CK MAPPING
    # =========================================================

    mitre_attack = get_mitre_mapping(
        attack_type
    )

    # =========================================================
    # SAVE ALERT
    # =========================================================

    alert = Alert(
        attack_type=attack_type,
        confidence=confidence,
        severity=severity,
        risk_score=risk_score,
        predicted_class=predicted_class,
        source="XGBoost",

        mitre_technique_id=mitre_attack.get(
            "technique_id"
        ),

        mitre_technique=mitre_attack.get(
            "technique"
        ),

        mitre_tactic=mitre_attack.get(
            "tactic"
        ),

        mitre_description=mitre_attack.get(
            "description"
        ),

        mitre_recommendation=mitre_attack.get(
            "recommendation"
        ),

        created_at=datetime.now()
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    # =========================================================
    # API RESPONSE
    # =========================================================

    return {
        "success": True,

        "prediction": {
            "attack_type": attack_type,
            "confidence": confidence,
            "severity": severity,
            "risk_score": risk_score,
            "predicted_class": predicted_class,

            "class_probabilities":
                prediction.get(
                    "class_probabilities",
                    {}
                ),

            "top_predictions":
                prediction.get(
                    "top_predictions",
                    []
                )
        },

        "mitre_attack": mitre_attack,

        "database": {
            "saved": True,
            "alert_id": alert.id
        }
    }