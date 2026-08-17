from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from backend.app.schemas.prediction import NetworkFlow
from backend.app.ml.predictor import predict_attack
from backend.app.database.database import get_db
from backend.app.database.models import SecurityAlert


router = APIRouter(
    prefix="/api",
    tags=["AI Analysis"]
)


# ============================================================
# AI NETWORK FLOW ANALYSIS
# ============================================================

@router.post("/analyze")
def analyze_network_flow(
    flow: NetworkFlow,
    db: Session = Depends(get_db)
):

    try:

        # -----------------------------------------
        # AI / XGBoost prediction
        # -----------------------------------------

        result = predict_attack(
            flow.model_dump()
        )

        # -----------------------------------------
        # Save prediction to MySQL
        # -----------------------------------------

        alert = SecurityAlert(
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            severity=result["severity"],
            risk_score=result["risk_score"],
            predicted_class=result["predicted_class"],
            source="XGBoost"
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        # -----------------------------------------
        # Return response
        # -----------------------------------------

        return {
            "success": True,
            "prediction": result,
            "database": {
                "saved": True,
                "alert_id": alert.id
            }
        }

    except Exception as exc:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )


# ============================================================
# GET SECURITY ALERTS
# ============================================================

@router.get("/alerts")
def get_alerts(
    db: Session = Depends(get_db)
):

    try:

        alerts = (
            db.query(SecurityAlert)
            .order_by(
                SecurityAlert.created_at.desc()
            )
            .all()
        )

        return {
            "success": True,
            "count": len(alerts),

            "alerts": [

                {
                    "id": alert.id,
                    "attack_type": alert.attack_type,
                    "confidence": alert.confidence,
                    "severity": alert.severity,
                    "risk_score": alert.risk_score,
                    "predicted_class": alert.predicted_class,
                    "source": alert.source,
                    "created_at": alert.created_at
                }

                for alert in alerts
            ]
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )