from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.database import get_db
from app.database.models import Alert


router = APIRouter(
    prefix="/api",
    tags=["Dashboard"]
)


@router.get("/dashboard/stats")
def dashboard_stats(
    db: Session = Depends(get_db)
):
    try:

        total_alerts = (
            db.query(Alert).count()
        )

        critical = (
            db.query(Alert)
            .filter(Alert.severity == "CRITICAL")
            .count()
        )

        high = (
            db.query(Alert)
            .filter(Alert.severity == "HIGH")
            .count()
        )

        medium = (
            db.query(Alert)
            .filter(Alert.severity == "MEDIUM")
            .count()
        )

        low = (
            db.query(Alert)
            .filter(Alert.severity == "LOW")
            .count()
        )

        attack_results = (
            db.query(
                Alert.attack_type,
                func.count(Alert.id)
            )
            .group_by(Alert.attack_type)
            .all()
        )

        attack_counts = {
            attack_type: count
            for attack_type, count in attack_results
        }

        return {
            "success": True,
            "total_alerts": total_alerts,
            "severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "attack_counts": attack_counts
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )