from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.database.database import get_db
from backend.app.database.models import SecurityAlert


router = APIRouter(
    prefix="/api",
    tags=["Dashboard"]
)


@router.get("/dashboard/stats")
def dashboard_stats(
    db: Session = Depends(get_db)
):

    try:

        # -----------------------------------------
        # Total alerts
        # -----------------------------------------

        total_alerts = (
            db.query(SecurityAlert)
            .count()
        )

        # -----------------------------------------
        # Severity counts
        # -----------------------------------------

        critical = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.severity == "CRITICAL"
            )
            .count()
        )

        high = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.severity == "HIGH"
            )
            .count()
        )

        medium = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.severity == "MEDIUM"
            )
            .count()
        )

        low = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.severity == "LOW"
            )
            .count()
        )

        # -----------------------------------------
        # Attack type counts
        # -----------------------------------------

        attack_results = (
            db.query(
                SecurityAlert.attack_type,
                func.count(
                    SecurityAlert.id
                )
            )
            .group_by(
                SecurityAlert.attack_type
            )
            .all()
        )

        attack_counts = {
            attack_type: count
            for attack_type, count
            in attack_results
        }

        # -----------------------------------------
        # Response
        # -----------------------------------------

        return {

            "success": True,

            "total_alerts":
                total_alerts,

            "severity": {

                "critical":
                    critical,

                "high":
                    high,

                "medium":
                    medium,

                "low":
                    low
            },

            "attack_counts":
                attack_counts
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )