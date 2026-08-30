from datetime import datetime

from sqlalchemy.orm import Session

from app.database.models import Alert


def get_alerts(db: Session):
    return (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .all()
    )


def create_alert(
    db: Session,
    attack_type: str,
    severity: str,
    source_ip: str = None,
    destination_ip: str = None,
    score: float = 0.0,
    message: str = None
):
    alert = Alert(
        attack_type=attack_type,
        confidence=1.0,
        severity=severity,
        risk_score=score,
        predicted_class=1,
        source=source_ip,
        created_at=datetime.utcnow()
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert