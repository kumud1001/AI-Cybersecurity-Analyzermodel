from sqlalchemy.orm import Session

from app.database.models import Alert


def get_alerts(db: Session):
    return (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .all()
    )