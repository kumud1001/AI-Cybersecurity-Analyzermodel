from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Float
from sqlalchemy import DateTime

from app.database.database import Base


class Alert(Base):

    __tablename__ = "security_alerts"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    attack_type = Column(
        String(100),
        nullable=False
    )

    confidence = Column(
        Float,
        nullable=False
    )

    severity = Column(
        String(20),
        nullable=False
    )

    risk_score = Column(
        Float,
        nullable=False
    )

    predicted_class = Column(
        Integer,
        nullable=False
    )

    source = Column(
        String(50),
        nullable=True
    )

    created_at = Column(
        DateTime,
        nullable=False
    )