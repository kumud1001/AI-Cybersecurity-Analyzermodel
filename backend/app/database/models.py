from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from backend.app.database.database import Base


class SecurityAlert(Base):

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)

    attack_type = Column(String(100), nullable=False)

    confidence = Column(Float, nullable=False)

    severity = Column(String(20), nullable=False)

    risk_score = Column(Float, nullable=False)

    predicted_class = Column(Integer, nullable=False)

    source = Column(String(50), default="XGBoost")

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )