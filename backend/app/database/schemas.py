from datetime import datetime
from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int
    attack_type: str
    confidence: float
    severity: str
    risk_score: float
    predicted_class: int
    source: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True