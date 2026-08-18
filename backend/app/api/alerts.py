from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.crud import get_alerts
from app.database.schemas import AlertResponse


router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"]
)


@router.get("/", response_model=list[AlertResponse])
def read_alerts(db: Session = Depends(get_db)):
    return get_alerts(db)


