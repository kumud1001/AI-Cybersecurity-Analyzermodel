from fastapi import APIRouter, HTTPException

from backend.app.schemas.prediction import NetworkFlow
from backend.app.ml.predictor import predict_attack


router = APIRouter(
    prefix="/api",
    tags=["AI Analysis"]
)


@router.post("/analyze")
def analyze_network_flow(flow: NetworkFlow):

    try:
        result = predict_attack(
            flow.model_dump()
        )

        return {
            "success": True,
            "prediction": result
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )