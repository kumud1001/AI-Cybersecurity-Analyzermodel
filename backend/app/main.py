from fastapi import FastAPI

from app.api.alerts import router as alerts_router
from app.api.dashboard import router as dashboard_router
from app.api.analyze import router as analyze_router


app = FastAPI(
    title="AI Cybersecurity Platform",
    version="1.0"
)

app.include_router(alerts_router)
app.include_router(dashboard_router)
app.include_router(analyze_router)


@app.get("/")
def home():
    return {
        "message": "AI Cybersecurity Platform Running"
    }