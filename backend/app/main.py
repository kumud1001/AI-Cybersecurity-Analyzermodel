from fastapi import FastAPI

from app.api.alerts import router as alerts_router


app = FastAPI(
    title="AI Cybersecurity Platform",
    version="1.0"
)

app.include_router(alerts_router)


@app.get("/")
def home():
    return {
        "message": "AI Cybersecurity Platform Running"
    }