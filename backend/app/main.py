from fastapi import FastAPI

from backend.app.api.analysis import router as analysis_router


app = FastAPI(
    title="AI Cybersecurity Analyzer",
    description="AI-based network intrusion detection API using XGBoost.",
    version="1.0.0"
)

app.include_router(analysis_router)


@app.get("/")
def root():
    return {
        "message": "AI Cybersecurity Analyzer API is running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }