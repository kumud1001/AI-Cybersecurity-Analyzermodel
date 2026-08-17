from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.analysis import router as analysis_router
from backend.app.api.dashboard import router as dashboard_router


app = FastAPI(
    title="AI Cybersecurity Analyzer",
    description="AI-based network intrusion detection API using XGBoost.",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROUTERS
# ============================================================

app.include_router(analysis_router)
app.include_router(dashboard_router)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "message": "AI Cybersecurity Analyzer API is running"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }