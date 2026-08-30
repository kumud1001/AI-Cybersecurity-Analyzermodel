from fastapi import FastAPI

from app.api.alerts import router as alerts_router
from app.api.dashboard import router as dashboard_router
from app.api.analyze import router as analyze_router
from fastapi.middleware.cors import CORSMiddleware
from app.agents.agent_router import router as agent_router


app = FastAPI(
    title="AI Cybersecurity Platform",
    version="1.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



app.include_router(alerts_router)
app.include_router(dashboard_router)
app.include_router(analyze_router)
app.include_router(agent_router)



@app.get("/")
def home():
    return {
        "message": "AI Cybersecurity Platform Running"
    }