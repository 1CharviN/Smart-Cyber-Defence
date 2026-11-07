import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.modules.module5_dashboard.dashboard_api import router
from backend.app.modules.module2_detection.inference_api import router as detection_router

app = FastAPI(
    title="Smart Cyber Defence",
    description=(
        "Autonomous Cyber Defence with Digital Twin. "
        "Detection, defence logging, traceback and validation APIs."
    ),

    version="1.1.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(detection_router)


@app.get("/")
def root():
    return {
        "message": "Smart Cyber Defence API is running",
        "docs": "/docs",
        "health": "/api/health",
    }
