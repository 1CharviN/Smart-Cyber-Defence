from fastapi import FastAPI
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

app.include_router(router)
app.include_router(detection_router)


@app.get("/")
def root():
    return {
        "message": "Smart Cyber Defence API is running",
        "docs": "/docs",
        "health": "/api/health",
    }
