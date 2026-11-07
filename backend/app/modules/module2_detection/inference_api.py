import ipaddress
import json
import sys
from types import SimpleNamespace
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

import joblib
import pandas as pd
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parents[4]
MODEL_DIR = PROJECT_ROOT / "ml" / "models"
LOG_FILE = (
    PROJECT_ROOT
    / "backend/app/modules/module2_detection/logs/detection_logs.jsonl"
)


DEFENCE_MODULE_DIR = PROJECT_ROOT / "backend/app/modules/module3_defence"
if str(DEFENCE_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(DEFENCE_MODULE_DIR))

from defence_controller import DefenceController
from defence_logger import DefenceLogger

DEFENCE_CONTROLLER = DefenceController(dry_run=True)
DEFENCE_LOGGER = DefenceLogger(
    log_file=DEFENCE_MODULE_DIR / "logs" / "defence_logs.jsonl"
)

FEATURE_COLUMNS = [
    "destination_port",
    "flow_duration_sec",
    "total_fwd_packets",
    "total_backward_packets",
    "total_fwd_bytes",
    "total_backward_bytes",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "fwd_packets_per_sec",
    "bwd_packets_per_sec",
    "packet_length_mean",
    "packet_length_std",
    "syn_flag_count",
    "rst_flag_count",
    "ack_flag_count",
    "average_packet_size",
]

router = APIRouter(prefix="/api/detection", tags=["AI Detection"])


class FlowDetectionRequest(BaseModel):
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    destination_port: int = Field(ge=0, le=65535)
    flow_duration_sec: float = Field(ge=0)
    total_fwd_packets: float = Field(ge=0)
    total_backward_packets: float = Field(ge=0)
    total_fwd_bytes: float = Field(ge=0)
    total_backward_bytes: float = Field(ge=0)
    flow_bytes_per_sec: float = Field(ge=0)
    flow_packets_per_sec: float = Field(ge=0)
    fwd_packets_per_sec: float = Field(ge=0)
    bwd_packets_per_sec: float = Field(ge=0)
    packet_length_mean: float = Field(ge=0)
    packet_length_std: float = Field(ge=0)
    syn_flag_count: float = Field(ge=0)
    rst_flag_count: float = Field(ge=0)
    ack_flag_count: float = Field(ge=0)
    average_packet_size: float = Field(ge=0)


@lru_cache(maxsize=1)
def load_models():
    rf_path = MODEL_DIR / "random_forest.joblib"
    if_path = MODEL_DIR / "isolation_forest.joblib"

    if not rf_path.is_file() or not if_path.is_file():
        raise FileNotFoundError("One or both saved ML models are missing.")

    return joblib.load(rf_path), joblib.load(if_path)


@router.post("/analyze")
def analyze_flow(request: FlowDetectionRequest):
    if request.source_ip:
        try:
            ipaddress.ip_address(request.source_ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid source_ip")

    if request.destination_ip:
        try:
            ipaddress.ip_address(request.destination_ip)
        except ValueError:
            raise HTTPException(
                status_code=400, detail="Invalid destination_ip"
            )

    try:
        rf_model, if_model = load_models()
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail=f"Could not load ML models: {exc}"
        ) from exc

    payload = request.model_dump()
    features = pd.DataFrame(
        [{name: payload[name] for name in FEATURE_COLUMNS}],
        columns=FEATURE_COLUMNS,
    )

    try:
        rf_prediction = str(rf_model.predict(features)[0])
        probabilities = rf_model.predict_proba(features)[0]
        confidence = float(max(probabilities))
        anomaly_score = float(if_model.decision_function(features)[0])
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Inference failed: {exc}"
        ) from exc

    # Candidate threshold selected during the preceding experiment.
    anomaly = anomaly_score < -0.10
    known_attack = (
        rf_prediction != "NORMAL" and confidence >= 0.80
    )
    unknown_anomaly = rf_prediction == "NORMAL" and anomaly

    if known_attack:
        attack_type = rf_prediction
        detection_source = "BOTH" if anomaly else "RANDOM_FOREST"
        severity = "HIGH" if confidence >= 0.95 else "MEDIUM"
    elif unknown_anomaly:
        attack_type = "UNKNOWN_ANOMALY"
        detection_source = "ISOLATION_FOREST"
        severity = "MEDIUM"
    elif rf_prediction != "NORMAL":
        attack_type = "LOW_CONFIDENCE"
        detection_source = "RANDOM_FOREST_LOW_CONFIDENCE"
        severity = "LOW"
    else:
        attack_type = "NORMAL"
        detection_source = "NONE"
        severity = "LOW"

    action_required = known_attack or unknown_anomaly

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": request.source_ip,
        "destination_ip": request.destination_ip,
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "confidence_percent": round(confidence * 100, 2),
        "severity": severity,
        "action_required": action_required,
        "rf_prediction": rf_prediction,
        "anomaly": anomaly,
        "anomaly_score": round(anomaly_score, 6),
        "detection_source": detection_source,
        "firewall_action": "DRY_RUN_ONLY",
    }

    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")
    except OSError as exc:
        raise HTTPException(
            status_code=500, detail=f"Could not write detection log: {exc}"
        ) from exc

    defence_input = {
        **event,
        "rf_confidence": confidence,
        "threat_signal": action_required,
    }

    try:
        defence_result = DEFENCE_CONTROLLER.process_detection(defence_input)
        DEFENCE_LOGGER.log(
            SimpleNamespace(**defence_result),
            defence_input,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not record dry-run defence decision: {exc}",
        ) from exc

    event["defence"] = defence_result
    return event
