import ipaddress
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.app.modules.module1_monitoring.monitoring_service import monitoring_service

from backend.app.modules.module4_traceback.traceback_service import (
    TracebackService,
)

router = APIRouter(prefix="/api", tags=["Module 4 and 5"])
traceback_service = TracebackService()

PROJECT_ROOT = Path(__file__).resolve().parents[4]
DETECTION_LOG = PROJECT_ROOT / "backend/app/modules/module2_detection/logs/detection_logs.jsonl"
DEFENCE_LOG = PROJECT_ROOT / "backend/app/modules/module3_defence/logs/defence_logs.jsonl"


def read_records(path: Path, limit: int = 100):
    records = []
    if not path.exists():
        return records

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                import json
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
            except (ValueError, TypeError):
                continue

    return records[-limit:]


class InvestigationRequest(BaseModel):
    source_ip: str
    detection: dict[str, Any] = Field(default_factory=dict)
    defence: dict[str, Any] = Field(default_factory=dict)


class TwinValidationRequest(BaseModel):
    scenario: str = Field(min_length=1, max_length=200)
    source_ip: Optional[str] = None
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    simulation_executed: bool = False
    notes: str = Field(default="", max_length=2000)


@router.get("/health")
def api_health():
    return {
        "status": "ok",
        "service": "Smart Cyber Defence API",
        "firewall_execution": "disabled_by_dry_run_design",
    }


@router.get("/dashboard/summary")
def dashboard_summary():
    summary = traceback_service.summary()
    summary["recent_detections"] = len(read_records(DETECTION_LOG, 100))
    summary["recent_defence_actions"] = len(read_records(DEFENCE_LOG, 100))
    return summary


@router.get("/dashboard/detections")
def dashboard_detections(limit: int = Query(default=50, ge=1, le=500)):
    return {"items": read_records(DETECTION_LOG, limit)}


@router.get("/dashboard/defences")
def dashboard_defences(limit: int = Query(default=50, ge=1, le=500)):
    return {"items": read_records(DEFENCE_LOG, limit)}


@router.get("/traceback/{source_ip}")
def traceback_lookup(source_ip: str):
    try:
        return traceback_service.lookup_ip(source_ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/investigations")
def create_investigation(request: InvestigationRequest):
    try:
        return traceback_service.investigate(
            source_ip=request.source_ip,
            detection=request.detection,
            defence=request.defence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/investigations")
def list_investigations(limit: int = Query(default=50, ge=1, le=500)):
    return {"items": traceback_service.recent_investigations(limit)}


@router.get("/twin/validations")
def list_twin_validations(limit: int = Query(default=50, ge=1, le=500)):
    return {"items": traceback_service.recent_validations(limit)}


@router.post("/twin/validations")
def create_twin_validation(request: TwinValidationRequest):
    if request.source_ip:
        try:
            ipaddress.ip_address(request.source_ip)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="source_ip must be a valid IPv4 or IPv6 address",
            )

    return traceback_service.validate_twin(
        scenario=request.scenario,
        source_ip=request.source_ip,
        before=request.before,
        after=request.after,
        simulation_executed=request.simulation_executed,
        notes=request.notes,
    )



@router.get("/monitoring/summary")
def monitoring_summary():
    return monitoring_service.summary()


@router.get("/monitoring/flows")
def monitoring_flows(limit: int = Query(default=100, ge=1, le=1000)):
    return {
        "items": monitoring_service.get_flows(limit),
        "count": len(monitoring_service.get_flows(limit)),
    }
