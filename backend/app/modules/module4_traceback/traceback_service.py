import json
import os
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[4]
DETECTION_LOG = PROJECT_ROOT / "backend/app/modules/module2_detection/logs/detection_logs.jsonl"
DEFENCE_LOG = PROJECT_ROOT / "backend/app/modules/module3_defence/logs/defence_logs.jsonl"
MODULE4_LOG_DIR = PROJECT_ROOT / "backend/app/modules/module4_traceback/logs"
INVESTIGATION_LOG = MODULE4_LOG_DIR / "investigations.jsonl"
VALIDATION_LOG = MODULE4_LOG_DIR / "twin_validations.jsonl"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_jsonl(path, limit=100):
    records = []
    if not path.exists():
        return records

    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
            except json.JSONDecodeError:
                continue

    return records[-limit:]


def append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, default=str) + "\n")


class TracebackService:
    """Investigation records, IP enrichment and Digital Twin validation."""

    def recent_investigations(self, limit=100):
        return read_jsonl(INVESTIGATION_LOG, limit)

    def investigate(self, source_ip, detection=None, defence=None):
        try:
            parsed_ip = str(ipaddress.ip_address(source_ip))
        except (ValueError, TypeError):
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address")

        record = {
            "investigation_id": f"INV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            "timestamp": utc_now(),
            "source_ip": parsed_ip,
            "detection": detection or {},
            "defence": defence or {},
            "traceback": self.lookup_ip(parsed_ip),
            "identity_confirmed": False,
        }
        append_jsonl(INVESTIGATION_LOG, record)
        return record

    def lookup_ip(self, source_ip):
        try:
            parsed_ip = ipaddress.ip_address(source_ip)
        except (ValueError, TypeError):
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address")

        # Private, loopback and reserved addresses have no public-IP enrichment.
        if not parsed_ip.is_global:
            return {
                "source_ip": str(parsed_ip),
                "status": "private_or_non_global_ip",
                "probable_origin": "Local or non-public address",
                "geolocation": None,
                "isp": None,
                "reputation": None,
                "identity_confirmed": False,
            }

        ai_ori_url = os.getenv("AIORI_API_URL", "").strip()
        if not ai_ori_url:
            return {
                "source_ip": str(parsed_ip),
                "status": "aiori_not_configured",
                "probable_origin": "Unknown — configure AIORI to request enrichment",
                "geolocation": None,
                "isp": None,
                "reputation": None,
                "identity_confirmed": False,
            }

        # AIORI response is treated as enrichment, not proof of identity.
        url = f"{ai_ori_url.rstrip('/')}/traceback?ip={parsed_ip}"
        try:
            request = Request(url, headers={"Accept": "application/json"})
            with urlopen(request, timeout=5) as response:
                if response.status != 200:
                    raise URLError(f"HTTP {response.status}")
                data = json.loads(response.read().decode("utf-8"))

            return {
                "source_ip": str(parsed_ip),
                "status": "aiori_response_received",
                "probable_origin": data.get("probable_origin", "Unknown"),
                "geolocation": data.get("geolocation"),
                "isp": data.get("isp"),
                "reputation": data.get("reputation"),
                "identity_confirmed": False,
            }
        except Exception as exc:
            return {
                "source_ip": str(parsed_ip),
                "status": "aiori_lookup_failed",
                "probable_origin": "Unknown — enrichment request failed",
                "geolocation": None,
                "isp": None,
                "reputation": None,
                "error": str(exc),
                "identity_confirmed": False,
            }

    def validate_twin(self, scenario, source_ip=None, before=None, after=None,
                      simulation_executed=False, notes=""):
        if not isinstance(scenario, str) or not scenario.strip():
            raise ValueError("scenario must be a non-empty string")

        # Never claim a Mininet simulation ran unless the caller explicitly
        # confirms it was run and provides its actual before/after observations.
        record = {
            "validation_id": f"TWIN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            "timestamp": utc_now(),
            "scenario": scenario.strip(),
            "source_ip": source_ip,
            "before_metrics": before or {},
            "after_metrics": after or {},
            "simulation_executed": bool(simulation_executed),
            "result_status": (
                "executed_result_recorded"
                if simulation_executed
                else "validation_recorded_not_executed"
            ),
            "notes": notes,
        }
        append_jsonl(VALIDATION_LOG, record)
        return record

    def recent_validations(self, limit=100):
        return read_jsonl(VALIDATION_LOG, limit)

    def summary(self):
        detections = read_jsonl(DETECTION_LOG, 10000)
        defences = read_jsonl(DEFENCE_LOG, 10000)
        investigations = read_jsonl(INVESTIGATION_LOG, 10000)
        validations = read_jsonl(VALIDATION_LOG, 10000)

        attacks = [
            d for d in detections
            if str(d.get("attack_type", "NORMAL")).upper() != "NORMAL"
        ]
        return {
            "detection_log_records": len(detections),
            "non_normal_detections": len(attacks),
            "defence_log_records": len(defences),
            "investigations": len(investigations),
            "twin_validation_records": len(validations),
            "twin_simulations_executed": sum(
                bool(v.get("simulation_executed")) for v in validations
            ),
            "firewall_commands_executed": sum(
                bool(d.get("executed")) for d in defences
            ),
        }
