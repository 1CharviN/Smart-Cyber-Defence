import json
from collections import deque
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

PROJECT_ROOT = Path(__file__).resolve().parents[4]
FLOW_FILE = (
    PROJECT_ROOT
    / "backend/app/modules/module1_monitoring/flows.jsonl"
)

_lock = Lock()


class MonitoringService:
    """File-backed flow store shared by the collector and FastAPI."""

    def __init__(self, max_size=1000):
        self.max_size = max_size

    def add_flow(self, flow):
        if is_dataclass(flow):
            record = asdict(flow)
        elif isinstance(flow, dict):
            record = dict(flow)
        else:
            record = vars(flow).copy()

        record["observed_at"] = datetime.now(timezone.utc).isoformat()
        FLOW_FILE.parent.mkdir(parents=True, exist_ok=True)

        with _lock:
            with FLOW_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")

    def get_flows(self, limit=100):
        if not FLOW_FILE.exists():
            return []

        with _lock:
            with FLOW_FILE.open("r", encoding="utf-8") as handle:
                records = deque(
                    (
                        json.loads(line)
                        for line in handle
                        if line.strip()
                    ),
                    maxlen=self.max_size,
                )

        result = list(records)[-limit:]
        result.reverse()
        return result

    def collector_running(self):
        """Return true only when the PID belongs to our collector script."""
        pid_file = Path(__file__).resolve().parent / "collector.pid"
        try:
            pid = int(pid_file.read_text().strip())
            cmdline = (Path("/proc") / str(pid) / "cmdline").read_bytes()
            return b"continuous_monitor.py" in cmdline
        except (OSError, ValueError, ProcessLookupError):
            return False

    def summary(self):
        records = self.get_flows(self.max_size)

        return {
            "collector_integration": "jsonl_file",
            "collector_running": self.collector_running(),
            "flows_buffered": len(records),
            "packets_observed": sum(
                r.get("total_fwd_packets", 0)
                + r.get("total_backward_packets", 0)
                for r in records
            ),
            "bytes_observed": sum(
                r.get("total_fwd_bytes", 0)
                + r.get("total_backward_bytes", 0)
                for r in records
            ),
            "protocols": sorted({
                r.get("protocol")
                for r in records
                if r.get("protocol")
            }),
            "flow_file": str(FLOW_FILE),
            "message": (
                "Counts reflect recent buffered flow records. "
                + (
                    "Continuous packet capture is running."
                    if self.collector_running()
                    else "Continuous packet capture is not running."
                )
            ),
        }


monitoring_service = MonitoringService()
