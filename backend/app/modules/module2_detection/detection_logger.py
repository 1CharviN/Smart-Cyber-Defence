import json
from datetime import datetime, timezone
from pathlib import Path


LOG_DIR = Path(
    "backend/app/modules/module2_detection/logs"
)

LOG_FILE = LOG_DIR / "detection_logs.jsonl"


class DetectionLogger:
    """
    Stores Module 2 detection results as JSON Lines.

    Each line in the file represents one detection event.
    """

    def __init__(self, log_file=LOG_FILE):
        self.log_file = Path(log_file)

        self.log_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def log(self, result):
        event = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "source_ip": result.source_ip,

            "destination_ip": (
                result.destination_ip
            ),

            "attack_type": result.attack_type,

            "confidence": round(
                result.confidence,
                4,
            ),

            "confidence_percent": round(
                result.confidence * 100,
                2,
            ),

            "severity": result.severity,

            "action_required": (
                result.action_required
            ),
        }

        with self.log_file.open(
            "a",
            encoding="utf-8",
        ) as file:

            file.write(
                json.dumps(event)
                + "\n"
            )

        return event