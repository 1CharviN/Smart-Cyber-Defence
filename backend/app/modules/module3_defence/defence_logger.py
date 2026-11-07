import json
from datetime import datetime, timezone
from pathlib import Path


LOG_DIR = Path(
    "backend/app/modules/module3_defence/logs"
)

LOG_FILE = (
    LOG_DIR / "defence_logs.jsonl"
)


class DefenceLogger:
    """
    Stores Module 3 defence decisions
    as JSON Lines.
    """

    def __init__(
        self,
        log_file=LOG_FILE,
    ):
        self.log_file = Path(
            log_file
        )

        self.log_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def log(
        self,
        action,
        detection,
    ):

        event = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "source_ip": action.source_ip,

            "attack_type": detection.get(
                "attack_type"
            ),

            "severity": detection.get(
                "severity"
            ),

            "rf_confidence": detection.get(
                "rf_confidence"
            ),

            "anomaly": detection.get(
                "anomaly"
            ),

            "anomaly_score": detection.get(
                "anomaly_score"
            ),

            "action": action.action,

            "reason": action.reason,

            "approved": action.approved,

            "executed": action.executed,

            "mode": "DRY_RUN",
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