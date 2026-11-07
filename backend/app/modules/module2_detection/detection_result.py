from dataclasses import dataclass
from typing import Optional


@dataclass
class DetectionResult:
    source_ip: Optional[str]
    destination_ip: Optional[str]

    attack_type: str
    confidence: float

    severity: str
    action_required: bool

    # Isolation Forest information
    is_anomaly: bool
    anomaly_score: float

    # Which model contributed to the decision
    detection_source: str