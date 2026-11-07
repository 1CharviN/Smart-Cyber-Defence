from pathlib import Path

import joblib

from detection_result import DetectionResult
from random_forest_detector import RandomForestDetector


MODEL_FILE = Path(
    "ml/models/random_forest.joblib"
)


class DetectionEngine:
    """
    Module 2 detection engine.

    Uses the trained Random Forest model to classify
    a network flow and converts the prediction into
    a security detection result.
    """

    def __init__(
        self,
        confidence_threshold=0.80,
    ):
        self.detector = RandomForestDetector(
            MODEL_FILE
        )

        self.confidence_threshold = (
            confidence_threshold
        )

    def determine_severity(
        self,
        prediction: str,
        confidence: float,
    ) -> str:

        if prediction == "NORMAL":
            return "LOW"

        if confidence >= 0.95:
            return "HIGH"

        if confidence >= 0.80:
            return "MEDIUM"

        return "LOW"

    def analyze(self, flow):

        result = self.detector.predict(
            flow
        )

        prediction = result[
            "prediction"
        ]

        confidence = result[
            "confidence"
        ]

        is_attack = (
            prediction != "NORMAL"
        )

        action_required = (
            is_attack
            and confidence
            >= self.confidence_threshold
        )

        severity = self.determine_severity(
            prediction,
            confidence,
        )

        return DetectionResult(
            source_ip=flow.source_ip,

            destination_ip=(
                flow.destination_ip
            ),

            attack_type=prediction,

            confidence=confidence,

            severity=severity,

            action_required=action_required,

            # This engine uses Random Forest only.
            # Isolation Forest is handled separately.
            is_anomaly=False,
            anomaly_score=0.0,
            detection_source="RANDOM_FOREST",
        )