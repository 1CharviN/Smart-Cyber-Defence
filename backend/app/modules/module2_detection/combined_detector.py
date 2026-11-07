from pathlib import Path

import joblib
import pandas as pd

from detection_result import DetectionResult
from random_forest_detector import FEATURE_COLUMNS


MODEL_DIR = Path("ml/models")

RF_MODEL_FILE = (
    MODEL_DIR / "random_forest.joblib"
)

IF_MODEL_FILE = (
    MODEL_DIR / "isolation_forest.joblib"
)


class CombinedDetector:
    """
    Combines:
        1. Random Forest for known attack classification
        2. Isolation Forest for unknown anomaly detection

    Important:
    Isolation Forest is supplementary. It does not need
    to agree with Random Forest for a known attack to be
    detected.
    """

    def __init__(
        self,
        confidence_threshold=0.80,
    ):

        if not RF_MODEL_FILE.exists():
            raise FileNotFoundError(
                f"Random Forest not found: "
                f"{RF_MODEL_FILE}"
            )

        if not IF_MODEL_FILE.exists():
            raise FileNotFoundError(
                f"Isolation Forest not found: "
                f"{IF_MODEL_FILE}"
            )

        self.rf_model = joblib.load(
            RF_MODEL_FILE
        )

        self.if_model = joblib.load(
            IF_MODEL_FILE
        )

        self.confidence_threshold = (
            confidence_threshold
        )

    def _to_dataframe(self, flow):

        data = {
            "destination_port": [
                flow.destination_port
            ],

            "flow_duration_sec": [
                flow.flow_duration_sec
            ],

            "total_fwd_packets": [
                flow.total_fwd_packets
            ],

            "total_backward_packets": [
                flow.total_backward_packets
            ],

            "total_fwd_bytes": [
                flow.total_fwd_bytes
            ],

            "total_backward_bytes": [
                flow.total_backward_bytes
            ],

            "flow_bytes_per_sec": [
                flow.flow_bytes_per_sec
            ],

            "flow_packets_per_sec": [
                flow.flow_packets_per_sec
            ],

            "fwd_packets_per_sec": [
                flow.fwd_packets_per_sec
            ],

            "bwd_packets_per_sec": [
                flow.bwd_packets_per_sec
            ],

            "packet_length_mean": [
                flow.packet_length_mean
            ],

            "packet_length_std": [
                flow.packet_length_std
            ],

            "syn_flag_count": [
                flow.syn_flag_count
            ],

            "rst_flag_count": [
                flow.rst_flag_count
            ],

            "ack_flag_count": [
                flow.ack_flag_count
            ],

            "average_packet_size": [
                flow.average_packet_size
            ],
        }

        return pd.DataFrame(
            data,
            columns=FEATURE_COLUMNS,
        )

    def analyze(self, flow):

        features = self._to_dataframe(
            flow
        )

        # -----------------------------------------------------
        # Random Forest
        # -----------------------------------------------------

        rf_prediction = self.rf_model.predict(
            features
        )[0]

        rf_probabilities = (
            self.rf_model.predict_proba(
                features
            )[0]
        )

        rf_confidence = float(
            rf_probabilities.max()
        )

        # -----------------------------------------------------
        # Isolation Forest
        # -----------------------------------------------------

        if_prediction = self.if_model.predict(
            features
        )[0]

        anomaly_score = float(
            self.if_model.decision_function(
                features
            )[0]
        )

        is_anomaly = (
            if_prediction == -1
        )

        # -----------------------------------------------------
        # Combined decision
        # -----------------------------------------------------

        known_attack = (
            rf_prediction != "NORMAL"
            and rf_confidence
            >= self.confidence_threshold
        )

        unknown_anomaly = (
            rf_prediction == "NORMAL"
            and is_anomaly
        )

        if known_attack:

            attack_type = rf_prediction

            if is_anomaly:
                detection_source = "BOTH"
            else:
                detection_source = (
                    "RANDOM_FOREST"
                )

            if rf_confidence >= 0.95:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        elif unknown_anomaly:

            attack_type = "UNKNOWN_ANOMALY"

            detection_source = (
                "ISOLATION_FOREST"
            )

            severity = "MEDIUM"

        else:

            attack_type = "NORMAL"

            detection_source = "NONE"

            severity = "LOW"

        # -----------------------------------------------------
        # Module 2 only raises the threat signal.
        #
        # Actual firewall action will be decided by Module 3.
        # -----------------------------------------------------

        threat_signal = (
            known_attack
            or unknown_anomaly
        )

        return {
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,

            "attack_type": attack_type,

            "rf_prediction": rf_prediction,

            "rf_confidence": rf_confidence,

            "anomaly": is_anomaly,

            "anomaly_score": anomaly_score,

            "severity": severity,

            "threat_signal": threat_signal,

            "detection_source": detection_source,
        }