from pathlib import Path

import joblib
import pandas as pd

from flow_schema import FlowRecord


MODEL_FILE = Path(
    "ml/models/random_forest.joblib"
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


class RandomForestDetector:
    """
    Loads the trained Random Forest model and performs
    prediction on a Module 1 FlowRecord.
    """

    def __init__(self, model_path=MODEL_FILE):
        if not Path(model_path).exists():
            raise FileNotFoundError(
                f"Random Forest model not found: {model_path}"
            )

        self.model = joblib.load(model_path)

    def flow_to_dataframe(
        self,
        flow: FlowRecord,
    ) -> pd.DataFrame:
        """
        Convert FlowRecord into exactly the feature
        structure expected by the trained model.
        """

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

    def predict(
        self,
        flow: FlowRecord,
    ):
        """
        Predict the traffic class and confidence.
        """

        features = self.flow_to_dataframe(
            flow
        )

        prediction = self.model.predict(
            features
        )[0]

        probabilities = (
            self.model.predict_proba(
                features
            )[0]
        )

        confidence = float(
            probabilities.max()
        )

        return {
            "prediction": prediction,
            "confidence": confidence,
            "confidence_percent": round(
                confidence * 100,
                2,
            ),
        }