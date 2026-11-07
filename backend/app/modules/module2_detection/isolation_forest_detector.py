from pathlib import Path

import joblib
import pandas as pd


MODEL_FILE = Path(
    "ml/models/isolation_forest.joblib"
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


class IsolationForestDetector:
    """
    Loads the trained Isolation Forest model and
    checks whether a network flow looks anomalous.
    """

    def __init__(self, model_path=MODEL_FILE):

        if not Path(model_path).exists():
            raise FileNotFoundError(
                f"Isolation Forest model not found: "
                f"{model_path}"
            )

        self.model = joblib.load(
            model_path
        )

    def flow_to_dataframe(self, flow):
        """
        Convert a FlowRecord into the exact
        feature structure used during training.
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

    def predict(self, flow):

        features = self.flow_to_dataframe(
            flow
        )

        prediction = self.model.predict(
            features
        )[0]

        anomaly_score = float(
            self.model.decision_function(
                features
            )[0]
        )

        return {
            "is_anomaly": prediction == -1,
            "anomaly_prediction": int(
                prediction
            ),
            "anomaly_score": anomaly_score,
        }
