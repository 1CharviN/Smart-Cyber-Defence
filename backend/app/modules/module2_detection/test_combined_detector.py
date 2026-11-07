from pathlib import Path
import sys

import pandas as pd


PROJECT_ROOT = Path(
    __file__
).resolve().parents[4]

MODULE1_PATH = (
    PROJECT_ROOT
    / "backend"
    / "app"
    / "modules"
    / "module1_monitoring"
)

if str(MODULE1_PATH) not in sys.path:
    sys.path.insert(
        0,
        str(MODULE1_PATH),
    )


from flow_schema import FlowRecord
from combined_detector import CombinedDetector


TEST_FILE = Path(
    "ml/dataset/processed/test.csv"
)


def row_to_flow(row):

    return FlowRecord(

        source_ip="TEST_SOURCE",

        destination_ip="TEST_DESTINATION",

        source_port=12345,

        destination_port=int(
            row["destination_port"]
        ),

        protocol="TCP",

        flow_duration_sec=float(
            row["flow_duration_sec"]
        ),

        total_fwd_packets=int(
            row["total_fwd_packets"]
        ),

        total_backward_packets=int(
            row["total_backward_packets"]
        ),

        total_fwd_bytes=int(
            row["total_fwd_bytes"]
        ),

        total_backward_bytes=int(
            row["total_backward_bytes"]
        ),

        flow_bytes_per_sec=float(
            row["flow_bytes_per_sec"]
        ),

        flow_packets_per_sec=float(
            row["flow_packets_per_sec"]
        ),

        fwd_packets_per_sec=float(
            row["fwd_packets_per_sec"]
        ),

        bwd_packets_per_sec=float(
            row["bwd_packets_per_sec"]
        ),

        packet_length_mean=float(
            row["packet_length_mean"]
        ),

        packet_length_std=float(
            row["packet_length_std"]
        ),

        syn_flag_count=int(
            row["syn_flag_count"]
        ),

        rst_flag_count=int(
            row["rst_flag_count"]
        ),

        ack_flag_count=int(
            row["ack_flag_count"]
        ),

        average_packet_size=float(
            row["average_packet_size"]
        ),
    )


def main():

    print("=" * 70)
    print(
        "COMBINED DETECTOR TEST"
    )
    print("=" * 70)

    print(
        "\nLoading test dataset..."
    )

    test = pd.read_csv(
        TEST_FILE
    )

    print(
        f"Test rows loaded: "
        f"{len(test):,}"
    )

    # Take one example from each class.
    selected_rows = []

    for label in [
        "NORMAL",
        "DDOS",
        "PORT_SCAN",
        "BRUTE_FORCE",
    ]:

        match = test[
            test["Project_Label"] == label
        ]

        if not match.empty:
            selected_rows.append(
                match.iloc[0]
            )

    print(
        f"Selected {len(selected_rows)} "
        f"test flows."
    )

    detector = CombinedDetector()

    print(
        "\nCombined detector loaded."
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "COMBINED DETECTION RESULTS"
    )

    print(
        "=" * 70
    )

    for index, row in enumerate(
        selected_rows,
        start=1,
    ):

        flow = row_to_flow(
            row
        )

        result = detector.analyze(
            flow
        )

        print(
            f"\nSample {index}"
        )

        print(
            f"Actual Class    : "
            f"{row['Project_Label']}"
        )

        print(
            f"RF Prediction   : "
            f"{result['rf_prediction']}"
        )

        print(
            f"RF Confidence   : "
            f"{result['rf_confidence'] * 100:.2f}%"
        )

        print(
            f"IF Anomaly      : "
            f"{result['anomaly']}"
        )

        print(
            f"Anomaly Score   : "
            f"{result['anomaly_score']:.6f}"
        )

        print(
            f"Final Detection : "
            f"{result['attack_type']}"
        )

        print(
            f"Severity        : "
            f"{result['severity']}"
        )

        print(
            f"Threat Signal   : "
            f"{result['threat_signal']}"
        )

        print(
            f"Detection Source: "
            f"{result['detection_source']}"
        )

    print(
        "\n" + "=" * 70
    )

    print(
        "COMBINED DETECTOR TEST COMPLETE"
    )

    print(
        "=" * 70
    )


if __name__ == "__main__":
    main()