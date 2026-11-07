from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix


TRAIN_FILE = Path(
    "ml/dataset/processed/train.csv"
)

TEST_FILE = Path(
    "ml/dataset/processed/test.csv"
)

MODEL_DIR = Path(
    "ml/models"
)

MODEL_FILE = (
    MODEL_DIR / "isolation_forest.joblib"
)

LABEL_COLUMN = "Project_Label"

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

NORMAL_SAMPLE_SIZE = 100_000

RANDOM_STATE = 42


def main():

    print("=" * 70)
    print("ISOLATION FOREST TRAINING")
    print("=" * 70)

    if not TRAIN_FILE.exists():
        print(
            f"ERROR: Training file not found: {TRAIN_FILE}"
        )
        return

    if not TEST_FILE.exists():
        print(
            f"ERROR: Test file not found: {TEST_FILE}"
        )
        return

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ---------------------------------------------------------
    # Load only NORMAL training rows
    # ---------------------------------------------------------

    print(
        "\nLoading NORMAL training samples..."
    )

    normal_parts = []

    remaining = NORMAL_SAMPLE_SIZE

    for chunk in pd.read_csv(
        TRAIN_FILE,
        chunksize=50_000,
    ):

        normal_rows = chunk[
            chunk[LABEL_COLUMN] == "NORMAL"
        ]

        if normal_rows.empty:
            continue

        take = min(
            len(normal_rows),
            remaining,
        )

        if take <= 0:
            break

        sampled = normal_rows.sample(
            n=take,
            random_state=RANDOM_STATE,
        )

        normal_parts.append(
            sampled
        )

        remaining -= take

        if remaining <= 0:
            break

    normal_train = pd.concat(
        normal_parts,
        ignore_index=True,
    )

    normal_train = normal_train.sample(
        frac=1,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    X_normal = normal_train[
        FEATURE_COLUMNS
    ]

    print(
        f"Normal training samples: "
        f"{len(X_normal):,}"
    )

    # ---------------------------------------------------------
    # Create Isolation Forest
    # ---------------------------------------------------------

    print(
        "\nCreating Isolation Forest..."
    )

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    # ---------------------------------------------------------
    # Train
    # ---------------------------------------------------------

    print(
        "\nTraining Isolation Forest..."
    )

    model.fit(
        X_normal
    )

    print(
        "Training completed."
    )

    # ---------------------------------------------------------
    # Load test data
    # ---------------------------------------------------------

    print(
        "\nLoading test dataset..."
    )

    test = pd.read_csv(
        TEST_FILE
    )

    X_test = test[
        FEATURE_COLUMNS
    ]

    y_test = test[
        LABEL_COLUMN
    ]

    print(
        f"Test rows: {len(test):,}"
    )

    # ---------------------------------------------------------
    # Predict anomaly / normal
    # ---------------------------------------------------------

    print(
        "\nGenerating anomaly predictions..."
    )

    predictions = model.predict(
        X_test
    )

    scores = model.decision_function(
        X_test
    )

    # Isolation Forest:
    #  1  = normal / inlier
    # -1  = anomaly / outlier

    is_anomaly = (
        predictions == -1
    )

    # ---------------------------------------------------------
    # Overall anomaly statistics
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("ANOMALY DETECTION RESULTS")
    print("=" * 70)

    total_anomalies = int(
        is_anomaly.sum()
    )

    total_normal = len(
        is_anomaly
    ) - total_anomalies

    print(
        f"\nPredicted normal   : "
        f"{total_normal:,}"
    )

    print(
        f"Predicted anomaly  : "
        f"{total_anomalies:,}"
    )

    print(
        f"Anomaly percentage : "
        f"{total_anomalies / len(is_anomaly) * 100:.2f}%"
    )

    # ---------------------------------------------------------
    # Results by actual class
    # ---------------------------------------------------------

    print(
        "\nAnomaly detection by actual class:"
    )

    for label in [
        "NORMAL",
        "DDOS",
        "PORT_SCAN",
        "BRUTE_FORCE",
    ]:

        mask = (
            y_test.values == label
        )

        count = int(
            mask.sum()
        )

        if count == 0:
            continue

        detected = int(
            is_anomaly[mask].sum()
        )

        percentage = (
            detected / count * 100
        )

        print(
            f"{label:<15} "
            f"{detected:>7,} / "
            f"{count:>7,} "
            f"({percentage:6.2f}% anomalous)"
        )

    # ---------------------------------------------------------
    # False positive rate on NORMAL traffic
    # ---------------------------------------------------------

    normal_mask = (
        y_test.values == "NORMAL"
    )

    normal_total = int(
        normal_mask.sum()
    )

    normal_false_positive = int(
        is_anomaly[normal_mask].sum()
    )

    if normal_total > 0:

        false_positive_rate = (
            normal_false_positive
            / normal_total
        )

        print(
            "\nNORMAL false-positive rate:"
        )

        print(
            f"{false_positive_rate * 100:.2f}%"
        )

    # ---------------------------------------------------------
    # Attack anomaly detection rate
    # ---------------------------------------------------------

    attack_mask = (
        y_test.values != "NORMAL"
    )

    attack_total = int(
        attack_mask.sum()
    )

    attacks_detected = int(
        is_anomaly[attack_mask].sum()
    )

    if attack_total > 0:

        attack_detection_rate = (
            attacks_detected
            / attack_total
        )

        print(
            "\nOverall attack anomaly "
            "detection rate:"
        )

        print(
            f"{attack_detection_rate * 100:.2f}%"
        )

    # ---------------------------------------------------------
    # Save model
    # ---------------------------------------------------------

    joblib.dump(
        model,
        MODEL_FILE,
    )

    print("\n" + "=" * 70)
    print("MODEL SAVED")
    print("=" * 70)

    print(
        f"\nModel file:\n{MODEL_FILE}"
    )

    print(
        "\nIsolation Forest training complete."
    )


if __name__ == "__main__":
    main()