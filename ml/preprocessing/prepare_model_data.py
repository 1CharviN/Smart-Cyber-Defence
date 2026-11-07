from pathlib import Path

import numpy as np
import pandas as pd


INPUT_PATH = Path(
    "ml/dataset/processed/selected_attacks.csv"
)

OUTPUT_PATH = Path(
    "ml/dataset/processed/model_features.csv"
)


# Exact column names present in selected_attacks.csv
FEATURE_COLUMNS = {
    "Destination Port": "destination_port",
    "Flow Duration": "flow_duration_sec",
    "Total Fwd Packets": "total_fwd_packets",
    "Total Backward Packets": "total_backward_packets",
    "Total Length of Fwd Packets": "total_fwd_bytes",
    "Total Length of Bwd Packets": "total_backward_bytes",
    "Flow Bytes/s": "flow_bytes_per_sec",
    "Flow Packets/s": "flow_packets_per_sec",
    "Fwd Packets/s": "fwd_packets_per_sec",
    "Bwd Packets/s": "bwd_packets_per_sec",
    "Packet Length Mean": "packet_length_mean",
    "Packet Length Std": "packet_length_std",
    "SYN Flag Count": "syn_flag_count",
    "RST Flag Count": "rst_flag_count",
    "ACK Flag Count": "ack_flag_count",
    "Average Packet Size": "average_packet_size",
}


CHUNK_SIZE = 50_000


def main():
    if not INPUT_PATH.exists():
        print(f"Input file not found: {INPUT_PATH}")
        return

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Remove previous output so we create a fresh file.
    if OUTPUT_PATH.exists():
        OUTPUT_PATH.unlink()

    # ---------------------------------------------------------
    # Verify that all required columns actually exist.
    # ---------------------------------------------------------
    header = pd.read_csv(
        INPUT_PATH,
        nrows=0,
    )

    available_columns = set(header.columns)

    required_columns = set(
        FEATURE_COLUMNS.keys()
    ) | {"Project_Label"}

    missing_columns = (
        required_columns - available_columns
    )

    if missing_columns:
        print("ERROR: Required columns are missing:")
        for column in sorted(missing_columns):
            print(f"  - {column}")
        return

    usecols = list(FEATURE_COLUMNS.keys()) + [
        "Project_Label"
    ]

    total_rows_read = 0
    total_rows_written = 0
    total_rows_removed = 0

    class_counts = {}

    first_chunk = True

    print("=" * 70)
    print("CREATING ML-READY DATASET")
    print("=" * 70)

    print(f"\nInput : {INPUT_PATH}")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Chunk size: {CHUNK_SIZE:,}")

    # ---------------------------------------------------------
    # Read dataset in chunks.
    # ---------------------------------------------------------
    for chunk_number, chunk in enumerate(
        pd.read_csv(
            INPUT_PATH,
            usecols=usecols,
            chunksize=CHUNK_SIZE,
        ),
        start=1,
    ):

        total_rows_read += len(chunk)

        print(
            f"\nProcessing chunk {chunk_number} "
            f"({len(chunk):,} rows)..."
        )

        # -----------------------------------------------------
        # Rename CICIDS2017 feature names to our project names.
        # -----------------------------------------------------
        chunk = chunk.rename(
            columns=FEATURE_COLUMNS
        )

        feature_names = list(
            FEATURE_COLUMNS.values()
        )

        # -----------------------------------------------------
        # Convert features to numeric.
        # Invalid values become NaN.
        # -----------------------------------------------------
        for feature in feature_names:
            chunk[feature] = pd.to_numeric(
                chunk[feature],
                errors="coerce",
            )

        # -----------------------------------------------------
        # CICIDS2017 Flow Duration is in microseconds.
        # Convert to seconds.
        # -----------------------------------------------------
        chunk["flow_duration_sec"] = (
            chunk["flow_duration_sec"]
            / 1_000_000.0
        )

        # -----------------------------------------------------
        # Replace infinite values with NaN.
        # -----------------------------------------------------
        chunk[feature_names] = (
            chunk[feature_names]
            .replace(
                [np.inf, -np.inf],
                np.nan,
            )
        )

        # -----------------------------------------------------
        # Find rows containing NaN in any selected feature.
        # -----------------------------------------------------
        invalid_mask = (
            chunk[feature_names]
            .isna()
            .any(axis=1)
        )

        removed = int(
            invalid_mask.sum()
        )

        # Keep only valid rows.
        clean_chunk = chunk.loc[
            ~invalid_mask
        ].copy()

        total_rows_removed += removed

        # -----------------------------------------------------
        # Count classes.
        # -----------------------------------------------------
        counts = (
            clean_chunk["Project_Label"]
            .value_counts()
        )

        for label, count in counts.items():
            class_counts[label] = (
                class_counts.get(label, 0)
                + int(count)
            )

        # -----------------------------------------------------
        # Keep only selected features + project label.
        # -----------------------------------------------------
        output_columns = feature_names + [
            "Project_Label"
        ]

        clean_chunk = clean_chunk[
            output_columns
        ]

        # -----------------------------------------------------
        # Append to output CSV.
        # -----------------------------------------------------
        clean_chunk.to_csv(
            OUTPUT_PATH,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False,
        )

        first_chunk = False

        written = len(clean_chunk)
        total_rows_written += written

        print(
            f"Valid rows   : {written:,}"
        )

        print(
            f"Removed rows : {removed:,}"
        )

    print("\n" + "=" * 70)
    print("ML DATASET CREATION COMPLETE")
    print("=" * 70)

    print(
        f"\nRows read    : {total_rows_read:,}"
    )

    print(
        f"Rows written : {total_rows_written:,}"
    )

    print(
        f"Rows removed : {total_rows_removed:,}"
    )

    print(
        f"\nOutput file:"
    )

    print(OUTPUT_PATH)

    print("\nFinal class distribution:")

    for label, count in sorted(
        class_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        print(
            f"{label:<15} {count:,}"
        )


if __name__ == "__main__":
    main()