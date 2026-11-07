from pathlib import Path

import numpy as np
import pandas as pd


DATASET_PATH = Path(
    "ml/dataset/processed/selected_attacks.csv"
)


def main():
    if not DATASET_PATH.exists():
        print(f"Dataset not found: {DATASET_PATH}")
        return

    print("=" * 70)
    print("CLEANED DATASET INSPECTION")
    print("=" * 70)

    # ---------------------------------------------------------
    # Read only a small sample first.
    # This is safe for an 8 GB RAM Mac.
    # ---------------------------------------------------------
    sample = pd.read_csv(DATASET_PATH, nrows=1000)

    print("\n1. SAMPLE SHAPE")
    print(sample.shape)

    print("\n2. COLUMNS")
    for index, column in enumerate(sample.columns, start=1):
        print(f"{index:2}. {repr(column)}")

    print("\n3. DATA TYPES")
    print(sample.dtypes)

    print("\n4. SAMPLE LABEL COUNTS")
    print(sample["Project_Label"].value_counts())

    # ---------------------------------------------------------
    # Check the complete dataset in chunks.
    # ---------------------------------------------------------
    total_rows = 0
    missing_counts = pd.Series(dtype="int64")
    inf_counts = pd.Series(dtype="int64")
    label_counts = {}

    for chunk in pd.read_csv(
        DATASET_PATH,
        chunksize=50_000,
    ):
        total_rows += len(chunk)

        # Missing values
        chunk_missing = chunk.isna().sum()

        if missing_counts.empty:
            missing_counts = chunk_missing
        else:
            missing_counts = missing_counts.add(
                chunk_missing,
                fill_value=0,
            )

        # Infinite values in numeric columns
        numeric_chunk = chunk.select_dtypes(
            include=[np.number]
        )

        chunk_inf = np.isinf(numeric_chunk).sum()

        if inf_counts.empty:
            inf_counts = chunk_inf
        else:
            inf_counts = inf_counts.add(
                chunk_inf,
                fill_value=0,
            )

        # Full label counts
        counts = chunk["Project_Label"].value_counts()

        for label, count in counts.items():
            label_counts[label] = (
                label_counts.get(label, 0) + int(count)
            )

    print("\n5. TOTAL ROWS")
    print(total_rows)

    print("\n6. COMPLETE LABEL DISTRIBUTION")
    for label, count in sorted(
        label_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        print(f"{label:<15} {count:,}")

    print("\n7. MISSING VALUES")
    missing_counts = missing_counts.astype(int)

    missing_values = missing_counts[
        missing_counts > 0
    ].sort_values(ascending=False)

    if missing_values.empty:
        print("No missing values found.")
    else:
        print(missing_values)

    print("\n8. INFINITE VALUES")
    inf_counts = inf_counts.astype(int)

    infinite_values = inf_counts[
        inf_counts > 0
    ].sort_values(ascending=False)

    if infinite_values.empty:
        print("No infinite values found.")
    else:
        print(infinite_values)

    print("\n" + "=" * 70)
    print("INSPECTION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()