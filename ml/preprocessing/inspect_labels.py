from pathlib import Path
import pandas as pd


DATASET_DIR = Path(
    "ml/dataset/raw/extracted/MachineLearningCVE"
)


def inspect_labels():
    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    if not csv_files:
        print("No CSV files found.")
        return

    print(f"Found {len(csv_files)} CSV files.\n")

    all_labels = []

    for csv_file in csv_files:
        print(f"Reading: {csv_file.name}")

        # Only read the Label column.
        df = pd.read_csv(
            csv_file,
            usecols=[" Label"],
        )

        # Remove leading/trailing whitespace.
        labels = df[" Label"].astype(str).str.strip()

        counts = labels.value_counts()

        print(counts)
        print()

        all_labels.extend(labels.tolist())

    print("=" * 60)
    print("COMBINED LABEL COUNTS")
    print("=" * 60)

    combined = pd.Series(all_labels)

    print(combined.value_counts())


if __name__ == "__main__":
    inspect_labels()