from pathlib import Path

import pandas as pd

from label_mapper import normalize_label


DATASET_DIR = Path(
    "ml/dataset/raw/extracted/MachineLearningCVE"
)

OUTPUT_DIR = Path("ml/dataset/processed")
OUTPUT_FILE = OUTPUT_DIR / "selected_attacks.csv"

CHUNK_SIZE = 50_000

TARGET_LABELS = {
    "NORMAL",
    "DDOS",
    "PORT_SCAN",
    "BRUTE_FORCE",
}


def process_file(csv_file: Path, output_file: Path):
    print(f"\nProcessing: {csv_file.name}")

    rows_written = 0

    for chunk in pd.read_csv(
        csv_file,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        # Clean column names.
        chunk.columns = chunk.columns.str.strip()

        # Convert original CICIDS labels into project labels.
        chunk["Project_Label"] = chunk["Label"].map(
            normalize_label
        )

        # Keep only our initial target classes.
        filtered = chunk[
            chunk["Project_Label"].isin(TARGET_LABELS)
        ].copy()

        if filtered.empty:
            continue

        # Check whether the output file already exists.
        file_exists = output_file.exists()

        # Append if the file exists.
        # Otherwise create it for the first time.
        filtered.to_csv(
            output_file,
            mode="a" if file_exists else "w",
            header=not file_exists,
            index=False,
        )

        rows_written += len(filtered)

    print(f"Selected rows: {rows_written}")


def main():
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Start with a completely fresh output file.
    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    csv_files = sorted(DATASET_DIR.glob("*.csv"))

    print(f"Found {len(csv_files)} CSV files.")

    for csv_file in csv_files:
        process_file(csv_file, OUTPUT_FILE)

    print("\n====================================")
    print("PREPROCESSING COMPLETE")
    print("====================================")
    print(f"Output: {OUTPUT_FILE}")

    if OUTPUT_FILE.exists():
        df = pd.read_csv(
            OUTPUT_FILE,
            usecols=["Project_Label"],
        )

        print("\nFinal class distribution:")
        print(
            df["Project_Label"].value_counts()
        )


if __name__ == "__main__":
    main()