from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


INPUT_FILE = Path(
    "ml/dataset/processed/model_features.csv"
)

OUTPUT_DIR = Path(
    "ml/dataset/processed"
)

BALANCED_FILE = OUTPUT_DIR / "balanced_dataset.csv"
TRAIN_FILE = OUTPUT_DIR / "train.csv"
TEST_FILE = OUTPUT_DIR / "test.csv"


# Number of rows we want from each class.
TARGET_COUNTS = {
    "NORMAL": 120_000,
    "DDOS": 100_000,
    "PORT_SCAN": 100_000,
    "BRUTE_FORCE": 15_339,
}

CHUNK_SIZE = 50_000
RANDOM_STATE = 42


def get_class_counts():
    """Count classes without loading the complete dataset."""

    print("\nCalculating class counts...")

    counts = {}

    for chunk in pd.read_csv(
        INPUT_FILE,
        chunksize=CHUNK_SIZE,
    ):
        current = chunk["Project_Label"].value_counts()

        for label, count in current.items():
            counts[label] = counts.get(label, 0) + int(count)

    return counts


def sample_dataset(class_counts):
    """
    Sample the desired number of rows from each class
    while processing the large CSV in chunks.
    """

    print("\nSampling dataset...\n")

    sampled_parts = []

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            INPUT_FILE,
            chunksize=CHUNK_SIZE,
        ),
        start=1,
    ):

        print(
            f"Processing chunk {chunk_number}..."
        )

        for label, target_count in TARGET_COUNTS.items():

            if label not in class_counts:
                continue

            # Expected sampling fraction.
            fraction = target_count / class_counts[label]

            class_rows = chunk[
                chunk["Project_Label"] == label
            ]

            if class_rows.empty:
                continue

            # Never sample more than the available rows.
            sample_size = min(
                len(class_rows),
                max(
                    1,
                    int(len(class_rows) * fraction)
                ),
            )

            sampled = class_rows.sample(
                n=sample_size,
                random_state=RANDOM_STATE + chunk_number,
            )

            sampled_parts.append(sampled)

    result = pd.concat(
        sampled_parts,
        ignore_index=True,
    )

    # Randomize the resulting rows.
    result = result.sample(
        frac=1,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    # Enforce exact target counts.
    final_parts = []

    for label, target_count in TARGET_COUNTS.items():

        class_rows = result[
            result["Project_Label"] == label
        ]

        if len(class_rows) < target_count:
            print(
                f"WARNING: Only {len(class_rows):,} "
                f"rows available for {label}. "
                f"Requested {target_count:,}."
            )
        else:
            class_rows = class_rows.sample(
                n=target_count,
                random_state=RANDOM_STATE,
            )

        final_parts.append(class_rows)

    final_dataset = pd.concat(
        final_parts,
        ignore_index=True,
    )

    final_dataset = final_dataset.sample(
        frac=1,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    return final_dataset


def main():

    print("=" * 70)
    print("CREATING BALANCED ML DATASET")
    print("=" * 70)

    if not INPUT_FILE.exists():
        print(f"\nERROR: File not found:")
        print(INPUT_FILE)
        return

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    class_counts = get_class_counts()

    print("\nOriginal class distribution:")

    for label, count in sorted(
        class_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        print(f"{label:<15} {count:,}")

    balanced = sample_dataset(
        class_counts
    )

    print("\n" + "=" * 70)
    print("BALANCED DATASET")
    print("=" * 70)

    print(f"\nRows: {len(balanced):,}")

    print("\nClass distribution:")

    print(
        balanced["Project_Label"]
        .value_counts()
    )

    balanced.to_csv(
        BALANCED_FILE,
        index=False,
    )

    print(
        f"\nSaved balanced dataset:"
        f"\n{BALANCED_FILE}"
    )

    # ---------------------------------------------------------
    # Train/test split
    # ---------------------------------------------------------

    X = balanced.drop(
        columns=["Project_Label"]
    )

    y = balanced["Project_Label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    train = X_train.copy()
    train["Project_Label"] = y_train.values

    test = X_test.copy()
    test["Project_Label"] = y_test.values

    train.to_csv(
        TRAIN_FILE,
        index=False,
    )

    test.to_csv(
        TEST_FILE,
        index=False,
    )

    print("\n" + "=" * 70)
    print("TRAIN / TEST SPLIT COMPLETE")
    print("=" * 70)

    print(
        f"\nTraining rows : {len(train):,}"
    )

    print(
        f"Testing rows  : {len(test):,}"
    )

    print("\nTraining distribution:")

    print(
        train["Project_Label"]
        .value_counts()
    )

    print("\nTesting distribution:")

    print(
        test["Project_Label"]
        .value_counts()
    )

    print("\nCreated files:")

    print(f"Balanced : {BALANCED_FILE}")
    print(f"Train    : {TRAIN_FILE}")
    print(f"Test     : {TEST_FILE}")


if __name__ == "__main__":
    main()
