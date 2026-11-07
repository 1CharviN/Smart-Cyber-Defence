from pathlib import Path

import joblib
import pandas as pd


MODEL_FILE = Path(
    "ml/models/random_forest.joblib"
)

TEST_FILE = Path(
    "ml/dataset/processed/test.csv"
)


def main():
    print("=" * 70)
    print("RANDOM FOREST PREDICTION TEST")
    print("=" * 70)

    if not MODEL_FILE.exists():
        print(
            f"ERROR: Model not found: {MODEL_FILE}"
        )
        return

    if not TEST_FILE.exists():
        print(
            f"ERROR: Test dataset not found: {TEST_FILE}"
        )
        return

    # Load saved model
    print("\nLoading trained model...")

    model = joblib.load(
        MODEL_FILE
    )

    print("Model loaded successfully.")

    # Load a small sample
    test = pd.read_csv(
        TEST_FILE,
        nrows=10,
    )

    X = test.drop(
        columns=["Project_Label"]
    )

    y_actual = test[
        "Project_Label"
    ]

    # Predict
    predictions = model.predict(X)

    probabilities = model.predict_proba(X)

    print("\nPredictions:")
    print("-" * 70)

    for i in range(len(X)):
        print(
            f"Sample {i + 1}: "
            f"Actual = {y_actual.iloc[i]:<12} "
            f"Predicted = {predictions[i]:<12} "
            f"Confidence = "
            f"{probabilities[i].max() * 100:.2f}%"
        )

    print("\n" + "=" * 70)
    print("PREDICTION TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()