from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


TRAIN_FILE = Path(
    "ml/dataset/processed/train.csv"
)

TEST_FILE = Path(
    "ml/dataset/processed/test.csv"
)

MODEL_DIR = Path(
    "ml/models"
)

MODEL_FILE = MODEL_DIR / "random_forest.joblib"


LABEL_COLUMN = "Project_Label"


def main():
    print("=" * 70)
    print("RANDOM FOREST TRAINING")
    print("=" * 70)

    # ---------------------------------------------------------
    # Check files
    # ---------------------------------------------------------

    if not TRAIN_FILE.exists():
        print(f"ERROR: Training file not found: {TRAIN_FILE}")
        return

    if not TEST_FILE.exists():
        print(f"ERROR: Test file not found: {TEST_FILE}")
        return

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ---------------------------------------------------------
    # Load training and testing data
    # ---------------------------------------------------------

    print("\nLoading training dataset...")

    train = pd.read_csv(TRAIN_FILE)

    print(
        f"Training rows: {len(train):,}"
    )

    print("\nLoading test dataset...")

    test = pd.read_csv(TEST_FILE)

    print(
        f"Testing rows: {len(test):,}"
    )

    # ---------------------------------------------------------
    # Separate features and labels
    # ---------------------------------------------------------

    X_train = train.drop(
        columns=[LABEL_COLUMN]
    )

    y_train = train[LABEL_COLUMN]

    X_test = test.drop(
        columns=[LABEL_COLUMN]
    )

    y_test = test[LABEL_COLUMN]

    print(
        f"\nNumber of features: {X_train.shape[1]}"
    )

    print("\nFeature columns:")

    for column in X_train.columns:
        print(f"  - {column}")

    print("\nTraining classes:")

    print(y_train.value_counts())

    # ---------------------------------------------------------
    # Create Random Forest
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("CREATING RANDOM FOREST")
    print("=" * 70)

    model = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        max_depth=None,
    )

    # ---------------------------------------------------------
    # Train
    # ---------------------------------------------------------

    print("\nTraining model...")
    print("This may take some time on an 8 GB Mac.")

    model.fit(
        X_train,
        y_train,
    )

    print("\nTraining completed.")

    # ---------------------------------------------------------
    # Predictions
    # ---------------------------------------------------------

    print("\nGenerating predictions...")

    predictions = model.predict(
        X_test
    )

    # ---------------------------------------------------------
    # Accuracy
    # ---------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)

    print(
        f"\nAccuracy: {accuracy:.4f}"
    )

    print(
        f"Accuracy: {accuracy * 100:.2f}%"
    )

    # ---------------------------------------------------------
    # Classification report
    # ---------------------------------------------------------

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            digits=4,
        )
    )

    # ---------------------------------------------------------
    # Confusion matrix
    # ---------------------------------------------------------

    labels = sorted(
        y_test.unique()
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=labels,
    )

    print("\nConfusion Matrix:")

    print("Labels:")
    print(labels)

    print(matrix)

    # ---------------------------------------------------------
    # Feature importance
    # ---------------------------------------------------------

    importance = pd.DataFrame(
        {
            "feature": X_train.columns,
            "importance": model.feature_importances_,
        }
    )

    importance = importance.sort_values(
        by="importance",
        ascending=False,
    )

    print("\nTop Feature Importances:")

    print(
        importance.head(10).to_string(
            index=False
        )
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

    print("\nRandom Forest training complete.")


if __name__ == "__main__":
    main()