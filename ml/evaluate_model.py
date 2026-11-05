
import csv
from pathlib import Path

import joblib
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_FILE = PROJECT_ROOT / "ml" / "scam_model.joblib"
DATA_FILE = PROJECT_ROOT / "ml" / "evaluation_data.csv"


def main():
    if not MODEL_FILE.exists():
        print("ERROR: Trained model not found. Run train_model.py first.")
        return

    messages = []
    expected_labels = []
    borderline_messages = []

    # Read the evaluation dataset.
    with open(DATA_FILE, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            message = row["message"].strip()
            label = row["label"].strip().lower()

            if not message:
                continue

            if label in {"safe", "scam"}:
                messages.append(message)
                expected_labels.append(label)
            elif label == "borderline":
                borderline_messages.append(message)
            else:
                print(f"WARNING: Unknown label skipped: {label!r}")

    if not messages:
        print("ERROR: No safe/scam evaluation messages found.")
        return

    # Predict only the clear safe/scam examples.
    predictions = model_predict(messages)

    print("ScamShield Independent Evaluation")
    print("=" * 42)
    print(f"Clear messages evaluated: {len(messages)}")
    print(f"Borderline messages reserved for review: {len(borderline_messages)}")
    print()

    for message, expected, predicted in zip(
        messages, expected_labels, predictions
    ):
        result = "PASS" if expected == predicted else "MISMATCH"
        print(f"[{result}] Expected: {expected.upper()} | Predicted: {predicted.upper()}")
        print(f"Message: {message}\n")

    print("Evaluation metrics for clear examples")
    print("-" * 42)
    print(f"Accuracy: {accuracy_score(expected_labels, predictions):.1%}")
    print("\nClassification report:")
    print(
        classification_report(
            expected_labels,
            predictions,
            labels=["safe", "scam"],
            zero_division=0
        )
    )

    matrix = confusion_matrix(
        expected_labels,
        predictions,
        labels=["safe", "scam"]
    )
    print("Confusion matrix (rows=actual, columns=predicted)")
    print("                  Predicted SAFE  Predicted SCAM")
    print(f"Actual SAFE       {matrix[0][0]:>14}  {matrix[0][1]:>14}")
    print(f"Actual SCAM       {matrix[1][0]:>14}  {matrix[1][1]:>14}")

    print("\nBorderline messages (not scored as simply safe or scam)")
    print("-" * 42)
    for message in borderline_messages:
        prediction = model_predict([message])[0]
        print(f"Model prediction: {prediction.upper()}")
        print(f"Message: {message}\n")

    print(
        "Note: This is a small, manually labelled evaluation set. "
        "Results are preliminary and do not establish real-world accuracy."
    )


def model_predict(messages):
    # Load the model locally and return its predicted labels.
    model = joblib.load(MODEL_FILE)
    return model.predict(messages)


if __name__ == "__main__":
    main()
