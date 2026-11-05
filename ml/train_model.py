
import csv
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report
import joblib


# Find the ScamShield project folder.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = PROJECT_ROOT / "ml" / "training_data.csv"
MODEL_FILE = PROJECT_ROOT / "ml" / "scam_model.joblib"


def main():
    messages = []
    labels = []

    # Read the labelled training examples.
    with open(DATA_FILE, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            message = row["message"].strip()
            label = row["label"].strip().lower()

            if message and label in {"safe", "scam"}:
                messages.append(message)
                labels.append(label)

    if len(messages) < 10 or len(set(labels)) < 2:
        raise ValueError(
            "Add at least 10 valid examples containing both safe and scam labels."
        )

    print(f"Training examples loaded: {len(messages)}")
    print(f"Safe examples: {labels.count('safe')}")
    print(f"Scam examples: {labels.count('scam')}")

    # Convert text into numerical features and train a classifier.
    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                sublinear_tf=True
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                random_state=42
            )
        )
    ])

    # Cross-validation gives a preliminary check using multiple splits.
    # With this tiny dataset, the scores are highly uncertain.
    minimum_class_count = min(labels.count("safe"), labels.count("scam"))
    folds = min(3, minimum_class_count)

    if folds >= 2:
        scores = cross_val_score(
            model,
            messages,
            labels,
            cv=folds,
            scoring="accuracy"
        )
        print(f"Cross-validation accuracy per fold: {scores.round(2)}")
        print(
            "Average cross-validation accuracy: "
            f"{scores.mean():.2f} (preliminary; tiny dataset)"
        )

    # Train the final model on all available examples.
    model.fit(messages, labels)

    # Show training-set results for learning purposes only.
    predictions = model.predict(messages)
    print("\nTraining-set report (not an independent accuracy test):")
    print(
        classification_report(
            labels,
            predictions,
            labels=["safe", "scam"],
            zero_division=0
        )
    )

    # Save the trained model separately from the existing detector.
    joblib.dump(model, MODEL_FILE)

    print(f"Model saved to: {MODEL_FILE}")
    print("Training completed.")


if __name__ == "__main__":
    main()
