
from pathlib import Path

import joblib


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_FILE = PROJECT_ROOT / "ml" / "scam_model.joblib"


def main():
    if not MODEL_FILE.exists():
        print("ERROR: Trained model not found.")
        print("Run train_model.py first.")
        return

    model = joblib.load(MODEL_FILE)

    test_messages = [
        (
            "Harmless greeting",
            "Hi, good morning! Have a wonderful day."
        ),
        (
            "Bank password and OTP request",
            "URGENT: Verify your bank password and OTP immediately."
        ),
        (
            "Prize processing fee",
            "Congratulations! Pay a processing fee to claim your prize."
        ),
        (
            "Class meeting",
            "Can we discuss the assignment after class?"
        ),
        (
            "Account suspension warning",
            "Click this link immediately to prevent your account from being suspended."
        ),
    ]

    print("ScamShield ML Model Test")
    print("=" * 40)

    for name, message in test_messages:
        prediction = model.predict([message])[0]
        probabilities = model.predict_proba([message])[0]

        classes = list(model.classes_)
        scam_probability = probabilities[classes.index("scam")]

        print(f"\nTest: {name}")
        print(f"Message: {message}")
        print(f"Prediction: {prediction.upper()}")
        print(f"Scam probability: {scam_probability:.1%}")

    print("\nTesting complete.")
    print("These predictions are experimental, not proof of accuracy.")


if __name__ == "__main__":
    main()
