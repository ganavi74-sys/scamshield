
from pathlib import Path

import joblib


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_FILE = PROJECT_ROOT / "ml" / "scam_model.joblib"

_model = None


def load_model():
    """Load the trained ScamShield model once and reuse it."""
    global _model

    if _model is None:
        if not MODEL_FILE.exists():
            raise FileNotFoundError(
                f"Trained ML model not found: {MODEL_FILE}"
            )

        _model = joblib.load(MODEL_FILE)

    return _model


def predict_scam(message):
    """Return the ML prediction and estimated scam probability."""
    model = load_model()

    prediction = str(model.predict([message])[0]).lower()
    probabilities = model.predict_proba([message])[0]
    classes = [str(label) for label in model.classes_]

    scam_probability = float(
        probabilities[classes.index("scam")]
    )

    return {
        "prediction": prediction.upper(),
        "scam_probability": round(scam_probability * 100, 2)
    }
