
from flask import Blueprint, request, jsonify

from services.scam_detector import detect_scam
from services.ml_detector import predict_scam

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not isinstance(message, str):
        return jsonify({"error": "Message must be text."}), 400

    result = detect_scam(message)

    try:
        ml_result = predict_scam(message)
    except Exception as e:
        print("ML prediction error:", repr(e))
        # Keep rule-based analysis available if ML fails.
        ml_result = {
            "prediction": "UNAVAILABLE",
            "scam_probability": None
        }

    return jsonify({
        "message": message,
        "analysis": result,
        "ml_analysis": ml_result
    })
