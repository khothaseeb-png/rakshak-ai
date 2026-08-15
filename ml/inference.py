from flask import Flask, jsonify, request
from flask_cors import CORS
import joblib
import numpy as np
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.behavior_features import NUM_FEATURES

app = Flask(__name__)
CORS(app)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ransomware_model.pkl")
artifact = joblib.load(MODEL_PATH)

if isinstance(artifact, dict):
    model = artifact["model"]
    expected_features = artifact.get("num_features", NUM_FEATURES)
else:
    model = artifact
    expected_features = NUM_FEATURES


@app.route("/predict", methods=["POST"])
def predict():
    data = request.json or {}
    features = data.get("features")

    if features is None:
        return jsonify({"error": "Missing 'features' in request body."}), 400

    if len(features) != expected_features:
        return jsonify(
            {
                "error": f"Expected {expected_features} features, got {len(features)}.",
            }
        ), 400

    feature_array = np.array(features, dtype=float).reshape(1, -1)
    probability = model.predict_proba(feature_array)[0][1]
    prediction = int(probability > 0.7)

    return jsonify(
        {
            "ransomware_probability": float(probability),
            "is_ransomware": prediction,
            "confidence": (
                "high"
                if probability > 0.9
                else "medium"
                if probability > 0.7
                else "low"
            ),
        }
    )


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "expected_features": expected_features})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
