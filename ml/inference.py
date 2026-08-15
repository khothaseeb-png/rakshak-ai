from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import os

app = Flask(__name__)
CORS(app)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ransomware_model.pkl')
model = joblib.load(MODEL_PATH)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    features = np.array(data['features']).reshape(1, -1)
    prob = model.predict_proba(features)[0][1]
    prediction = int(prob > 0.7)

    return jsonify({
        'ransomware_probability': float(prob),
        'is_ransomware': prediction,
        'confidence': 'high' if prob > 0.9 else 'medium' if prob > 0.7 else 'low'
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
