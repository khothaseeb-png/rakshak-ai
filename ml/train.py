import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report
import joblib

def generate_mock_data(n_samples=5000):
    np.random.seed(42)
    X_benign = np.random.rand(n_samples//2, 10) * 0.5
    y_benign = np.zeros(n_samples//2)

    X_mal = np.random.rand(n_samples//2, 10) * 0.5 + 0.4
    y_mal = np.ones(n_samples//2)

    X = np.vstack([X_benign, X_mal])
    y = np.hstack([y_benign, y_mal])

    return X, y

def train():
    print("Training model...")
    X, y = generate_mock_data()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight='balanced',
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.4f}")
    print(classification_report(y_test, y_pred))

    joblib.dump(model, 'ml/ransomware_model.pkl')
    print("Model saved to ml/ransomware_model.pkl")

if __name__ == "__main__":
    train()
