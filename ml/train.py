import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.behavior_features import FEATURE_NAMES, NUM_FEATURES
from ml.generate_dataset import generate_dataset

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ransomware_model.pkl")
LOG_PATH = os.path.join(os.path.dirname(__file__), "behavior_logs.csv")
MIN_SAMPLES = 50


def load_behavior_data(path: str = LOG_PATH) -> pd.DataFrame | None:
    if not os.path.exists(path):
        return None

    dataframe = pd.read_csv(path)
    if "label" not in dataframe.columns:
        return None

    dataframe = dataframe.dropna(subset=["label"])
    if len(dataframe) < MIN_SAMPLES:
        return None

    missing_columns = [name for name in FEATURE_NAMES if name not in dataframe.columns]
    if missing_columns:
        print(f"[WARN] Behavior log schema mismatch (missing {missing_columns}). Regenerating dataset...")
        os.remove(path)
        return None

    return dataframe


def split_by_run(dataframe: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    if "run_id" in dataframe.columns and dataframe["run_id"].nunique() > 1:
        unique_runs = dataframe["run_id"].dropna().unique().tolist()
        train_runs, test_runs = train_test_split(
            unique_runs, test_size=0.2, random_state=42
        )
        train_df = dataframe[dataframe["run_id"].isin(train_runs)]
        test_df = dataframe[dataframe["run_id"].isin(test_runs)]
    else:
        train_df, test_df = train_test_split(
            dataframe, test_size=0.2, random_state=42, stratify=dataframe["label"]
        )

    x_train = train_df[FEATURE_NAMES].values
    y_train = train_df["label"].astype(int).values
    x_test = test_df[FEATURE_NAMES].values
    y_test = test_df["label"].astype(int).values
    return x_train, x_test, y_train, y_test


def train() -> None:
    print("Training Random Forest on behavioral features...")
    print(f"Feature schema ({NUM_FEATURES}): {', '.join(FEATURE_NAMES)}")

    dataframe = load_behavior_data()
    if dataframe is None:
        print("No behavior_logs.csv found (or too few rows). Generating dataset...")
        generate_dataset(output_path=LOG_PATH)
        dataframe = load_behavior_data()

    if dataframe is None:
        raise RuntimeError("Could not load or generate behavioral training data.")

    print(f"Loaded {len(dataframe)} labeled samples from {LOG_PATH}")
    x_train, x_test, y_train, y_test = split_by_run(dataframe)

    model = RandomForestClassifier(
        n_estimators=20,
        max_depth=5,
        class_weight="balanced",
        random_state=42,
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    y_prob = model.predict_proba(x_test)[:, 1]

    print(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.4f}")
    print(classification_report(y_test, y_pred))

    joblib.dump(
        {
            "model": model,
            "feature_names": FEATURE_NAMES,
            "num_features": NUM_FEATURES,
        },
        MODEL_PATH,
    )
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()
