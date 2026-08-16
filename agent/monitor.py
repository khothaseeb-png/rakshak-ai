import argparse
import datetime
import json
import os
import sys
import time

import joblib
import numpy as np
import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.behavior_features import (
    BehaviorState,
    compute_features,
    read_file_entropy,
)
from behavior_logger import log_features
from containment import isolate_file, kill_process_by_path
from honeypot import HONEYPOT_DIR, create_honeypots, is_honeypot

WATCH_DIR = "./watch_target"
ML_API = "http://localhost:5000/predict"
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "ransomware_model.pkl")
THREAT_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "live_threats.json")
ENTROPY_THRESHOLD = 6.5
FILE_CHANGE_THRESHOLD = 5


def save_threat_log(alert_data: dict) -> None:
    """Save threat alerts to a shared JSON file for real-time Streamlit dashboard rendering."""
    try:
        os.makedirs(os.path.dirname(THREAT_LOG_PATH), exist_ok=True)
        threats = []
        if os.path.exists(THREAT_LOG_PATH):
            try:
                with open(THREAT_LOG_PATH, "r", encoding="utf-8") as f:
                    threats = json.load(f)
            except Exception:
                threats = []
        threats.insert(0, alert_data)
        threats = threats[:50]
        with open(THREAT_LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(threats, f, indent=2)
    except Exception as err:
        print(f"[ERROR] Could not log live threat: {err}")


class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, log_label: int | None = None, run_id: str = ""):
        self.state = BehaviorState()
        self.alerted_files = set()
        self.log_label = log_label
        self.run_id = run_id
        self.local_model = self._load_local_model()

    def _load_local_model(self):
        try:
            if os.path.exists(MODEL_PATH):
                artifact = joblib.load(MODEL_PATH)
                if isinstance(artifact, dict):
                    print("[AGENT] Loaded Random Forest model locally for sub-ms scoring.")
                    return artifact["model"]
                return artifact
        except Exception as e:
            print(f"[WARN] Local model load failed ({e}); fallback to API.")
        return None

    def on_modified(self, event):
        if event.is_directory:
            return
        self._process_event(event.src_path, "modified")

    def on_created(self, event):
        if event.is_directory:
            return
        self._process_event(event.src_path, "created")

    def on_moved(self, event):
        if event.is_directory:
            return
        if event.dest_path:
            self._process_event(event.dest_path, "renamed")

    def _process_event(self, filepath, event_type):
        now = time.time()
        honeypot = is_honeypot(filepath)
        entropy, byte_count = read_file_entropy(filepath)

        self.state.add_event(
            filepath=filepath,
            event_type=event_type,
            entropy=entropy,
            bytes_read=byte_count,
            is_honeypot=honeypot,
            timestamp=now,
        )
        features = compute_features(self.state, entropy, honeypot, now=now)

        if self.log_label is not None:
            log_features(
                features,
                label=self.log_label,
                filepath=filepath,
                run_id=self.run_id,
            )

        if honeypot:
            print(f"[ALERT] HONEYPOT TOUCHED: {filepath} | Entropy: {entropy:.2f}")

        # Always run ML model evaluation on suspicious file events
        self._evaluate_threat(filepath, features, entropy, honeypot, now)

    def _evaluate_threat(self, filepath, features, entropy, honeypot, now):
        probability = 0.0
        confidence = "low"
        is_ransomware = False
        reason = "BEHAVIORAL_ML_DETECTION"

        # Step 1: In-process sub-millisecond local ML scoring
        if self.local_model is not None:
            try:
                feature_array = np.array(features, dtype=float).reshape(1, -1)
                probability = float(self.local_model.predict_proba(feature_array)[0][1])
                is_ransomware = probability > 0.4
                confidence = "high" if probability > 0.8 else "medium" if probability > 0.4 else "low"
            except Exception as err:
                print(f"[WARN] Local ML evaluation error: {err}")

        # Step 2: Fallback to Flask REST API if local model unavailable
        if not is_ransomware and self.local_model is None:
            try:
                response = requests.post(ML_API, json={"features": features}, timeout=1.0)
                res = response.json()
                probability = res.get("ransomware_probability", 0.0)
                is_ransomware = res.get("is_ransomware", False)
                confidence = res.get("confidence", "medium")
            except requests.RequestException:
                pass

        # Step 3: Behavioral pattern & honeypot triggers
        is_encrypted_ext = filepath.endswith(".encrypted") or ".encrypted" in filepath
        if honeypot:
            probability = max(probability, 0.99)
            is_ransomware = True
            reason = "HONEYPOT_DECOY_TOUCHED"
            confidence = "high"
        elif entropy > 5.5 or is_encrypted_ext:
            probability = max(probability, 0.95)
            is_ransomware = True
            reason = "HIGH_ENTROPY_ENCRYPTION_BURST"
            confidence = "high"

        if is_ransomware:
            self._trigger_alert(filepath, reason, probability, confidence, entropy)

    def _trigger_alert(self, filepath, reason, probability, confidence, entropy):
        if filepath in self.alerted_files:
            return
        self.alerted_files.add(filepath)

        print(f"\n{'=' * 60}")
        print("🚨 RANSOMWARE DETECTED BY RAKSHAK")
        print(f"  File: {filepath}")
        print(f"  Reason: {reason}")
        print(f"  Probability: {probability:.2%}")
        print(f"  Confidence: {confidence}")
        print(f"{'=' * 60}\n")

        # Process-level termination & file quarantine
        proc_killed = kill_process_by_path(filepath)
        quarantine_dest = isolate_file(filepath)

        # Log to shared JSON file for real-time dashboard UI
        save_threat_log(
            {
                "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                "file": os.path.basename(filepath),
                "filepath": filepath,
                "process": proc_killed or "suspicious_process.exe",
                "reason": reason,
                "confidence": probability,
                "entropy": round(entropy, 2),
                "action": "PROCESS_KILLED & QUARANTINED" if proc_killed else "FILE_QUARANTINED",
                "quarantine_dest": quarantine_dest or "",
            }
        )


def start_monitoring(log_label: int | None = None, run_id: str = ""):
    create_honeypots()
    os.makedirs(WATCH_DIR, exist_ok=True)
    event_handler = RansomwareHandler(log_label=log_label, run_id=run_id)
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.schedule(event_handler, HONEYPOT_DIR, recursive=True)
    print(f"[AGENT] Rakshak Monitoring: {WATCH_DIR} and {HONEYPOT_DIR}")
    if log_label is not None:
        print(f"[AGENT] Logging features with label={log_label} (run_id={run_id or 'manual'})")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def parse_args():
    parser = argparse.ArgumentParser(description="Rakshak file-system behavior monitor")
    parser.add_argument(
        "--log-label",
        type=int,
        choices=[0, 1],
        default=None,
        help="If set, append feature vectors to ml/behavior_logs.csv with this label.",
    )
    parser.add_argument(
        "--run-id",
        default="",
        help="Optional run identifier stored in behavior_logs.csv.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    start_monitoring(log_label=args.log_label, run_id=args.run_id)
