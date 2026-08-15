import argparse
import os
import sys
import time

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
from containment import isolate_file
from honeypot import HONEYPOT_DIR, create_honeypots, get_honeypot_entropy, is_honeypot

WATCH_DIR = "./watch_target"
ML_API = "http://localhost:5000/predict"
ENTROPY_THRESHOLD = 6.5
FILE_CHANGE_THRESHOLD = 5


class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, log_label: int | None = None, run_id: str = ""):
        self.state = BehaviorState()
        self.alert_sent = False
        self.log_label = log_label
        self.run_id = run_id

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
            if entropy > ENTROPY_THRESHOLD:
                self._trigger_alert(filepath, "HONEYPOT_ENCRYPTION", 1.0)
                return

        recent_event_count = len(self.state.snapshot(now))
        if recent_event_count > FILE_CHANGE_THRESHOLD:
            self._trigger_alert(filepath, "MASS_FILE_MODIFICATION", 0.85)
            return

        if entropy > ENTROPY_THRESHOLD:
            print(f"[SUSPICIOUS] High entropy ({entropy:.2f}): {filepath}")
            self._check_with_ml(filepath, features, entropy)

    def _check_with_ml(self, filepath, features, entropy):
        try:
            response = requests.post(
                ML_API, json={"features": features}, timeout=2.0
            )
            result = response.json()
            if result.get("is_ransomware"):
                self._trigger_alert(
                    filepath,
                    f"ML_DETECTION_{result['confidence']}",
                    result["ransomware_probability"],
                )
        except requests.RequestException:
            if entropy > 7.5:
                self._trigger_alert(filepath, "HEURISTIC_FALLBACK", 0.9)

    def _trigger_alert(self, filepath, reason, confidence):
        if self.alert_sent:
            return
        self.alert_sent = True
        print(f"\n{'=' * 60}")
        print("🚨 RANSOMWARE DETECTED")
        print(f"  File: {filepath}")
        print(f"  Reason: {reason}")
        print(f"  Confidence: {confidence:.2%}")
        print(f"{'=' * 60}\n")
        isolate_file(filepath)


def start_monitoring(log_label: int | None = None, run_id: str = ""):
    create_honeypots()
    os.makedirs(WATCH_DIR, exist_ok=True)
    event_handler = RansomwareHandler(log_label=log_label, run_id=run_id)
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.schedule(event_handler, HONEYPOT_DIR, recursive=True)
    print(f"[AGENT] Monitoring: {WATCH_DIR} and {HONEYPOT_DIR}")
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
    parser = argparse.ArgumentParser(description="RakshakAI file-system behavior monitor")
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
