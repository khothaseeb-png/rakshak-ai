"""
Generate labeled behavioral training data by simulating benign and attack activity.

Run directly:
    python ml/generate_dataset.py

Or let ml/train.py call this when behavior_logs.csv is missing.
"""

import csv
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.behavior_features import (
    FEATURE_NAMES,
    BehaviorState,
    compute_features,
    read_file_entropy,
    shannon_entropy,
)

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "behavior_logs.csv")
DATASET_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "dataset_runs")


def _append_row(
    rows: list[dict],
    features: list[float],
    label: int,
    filepath: str,
    run_id: str,
    timestamp: float,
) -> None:
    rows.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
            **dict(zip(FEATURE_NAMES, features)),
            "label": label,
            "filepath": filepath,
            "run_id": run_id,
        }
    )


def _write_rows(rows: list[dict], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["timestamp", *FEATURE_NAMES, "label", "filepath", "run_id"],
        )
        writer.writeheader()
        writer.writerows(rows)


def _simulate_benign_run(run_id: str, run_dir: str, rows: list[dict]) -> None:
    os.makedirs(run_dir, exist_ok=True)
    state = BehaviorState()
    base_time = time.time()

    actions = [
        ("created", "notes.txt", "Meeting notes for tomorrow.\n" * 20),
        ("modified", "notes.txt", "Meeting notes for tomorrow - updated.\n" * 20),
        ("created", "budget.csv", "item,cost\npaper,10\nink,5\n"),
        ("modified", "budget.csv", "item,cost\npaper,12\nink,5\n"),
    ]

    for index, (event_type, filename, content) in enumerate(actions):
        filepath = os.path.join(run_dir, filename)
        with open(filepath, "w", encoding="utf-8") as handle:
            handle.write(content)

        timestamp = base_time + index * 2.0
        entropy, byte_count = read_file_entropy(filepath)
        state.add_event(
            filepath=filepath,
            event_type=event_type,
            entropy=entropy,
            bytes_read=byte_count,
            is_honeypot=False,
            timestamp=timestamp,
        )
        features = compute_features(state, entropy, False, now=timestamp)
        _append_row(rows, features, 0, filepath, run_id, timestamp)


def _simulate_attack_run(run_id: str, run_dir: str, rows: list[dict]) -> None:
    os.makedirs(run_dir, exist_ok=True)
    state = BehaviorState()
    base_time = time.time()

    filepaths = []
    for index in range(8):
        filepath = os.path.join(run_dir, f"doc_{index}.txt")
        with open(filepath, "w", encoding="utf-8") as handle:
            handle.write("Important business document content.\n" * 40)
        filepaths.append(filepath)

    honeypot_path = os.path.join(run_dir, "salary_2026.xlsx")
    with open(honeypot_path, "w", encoding="utf-8") as handle:
        handle.write("Decoy salary spreadsheet.\n" * 40)
    filepaths.append(honeypot_path)

    event_offset = 0.0
    for filepath in filepaths:
        timestamp = base_time + event_offset
        encrypted = secrets.token_bytes(1024)
        with open(filepath, "wb") as handle:
            handle.write(encrypted)

        renamed_path = filepath + ".encrypted"
        os.rename(filepath, renamed_path)

        entropy = shannon_entropy(encrypted)
        is_honeypot = "salary_2026" in os.path.basename(filepath)
        state.add_event(
            filepath=renamed_path,
            event_type="renamed",
            entropy=entropy,
            bytes_read=len(encrypted),
            is_honeypot=is_honeypot,
            timestamp=timestamp,
        )
        features = compute_features(state, entropy, is_honeypot, now=timestamp)
        _append_row(rows, features, 1, renamed_path, run_id, timestamp)
        event_offset += 0.4


def generate_dataset(
    benign_runs: int = 80,
    attack_runs: int = 80,
    output_path: str = OUTPUT_PATH,
) -> str:
    rows: list[dict] = []

    for run_index in range(benign_runs):
        run_id = f"benign_{run_index:03d}"
        _simulate_benign_run(run_id, os.path.join(DATASET_DIR, run_id), rows)

    for run_index in range(attack_runs):
        run_id = f"attack_{run_index:03d}"
        _simulate_attack_run(run_id, os.path.join(DATASET_DIR, run_id), rows)

    _write_rows(rows, output_path)
    return output_path


if __name__ == "__main__":
    path = generate_dataset()
    print(f"Generated {path} with simulated benign and attack behavioral logs.")
