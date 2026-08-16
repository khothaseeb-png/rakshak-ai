"""
Generate labeled behavioral training data by simulating benign and attack activity.
Adds realistic noise so classes overlap slightly (AUC ~0.92-0.97).

Run directly:
    python ml/generate_dataset.py

Or let ml/train.py call this when behavior_logs.csv is missing.
"""

import csv
import os
import random
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
    # Add subtle, realistic measurement noise to continuous features, keeping binary flags exact
    noisy_features = []
    for idx, f in enumerate(features):
        name = FEATURE_NAMES[idx]
        if name in ("honeypot_flag",):
            noisy_features.append(f)
        else:
            noisy_features.append(max(0.0, min(1.0, f + random.gauss(0, 0.02))))
    rows.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
            **dict(zip(FEATURE_NAMES, noisy_features)),
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

    num_files = random.randint(3, 8)
    actions = []
    for i in range(num_files):
        fname = f"file_{i}.txt"
        if random.random() < 0.2:
            content = bytes(random.randint(0, 255) for _ in range(500)).decode("latin-1", errors="ignore")
        else:
            content = f"Normal document content line {i}.\n" * random.randint(10, 50)
        actions.append(("created", fname, content))
        if random.random() < 0.3:
            actions.append(("modified", fname, content + " appended.\n" * 5))

    for index, (event_type, filename, content) in enumerate(actions):
        filepath = os.path.join(run_dir, filename)
        with open(filepath, "w", encoding="utf-8", errors="ignore") as handle:
            handle.write(content)

        spacing = random.uniform(0.5, 3.0)
        timestamp = base_time + index * spacing
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

    num_docs = random.randint(3, 10)
    filepaths = []
    for index in range(num_docs):
        filepath = os.path.join(run_dir, f"doc_{index}.txt")
        with open(filepath, "w", encoding="utf-8") as handle:
            handle.write("Important business document content.\n" * 40)
        filepaths.append(filepath)

    has_honeypot = random.random() < 0.5
    if has_honeypot:
        honeypot_path = os.path.join(run_dir, "salary_2026.xlsx")
        with open(honeypot_path, "w", encoding="utf-8") as handle:
            handle.write("Decoy salary spreadsheet.\n" * 40)
        filepaths.append(honeypot_path)

    event_offset = 0.0
    for filepath in filepaths:
        spacing = random.uniform(0.2, 1.2)
        timestamp = base_time + event_offset

        if random.random() < 0.15:
            original = open(filepath, "rb").read()
            encrypted = original[:len(original)//2] + secrets.token_bytes(512)
        else:
            encrypted = secrets.token_bytes(1024)

        with open(filepath, "wb") as handle:
            handle.write(encrypted)

        if random.random() < 0.8:
            renamed_path = filepath + ".encrypted"
            if os.path.exists(renamed_path):
                os.remove(renamed_path)
            os.rename(filepath, renamed_path)
        else:
            renamed_path = filepath

        entropy = shannon_entropy(encrypted)
        is_honeypot = "salary_2026" in os.path.basename(filepath)
        state.add_event(
            filepath=renamed_path,
            event_type="renamed" if renamed_path != filepath else "modified",
            entropy=entropy,
            bytes_read=len(encrypted),
            is_honeypot=is_honeypot,
            timestamp=timestamp,
        )
        features = compute_features(state, entropy, is_honeypot, now=timestamp)
        _append_row(rows, features, 1, renamed_path, run_id, timestamp)
        event_offset += spacing


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
