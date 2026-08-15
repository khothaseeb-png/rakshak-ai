"""Append behavioral feature vectors to a CSV for model training."""

import csv
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ml.behavior_features import FEATURE_NAMES

DEFAULT_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "behavior_logs.csv")


def log_features(
    features: list[float],
    label: int | None = None,
    filepath: str = "",
    run_id: str = "",
    log_path: str = DEFAULT_LOG_PATH,
) -> None:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    file_exists = os.path.exists(log_path)

    with open(log_path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if not file_exists:
            writer.writerow(
                ["timestamp", *FEATURE_NAMES, "label", "filepath", "run_id"]
            )

        writer.writerow(
            [
                datetime.now(timezone.utc).isoformat(),
                *features,
                "" if label is None else int(label),
                filepath,
                run_id,
            ]
        )
