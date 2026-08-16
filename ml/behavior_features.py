"""
Behavioral feature vector for ransomware detection.

Used by: agent/monitor.py, agent/behavior_logger.py, ml/train.py, ml/generate_dataset.py
All components MUST use compute_features() so training and inference stay aligned.
"""

import math
import os
import time
from dataclasses import dataclass, field

WINDOW_SECONDS = 10
ENTROPY_MAX = 8.0
HIGH_ENTROPY_THRESHOLD = 6.5

FEATURE_NAMES = [
    "normalized_entropy",      # Shannon entropy of current file sample / 8.0
    "event_rate",              # File events in rolling window / 10, capped at 1.0
    "unique_extension_rate",   # Unique extensions touched in window / 5, capped at 1.0
    "honeypot_flag",           # 1.0 if current file is a honeypot path, else 0.0
    "rename_ratio",            # Renames / total events in window
    "create_ratio",            # Creates / total events in window
    "modified_ratio",          # Modifies / total events in window
    "high_entropy_ratio",      # Share of window events with entropy > 6.5
    "bytes_per_second",        # Bytes observed in window / window duration, normalized by 10 MB/s
    "burst_duration",          # Seconds since first event in window / 10, capped at 1.0
    "entropy_delta",           # Current entropy minus past average entropy in window, normalized
    "delete_ratio",            # Deletions / total events in window
]

NUM_FEATURES = len(FEATURE_NAMES)


@dataclass
class FileEvent:
    timestamp: float
    filepath: str
    event_type: str
    entropy: float = 0.0
    bytes_read: int = 0
    is_honeypot: bool = False


@dataclass
class BehaviorState:
    """Rolling window of file-system events for behavioral feature extraction."""

    window_seconds: float = WINDOW_SECONDS
    events: list = field(default_factory=list)

    def add_event(
        self,
        filepath: str,
        event_type: str,
        entropy: float = 0.0,
        bytes_read: int = 0,
        is_honeypot: bool = False,
        timestamp: float | None = None,
    ) -> None:
        now = timestamp if timestamp is not None else time.time()
        self._prune(now)
        self.events.append(
            FileEvent(
                timestamp=now,
                filepath=filepath,
                event_type=event_type,
                entropy=entropy,
                bytes_read=bytes_read,
                is_honeypot=is_honeypot,
            )
        )

    def _prune(self, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        cutoff = now - self.window_seconds
        self.events = [event for event in self.events if event.timestamp >= cutoff]

    def snapshot(self, now: float | None = None) -> list[FileEvent]:
        now = now if now is not None else time.time()
        self._prune(now)
        return list(self.events)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for byte_value in range(256):
        probability = data.count(bytes([byte_value])) / length
        if probability > 0:
            entropy -= probability * math.log(probability, 2)
    return entropy


def read_file_entropy(filepath: str, sample_size: int = 8192) -> tuple[float, int]:
    try:
        with open(filepath, "rb") as handle:
            data = handle.read(sample_size)
        if not data:
            return 0.0, 0
        return shannon_entropy(data), len(data)
    except OSError:
        return 0.0, 0


def _cap(value: float, maximum: float = 1.0) -> float:
    return min(max(value, 0.0), maximum)


def compute_features(
    state: BehaviorState,
    current_entropy: float,
    is_honeypot: bool,
    now: float | None = None,
) -> list[float]:
    """Build the feature vector from current behavioral state."""
    now = now if now is not None else time.time()
    events = state.snapshot(now)
    total_events = len(events)

    if total_events == 0:
        return [0.0] * NUM_FEATURES

    rename_count = sum(1 for event in events if event.event_type == "renamed")
    create_count = sum(1 for event in events if event.event_type == "created")
    modified_count = sum(1 for event in events if event.event_type == "modified")
    delete_count = sum(1 for event in events if event.event_type in ("deleted", "removed"))
    high_entropy_count = sum(
        1 for event in events if event.entropy > HIGH_ENTROPY_THRESHOLD
    )

    if total_events > 1:
        past_events = events[:-1]
        avg_past_entropy = sum(e.entropy for e in past_events) / len(past_events)
        entropy_delta_raw = current_entropy - avg_past_entropy
        entropy_delta = _cap((entropy_delta_raw + ENTROPY_MAX) / (2.0 * ENTROPY_MAX))
    else:
        entropy_delta = 0.5

    extensions = {
        os.path.splitext(event.filepath)[1].lower()
        for event in events
        if os.path.splitext(event.filepath)[1]
    }
    total_bytes = sum(event.bytes_read for event in events)
    first_timestamp = min(event.timestamp for event in events)
    elapsed = max(now - first_timestamp, 0.001)

    return [
        _cap(current_entropy / ENTROPY_MAX),
        _cap(total_events / 10.0),
        _cap(len(extensions) / 5.0),
        1.0 if is_honeypot else 0.0,
        rename_count / total_events,
        create_count / total_events,
        modified_count / total_events,
        high_entropy_count / total_events,
        _cap((total_bytes / elapsed) / 10000000.0),
        _cap(elapsed / state.window_seconds),
        entropy_delta,
        delete_count / total_events,
    ]


def features_to_dict(features: list[float]) -> dict[str, float]:
    return dict(zip(FEATURE_NAMES, features))
