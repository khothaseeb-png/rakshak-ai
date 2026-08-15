# Behavioral Feature Schema

RAKSHAK-AI uses a single 10-dimensional feature vector for ransomware behavior scoring.
The same vector is produced at **training time**, **inference time**, and **live monitoring**.

Source of truth: `ml/behavior_features.py`

## Features

| # | Name | Range | Description |
|---|------|-------|-------------|
| 1 | `normalized_entropy` | 0.0–1.0 | Shannon entropy of the current file sample divided by 8.0 |
| 2 | `event_rate` | 0.0–1.0 | Number of file events in the last 10s, divided by 10 |
| 3 | `unique_extension_rate` | 0.0–1.0 | Unique file extensions touched in the window, divided by 5 |
| 4 | `honeypot_flag` | 0.0 or 1.0 | 1.0 when the event path is a honeypot decoy file |
| 5 | `rename_ratio` | 0.0–1.0 | Renames / total events in the rolling window |
| 6 | `create_ratio` | 0.0–1.0 | Creates / total events in the rolling window |
| 7 | `modified_ratio` | 0.0–1.0 | Modifies / total events in the rolling window |
| 8 | `high_entropy_ratio` | 0.0–1.0 | Share of window events with entropy > 6.5 |
| 9 | `bytes_per_second` | 0.0–1.0 | Bytes observed in the window per second, normalized by 50 KB/s |
| 10 | `burst_duration` | 0.0–1.0 | Seconds since the first event in the window, divided by 10 |

## Rolling window

All temporal features use a **10-second rolling window** maintained by `BehaviorState`.

## Training data workflow

1. **Bootstrap (automated):**
   ```bash
   python ml/generate_dataset.py
   python ml/train.py
   ```

2. **Collect live logs (optional, higher quality):**
   ```bash
   # Terminal A — benign activity while logging label 0
   python agent/monitor.py --log-label 0 --run-id benign_manual_01

   # Terminal B — run simulator while logging label 1
   python agent/monitor.py --log-label 1 --run-id attack_manual_01
   python simulator/fake_ransomware.py
   ```

3. **Retrain on combined CSV:**
   ```bash
   python ml/train.py
   ```

Training splits by `run_id` when available so events from the same attack run do not leak into both train and test sets.

## Model

- Algorithm: **Random Forest** (`sklearn.ensemble.RandomForestClassifier`)
- Saved artifact: `ml/ransomware_model.pkl` (includes feature metadata)

## API contract

`POST /predict`

```json
{
  "features": [0.91, 0.80, 0.40, 0.0, 0.75, 0.10, 0.15, 0.88, 0.62, 0.90]
}
```

The API rejects requests that do not send exactly 10 features.
