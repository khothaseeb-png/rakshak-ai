# 🛡️ RAKSHAK-AI
> Behavioral Ransomware Detection with AI-Powered Auto-Containment  
> Smart India Hackathon Project

## ⚡ Quick Start (Full Setup)

### 1. Clone & Setup
```bash
git clone https://github.com/khothaseeb-png/rakshak-ai.git
cd rakshak-ai
python -m venv venv
source venv/Scripts/activate        # Windows Git Bash
pip install -r requirements.txt
```

### 2. Train the Model
```bash
python ml/train.py
```
This loads `ml/behavior_logs.csv` if present. Otherwise it auto-generates simulated benign/attack behavioral logs, then trains a **Random Forest** classifier.

Expected output: AUC-ROC score + `Model saved to ml/ransomware_model.pkl`

See [FEATURES.md](FEATURES.md) for the 10 behavioral features used at train and inference time.

### 3. Run the System (4 Terminals)

**Terminal 1 — ML Inference API:**
```bash
source venv/Scripts/activate
python ml/inference.py
```
> Runs on `http://localhost:5000`

**Terminal 2 — Agent Monitor:**
```bash
source venv/Scripts/activate
python agent/monitor.py
```
> Watches files, detects ransomware, auto-quarantines threats

**Terminal 3 — Dashboard (UI prototype):**
```bash
source venv/Scripts/activate
streamlit run dashboard/app.py
```
> Opens at `http://localhost:8501` — mock UI for demo visuals; real detection happens in the agent terminal

**Terminal 4 — Simulator (Trigger Attack):**
```bash
source venv/Scripts/activate
python simulator/fake_ransomware.py
```
> Watch Terminal 2 catch it and quarantine encrypted files

---

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Agent       │────▶│  ML API      │────▶│  Dashboard   │
│  (monitor.py)│     │  (Flask)     │     │  (Streamlit) │
└──────────────┘     └──────────────┘     └──────────────┘
       │                    ▲
       │                    │
       ▼                    │
┌──────────────┐     ┌──────────────┐
│  Honeypot    │     │  Random Forest│
│  (decoy files)│     │  (behavior)  │
└──────────────┘     └──────────────┘
       │
       ▼
┌──────────────┐
│  Quarantine  │
└──────────────┘
```

---

## 📁 Project Structure

| Folder | Files | Purpose |
|--------|-------|---------|
| `ml/` | `behavior_features.py`, `train.py`, `inference.py`, `generate_dataset.py` | Behavioral features + Random Forest + Flask API |
| `agent/` | `monitor.py`, `behavior_logger.py`, `honeypot.py`, `containment.py` | File watcher + feature logging + quarantine |
| `dashboard/` | `app.py` | UI prototype (not wired to agent yet) |
| `simulator/` | `fake_ransomware.py` | Safe test ransomware (Fernet encryption) |

---

## 🧠 ML Feature Schema

All components share the same 10 behavioral features via `ml/behavior_features.py`:

`normalized_entropy`, `event_rate`, `unique_extension_rate`, `honeypot_flag`, `rename_ratio`, `create_ratio`, `modified_ratio`, `high_entropy_ratio`, `bytes_per_second`, `burst_duration`

Full definitions: [FEATURES.md](FEATURES.md)

### Optional: collect live training data
```bash
python agent/monitor.py --log-label 0 --run-id benign_manual_01
python agent/monitor.py --log-label 1 --run-id attack_manual_01
python ml/train.py
```

---

## 🐛 Troubleshooting

| Error | Fix |
|-------|-----|
| `No module named 'sklearn'` | Run `source venv/Scripts/activate` first |
| `FileNotFoundError: ransomware_model.pkl` | Run `python ml/train.py` before `inference.py` |
| `Expected 10 features` | Restart agent after retraining; monitor and model must use the same schema |
| `Port 5000 in use` | `taskkill /PID <PID> /F` or change port in `inference.py` |
| `source: command not found` | Use `. venv/Scripts/activate` instead |

---

## 🎯 Demo Flow
1. Run `python ml/train.py`
2. Start ML API (`ml/inference.py`) and Agent (`agent/monitor.py`)
3. Run Simulator (`simulator/fake_ransomware.py`)
4. Watch entropy spike → behavioral ML scoring → file quarantined

> **Note:** Detection triggers on observable encryption artifacts (entropy spike / honeypot touch). Process-level containment is a future enhancement.

---

**Team:** RAKSHAK-AI | **SIH 2026**
