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
Expected output: `AUC-ROC: 0.95xx` and `Model saved to ml/ransomware_model.pkl`

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

**Terminal 3 — Dashboard:**
```bash
source venv/Scripts/activate
streamlit run dashboard/app.py
```
> Opens at `http://localhost:8501`

**Terminal 4 — Simulator (Trigger Attack):**
```bash
source venv/Scripts/activate
python simulator/fake_ransomware.py
```
> Watch Terminal 2 catch it and Terminal 3 show the alert!

---

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Agent       │────▶│  ML API      │────▶│  Dashboard   │
│  (monitor.py)│     │  (Flask)     │     │  (Streamlit) │
└──────────────┘     └──────────────┘     └──────────────┘
       │                                              
       ▼                                              
┌──────────────┐     ┌──────────────┐                
│  Honeypot    │     │  Quarantine  │                
│  (decoy files)│     │  (isolated)  │                
└──────────────┘     └──────────────┘                
```

---

## 📁 Project Structure

| Folder | Files | Purpose |
|--------|-------|---------|
| `ml/` | `train.py`, `inference.py`, `features.py` | XGBoost model + Flask API |
| `agent/` | `monitor.py`, `honeypot.py`, `containment.py` | File watcher + auto-kill + quarantine |
| `dashboard/` | `app.py` | Real-time Streamlit UI |
| `simulator/` | `fake_ransomware.py` | Safe test ransomware (Fernet encryption) |

---

## 🐛 Troubleshooting

| Error | Fix |
|-------|-----|
| `No module named 'sklearn'` | Run `source venv/Scripts/activate` first |
| `FileNotFoundError: ransomware_model.pkl` | Run `python ml/train.py` before `inference.py` |
| `Port 5000 in use` | `taskkill /PID <PID> /F` or change port in `inference.py` |
| `source: command not found` | Use `. venv/Scripts/activate` instead |

---

## 🎯 Demo Flow
1. Open Dashboard at `localhost:8501`
2. Run Agent (`monitor.py`)
3. Run Simulator (`fake_ransomware.py`)
4. Watch entropy spike → ML detection → process killed → file quarantined

---

**Team:** RAKSHAK-AI | **SIH 2026**
