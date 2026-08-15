import streamlit as st
import time
from datetime import datetime
import random

st.set_page_config(page_title="RakshakAI Dashboard", layout="wide")
st.title("🛡️ RakshakAI — Ransomware Defense Dashboard")
st.markdown("Real-time behavioral monitoring with AI-powered containment")

if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'processes' not in st.session_state:
    st.session_state.processes = [
        {"name": "chrome.exe", "pid": 1234, "risk": 0.02, "status": "safe"},
        {"name": "notepad.exe", "pid": 5678, "risk": 0.05, "status": "safe"},
        {"name": "svchost.exe", "pid": 9012, "risk": 0.01, "status": "safe"},
    ]

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Active Threats", len([a for a in st.session_state.alerts if a.get('active', True)]), delta="Live")
with col2:
    st.metric("Files Protected", "12,847")
with col3:
    st.metric("Avg Response Time", "0.3s")

st.divider()
st.subheader("🔍 Live Process Monitor")
for proc in st.session_state.processes:
    risk_color = "🟢" if proc['risk'] < 0.3 else "🟡" if proc['risk'] < 0.7 else "🔴"
    st.progress(proc['risk'], text=f"{risk_color} {proc['name']} (PID: {proc['pid']}) — Risk: {proc['risk']:.1%}")

st.divider()
st.subheader("🚨 Threat Log")

if st.button("🧪 Simulate Ransomware Detection"):
    alert = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "process": "suspicious_process.exe",
        "pid": random.randint(10000, 99999),
        "reason": "HONEYPOT_ENCRYPTION",
        "confidence": 0.98,
        "files_affected": 47,
        "entropy_jump": "4.2 → 7.9",
        "action": "PROCESS_KILLED",
        "active": True
    }
    st.session_state.alerts.insert(0, alert)
    st.session_state.processes.append({
        "name": alert['process'],
        "pid": alert['pid'],
        "risk": alert['confidence'],
        "status": "blocked"
    })

for alert in st.session_state.alerts:
    with st.container():
        c1, c2, c3 = st.columns([3, 1, 1])
        with c1:
            st.error(f"**{alert['timestamp']}** | `{alert['process']}` | {alert['reason']} | Confidence: {alert['confidence']:.1%}")
            st.caption(f"Entropy: {alert['entropy_jump']} | Files: {alert['files_affected']}")
        with c2:
            st.success(f"✅ {alert['action']}")
        with c3:
            st.button("Details", key=f"btn_{alert['timestamp']}_{alert['pid']}")

st.divider()
st.subheader("📊 System Health")
h1, h2, h3 = st.columns(3)
with h1:
    st.info("ML Model: 🟢 Online\nAUC-ROC: 0.947")
with h2:
    st.info("Honeypot Layer: 🟢 Active\n4 decoy files deployed")
with h3:
    st.info("Agent: 🟢 Running\nLatency: 23ms")
