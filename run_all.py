"""
RAKSHAK — One-Command Launcher
Usage: python run_all.py
"""

import os
import subprocess
import sys
import time

ML_API = "ml/inference.py"
AGENT = "agent/monitor.py"
DASHBOARD = "dashboard/app.py"
SIMULATOR = "simulator/fake_ransomware.py"
MODEL = "ml/ransomware_model.pkl"

# Find venv root from current Python path
# e.g. .../rakshak/venv/Scripts/python.exe -> .../rakshak/venv
VENV = os.path.dirname(os.path.dirname(sys.executable))
ACTIVATE = os.path.join(VENV, "Scripts", "activate.bat")

def launch(title, cmd):
    # Activate venv, then run command in new CMD window
    full = f'call "{ACTIVATE}" && title {title} && python {cmd}'
    subprocess.Popen(f'start "{title}" cmd /k "{full}"', shell=True)

def check_model():
    if not os.path.exists(MODEL):
        print("Training model...")
        result = subprocess.run([sys.executable, "ml/train.py"])
        if result.returncode != 0 or not os.path.exists(MODEL):
            print("Training failed.")
            sys.exit(1)
        print("Done.\n")
    else:
        print("Model found.\n")

def main():
    print("=" * 50)
    print("RAKSHAK Launcher")
    print("=" * 50 + "\n")
    check_model()

    print("[1/4] ML API        -> http://localhost:5000")
    launch("ML API", ML_API)
    time.sleep(2)

    print("[2/4] Agent Monitor -> Watching files")
    launch("Agent", AGENT)
    time.sleep(2)

    print("[3/4] Dashboard     -> http://localhost:8501")
    launch("Dashboard", f"-m streamlit run {DASHBOARD}")
    time.sleep(3)

    print("\nAll 3 services started.\n")
    input("Press ENTER to launch simulator...")

    print("[4/4] Simulator running! Watch Agent window.\n")
    launch("Simulator", SIMULATOR)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDone.")

if __name__ == "__main__":
    main()
