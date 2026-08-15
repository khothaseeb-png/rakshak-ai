import os
import shutil
import psutil
import datetime

QUARANTINE_DIR = "./quarantine"

def kill_process_by_path(filepath):
    try:
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                if proc.info['open_files']:
                    for file in proc.info['open_files']:
                        if filepath in file.path:
                            print(f"[CONTAINMENT] Killing {proc.info['name']} (PID: {proc.info['pid']})")
                            psutil.Process(proc.info['pid']).terminate()
                            return proc.info['name']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        print(f"[ERROR] Could not kill process: {e}")
    return None

def isolate_file(filepath):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    try:
        dest = os.path.join(QUARANTINE_DIR,
            f"{datetime.datetime.now().strftime('%H%M%S')}_{os.path.basename(filepath)}")
        shutil.move(filepath, dest)
        print(f"[CONTAINMENT] Isolated: {filepath} -> {dest}")
    except Exception as e:
        print(f"[ERROR] Could not isolate: {e}")
