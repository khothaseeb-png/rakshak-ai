import time
import os
import math
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from honeypot import create_honeypots, is_honeypot, get_honeypot_entropy, HONEYPOT_DIR
from containment import kill_process_by_path, isolate_file

WATCH_DIR = "./watch_target"
ML_API = "http://localhost:5000/predict"
ENTROPY_THRESHOLD = 6.5
FILE_CHANGE_THRESHOLD = 5

class RansomwareHandler(FileSystemEventHandler):
    def __init__(self):
        self.recent_changes = []
        self.alert_sent = False

    def on_modified(self, event):
        if event.is_directory:
            return
        self._process_event(event.src_path, 'modified')

    def on_created(self, event):
        if event.is_directory:
            return
        self._process_event(event.src_path, 'created')

    def on_moved(self, event):
        if event.is_directory:
            return
        if event.dest_path:
            self._process_event(event.dest_path, 'renamed')

    def _process_event(self, filepath, event_type):
        now = time.time()
        self.recent_changes = [t for t in self.recent_changes if now - t < 10]
        self.recent_changes.append(now)

        if is_honeypot(filepath):
            entropy = get_honeypot_entropy(filepath)
            print(f"[ALERT] HONEYPOT TOUCHED: {filepath} | Entropy: {entropy:.2f}")
            if entropy > ENTROPY_THRESHOLD:
                self._trigger_alert(filepath, "HONEYPOT_ENCRYPTION", 1.0)
                return

        if len(self.recent_changes) > FILE_CHANGE_THRESHOLD:
            self._trigger_alert(filepath, "MASS_FILE_MODIFICATION", 0.85)

        try:
            with open(filepath, 'rb') as f:
                data = f.read(8192)
            if data:
                entropy = shannon_entropy(data)
                if entropy > ENTROPY_THRESHOLD:
                    print(f"[SUSPICIOUS] High entropy ({entropy:.2f}): {filepath}")
                    self._check_with_ml(filepath, entropy)
        except Exception:
            pass

    def _check_with_ml(self, filepath, entropy):
        features = [
            entropy / 8.0,
            min(len(self.recent_changes)/10, 1.0),
            0.5, 0.3, 0.2, 0.1, 0.8, 0.4, 0.6, 0.7
        ]
        try:
            resp = requests.post(ML_API, json={'features': features}, timeout=0.5)
            result = resp.json()
            if result['is_ransomware']:
                self._trigger_alert(filepath, f"ML_DETECTION_{result['confidence']}",
                                    result['ransomware_probability'])
        except:
            if entropy > 7.5:
                self._trigger_alert(filepath, "HEURISTIC_FALLBACK", 0.9)

    def _trigger_alert(self, filepath, reason, confidence):
        if self.alert_sent:
            return
        self.alert_sent = True
        print(f"\n{'='*60}")
        print(f"🚨 RANSOMWARE DETECTED")
        print(f"  File: {filepath}")
        print(f"  Reason: {reason}")
        print(f"  Confidence: {confidence:.2%}")
        print(f"{'='*60}\n")
        isolate_file(filepath)

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def start_monitoring():
    create_honeypots()
    os.makedirs(WATCH_DIR, exist_ok=True)
    event_handler = RansomwareHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.schedule(event_handler, HONEYPOT_DIR, recursive=True)
    print(f"[AGENT] Monitoring: {WATCH_DIR} and {HONEYPOT_DIR}")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_monitoring()
