import os
import math

HONEYPOT_DIR = "./honeypot_files"
HONEYPOT_FILES = ["salary_2026.xlsx", "project_plan.docx", "passwords.txt", "client_data.csv"]

def create_honeypots():
    os.makedirs(HONEYPOT_DIR, exist_ok=True)
    for fname in HONEYPOT_FILES:
        path = os.path.join(HONEYPOT_DIR, fname)
        content = "This is a honeypot file. Do not encrypt.\n" * 100
        with open(path, 'w') as f:
            f.write(content)
    print(f"[HONEYPOT] Created {len(HONEYPOT_FILES)} decoy files in {HONEYPOT_DIR}")

def is_honeypot(filepath):
    abs_hp = os.path.abspath(HONEYPOT_DIR).lower()
    abs_file = os.path.abspath(filepath).lower()
    return abs_hp in abs_file or "salary_2026" in abs_file

def get_honeypot_entropy(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    return shannon_entropy(data)

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy
