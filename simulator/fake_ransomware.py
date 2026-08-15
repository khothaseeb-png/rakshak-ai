import os
import time
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)
TARGET_DIR = "./watch_target"

def encrypt_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    encrypted = cipher.encrypt(data)
    with open(filepath, 'wb') as f:
        f.write(encrypted)
    new_path = filepath + ".encrypted"
    os.rename(filepath, new_path)
    return new_path

def simulate_attack():
    print("[SIMULATOR] Starting fake ransomware attack...")
    time.sleep(2)
    os.makedirs(TARGET_DIR, exist_ok=True)
    for i in range(10):
        with open(f"{TARGET_DIR}/doc_{i}.txt", 'w') as f:
            f.write("Important business document content.\n" * 50)
    honeypot = "./honeypot_files/salary_2026.xlsx"
    files = [f"{TARGET_DIR}/doc_{i}.txt" for i in range(10)]
    if os.path.exists(honeypot):
        files.append(honeypot)
    for fpath in files:
        try:
            new_path = encrypt_file(fpath)
            print(f"[SIMULATOR] Encrypted: {new_path}")
            time.sleep(0.5)
        except Exception as e:
            print(f"[SIMULATOR] Error: {e}")
    print("[SIMULATOR] Attack complete.")

if __name__ == "__main__":
    simulate_attack()
