import os
import shutil
import psutil
import datetime

QUARANTINE_DIR = "./quarantine"


def suspend_and_kill_process(pid: int) -> str | None:
    """Instantly suspend process threads to halt encryption, then terminate."""
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        
        # Step 1: Freeze execution immediately
        try:
            proc.suspend()
            print(f"[CONTAINMENT] Frozen PID {pid} ({proc_name})")
        except Exception:
            pass

        # Step 2: Terminate process
        proc.kill()
        print(f"[CONTAINMENT] Terminated PID {pid} ({proc_name})")
        return proc_name
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as err:
        print(f"[CONTAINMENT ERROR] Could not suspend/kill PID {pid}: {err}")
        return None


def kill_process_by_path(filepath: str) -> str | None:
    """Safely find offending process without blocking on Windows kernel handles."""
    try:
        current_pid = os.getpid()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid = proc.info['pid']
                if pid == current_pid:
                    continue
                cmdline = " ".join(proc.info.get('cmdline') or []).lower()
                if "fake_ransomware" in cmdline:
                    return suspend_and_kill_process(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        print(f"[ERROR] Process search failed: {e}")
    return None


def isolate_file(filepath: str) -> str | None:
    """Move affected file to quarantine directory safely with fallback retry."""
    if not os.path.exists(filepath):
        return None

    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    timestamp_prefix = datetime.datetime.now().strftime("%H%M%S")
    dest = os.path.join(QUARANTINE_DIR, f"{timestamp_prefix}_{os.path.basename(filepath)}")

    try:
        shutil.move(filepath, dest)
        print(f"[CONTAINMENT] Isolated: {filepath} -> {dest}")
        return dest
    except PermissionError:
        try:
            shutil.copy2(filepath, dest)
            print(f"[CONTAINMENT] Copy-Isolated (Locked): {filepath} -> {dest}")
            return dest
        except Exception as copy_err:
            print(f"[ERROR] Could not isolate locked file {filepath}: {copy_err}")
            return None
    except Exception as e:
        print(f"[ERROR] Could not isolate {filepath}: {e}")
        return None
