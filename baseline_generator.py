import psutil
import hashlib
import json
import os
from datetime import datetime

FILES_TO_MONITOR = {
    r"C:\Windows\System32\ntoskrnl.exe": "CRITICAL",
    r"C:\Windows\System32\drivers\etc\hosts": "CRITICAL",
    r"C:\Windows\System32\cmd.exe": "HIGH",
    r"C:\Windows\System32\lsass.exe": "MEDIUM",
    # bootmgr escluso: su sistemi UEFI risiede nella EFI System Partition
    # percorso reale: \EFI\MICROSOFT\BOOT\BOOTMGFW.EFI
    # non accessibile tramite filesystem Windows standard
}

def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return "ERROR: file non trovato"
    except PermissionError:
        return "ERROR: accesso negato"
    except Exception as e:
        return f"ERROR: {str(e)}"

def get_processes_baseline():
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            info = {
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "exe": None,
                "username": None
            }
            try:
                info["exe"] = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                info["username"] = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            processes.append(info)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

def get_network_baseline():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            connections.append({
                "pid": conn.pid,
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status
            })
        except Exception:
            pass
    return connections

def generate_baseline():
    print("[*] Generazione baseline in corso...")

    baseline = {
        "generated_at": datetime.now().isoformat(),
        "files": {},
        "processes": [],
        "connections": []
    }

    print("[*] Calcolo hash file critici...")
    for filepath, severity in FILES_TO_MONITOR.items():
        baseline["files"][filepath] = {
            "hash": calculate_hash(filepath),
            "severity": severity
        }
        print(f"    [{severity}] {filepath}: {baseline['files'][filepath]['hash'][:20]}...")

    print("[*] Raccolta processi in esecuzione...")
    baseline["processes"] = get_processes_baseline()
    print(f"    {len(baseline['processes'])} processi rilevati")

    print("[*] Raccolta connessioni di rete...")
    baseline["connections"] = get_network_baseline()
    print(f"    {len(baseline['connections'])} connessioni rilevate")

    output_path = os.path.join("data", "baseline.json")
    with open(output_path, "w") as f:
        json.dump(baseline, f, indent=4)

    print(f"\n[+] Baseline salvata in {output_path}")
    print(f"[+] Generata il: {baseline['generated_at']}")

if __name__ == "__main__":
    generate_baseline()