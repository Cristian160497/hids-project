import psutil
import json
import os
import sys
from datetime import datetime

PROCESS_WHITELIST = {
    "python.exe",
    "pythonw.exe",
    "bash.exe",
    "WindowsTerminal.exe",
    "dllhost.exe",
    "svchost.exe",
    "RuntimeBroker.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "WmiPrvSE.exe",
    "MoUsoCoreWorker.exe",
    "LockApp.exe",
    "TiWorker.exe",
    "audiodg.exe",
    "wuaucltcore.exe",
    "TrustedInstaller.exe",
    "vds.exe",
    "SrTasks.exe",
    "backgroundTaskHost.exe",
    "QcShm.exe",
    "MicrosoftEdgeUpdate.exe",
}

PROCESS_TRUSTED_PATHS = {
    "dllhost.exe": [
        r"C:\Windows\System32\dllhost.exe",
        r"C:\Windows\SysWOW64\dllhost.exe",
    ],
    "bash.exe": [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ],
    "python.exe": [
        r"C:\Python313\python.exe",
        r"C:\Users\user\hids-project\venv\Scripts\python.exe",
    ]
}

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_processes(baseline_path="data/baseline.json"):
    try:
        with open(baseline_path, "r") as f:
            baseline = json.load(f)
    except FileNotFoundError:
        return [{"error": "Baseline non trovata - esegui baseline-generator.py prima"}]
    
    baseline_processes = {
        proc["name"]: proc["exe"]
        for proc in baseline["processes"]
        if proc["name"]
    }

    alerts = []

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = proc.info['name']

            if not proc_name:
                continue
            proc_exe = None

            try:
                proc_exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            if proc_name not in baseline_processes:
                if proc_name not in PROCESS_WHITELIST:
                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "alert_type": "UNKNOWN_PROCESS",
                        "severity": "MEDIUM",
                        "process_name": proc_name,
                        "process_exe": proc_exe,
                        "pid": proc.info['pid'],
                        "details": "Processo non presente in baseline"
                    })

            elif proc_exe and baseline_processes[proc_name] and \
                proc_exe.lower() != baseline_processes[proc_name].lower():

                # Controlla se il percorso è nella lista dei percorsi trusted
                trusted_paths = PROCESS_TRUSTED_PATHS.get(proc_name, [])
                trusted_paths_lower = [p.lower() for p in trusted_paths]

                if proc_exe.lower() not in trusted_paths_lower:
                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "alert_type": "PROCESS_MASQUERADING",
                        "severity": "CRITICAL",
                        "process_name": proc_name,
                        "process_exe": baseline_processes[proc_name],
                        "current_exe": proc_exe,
                        "pid": proc.info['pid'],
                        "details": "Processo gira da percorso non autorizzato"
                    })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return alerts
