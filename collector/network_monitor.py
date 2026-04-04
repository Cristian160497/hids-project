import psutil
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Porte sospette - comunemente usate per reverse shell e C2
SUSPICIOUS_PORTS = {
    4444,  # Metasploit default
    4445,  # Metasploit alternativo
    1337,  # LEET - comune nei tool di attacco
    31337, # Elite - backdoor classica
    8888,  # comune per C2
    9001,  # Tor default
}

# Processi che non dovrebbero mai fare connessioni di rete
SUSPICIOUS_PROCESS = {
    "lsass.exe",
    "cmd.exe",
    "regedit.exe",
    "taskmgr.exe",
}

SUSPICIOUS_IPS = {
    "185.220.101.1",  # Tor exit node noto
    "45.33.32.156",   # Scanner noto
    "198.199.10.234", # C2 documentato
}

def check_network_connections():
    alerts = []

    for conn in psutil.net_connections(kind='inet'):
        try:
            if not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            pid = conn.pid
            proc_name = None

            if pid:
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Regola 1 - Porta sospetta
            if remote_port in SUSPICIOUS_PORTS:
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "SUSPICIOUS_PORT",
                    "severity": "HIGH",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process_name": proc_name,
                    "pid": pid,
                    "details": f"Connessione verso porta sospetta {remote_port}"
                })

            # Regola 2 - Processo che non dovrebbe connettersi
            if proc_name and proc_name.lower() in {p.lower() for p in SUSPICIOUS_PROCESS}:
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "SUSPICIOUS_PROCESS_CONNECTION",
                    "severity": "CRITICAL",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process_name": proc_name,
                    "pid": pid,
                    "details": f"{proc_name} ha stabilito una connessione di rete anomala"
                })

            # Regola 3 - IP pericoloso
            if remote_ip in SUSPICIOUS_IPS:
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "SUSPICIOUS_IP",
                    "severity": "HIGH",
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process_name": proc_name,
                    "pid": pid,
                    "details": f"Connessione verso IP flaggato come pericoloso"
                })
        except Exception:
            pass

    return alerts