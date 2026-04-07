import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.file_integrity import check_file_integrity
from collector.process_monitor import check_processes
from collector.network_monitor import check_network_connections
from collector.log_monitor import check_logs

def run_engine():
    all_alerts = []

    collectors = [
        ("File Integrity Monitor", check_file_integrity),
        ("Process Monitor", check_processes),
        ("Network Monitor", check_network_connections),
        ("Log Monitor", check_logs),
    ]

    for collector_name, collector_func in collectors:
        try:
            print(f"[*] Esecuzione {collector_name}...")
            alerts = collector_func()

            errors = [a for a in alerts if "error" in a]
            valid_alerts = [a for a in alerts if "error" not in a]

            if errors:
                for e in errors:
                    print(f"  [!] Errore in {collector_name}: {e['error']}")

            all_alerts.extend(valid_alerts)
            print(f"  [+] {len(valid_alerts)} alert rilevati")

        except Exception as e:
            print(f"  [!] {collector_name} ha crashato: {str(e)}")
            continue

    return all_alerts

def save_alerts(alerts, alerts_path="data/alerts.json"):
    existing_alerts = []

    try:
        with open(alerts_path, "r") as f:
            content = f.read().strip()
            if content:
                existing_alerts = json.loads(content)
    except FileNotFoundError:
        pass

    existing_alerts.extend(alerts)

    with open(alerts_path, "w") as f:
        json.dump(existing_alerts, f, indent=4)

def print_alerts(alerts):
    if not alerts:
        print("\n[✓] Nessun alert rilevato - sistema nella norma")
        return
    
    print(f"\n{'='*50}")
    print(f"ALERT RILEVANTI: {len(alerts)}")
    print(f"{'='*50}")

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for alert in sorted(alerts, key=lambda x: severity_order.get(x.get("severity", "LOW"), 0), reverse=True):
        severity = alert.get("severity", "UNKNOWN")
        alert_type = alert.get("alert_type", "UNKNOWN")
        details = alert.get("details", "")
        timestamp = alert.get("timestamp", "")

        print(f"\n[{severity}] {alert_type}")
        print(f"  Timestamp: {timestamp}")
        print(f"  Dettagli: {details}")

    print(f"\n{'='*50}")

    