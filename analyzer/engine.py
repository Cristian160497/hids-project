import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collector.file_integrity import check_file_integrity
from collector.process_monitor import check_processes
from collector.network_monitor import check_network_connections
from collector.log_monitor import check_logs, check_wmi_logs
from collector.firewall_monitor import check_firewall

def run_engine():
    all_alerts = []

    collectors = [
        ("File Integrity Monitor", check_file_integrity),
        ("Process Monitor", check_processes),
        ("Network Monitor", check_network_connections),
        ("Log Monitor", check_logs),
        ("WMI Monitor", check_wmi_logs),
        ("Firewall Monitor", check_firewall),
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