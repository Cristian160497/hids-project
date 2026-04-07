import json
import os

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