import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from baseline_generator import calculate_hash

def check_file_integrity(baseline_path="data/baseline.json"):
    try:
        with open(baseline_path, "r") as f:
            baseline = json.load(f)
    except FileNotFoundError:
        return [{"error": "Baseline non trovata - esegui baseline_generator.py prima"}]
    
    alerts = []

    for filepath, file_data in baseline["files"].items():
        expected_hash = file_data["hash"]
        severity = file_data["severity"]
        current_hash = calculate_hash(filepath)

        if current_hash != expected_hash:
            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "alert_type": "FILE_MODIFIED",
                "severity": severity,
                "filepath": filepath,
                "expected_hash": expected_hash,
                "current_hash": current_hash,
                "details": "Hash mismatch rilevato"
            })

    return alerts