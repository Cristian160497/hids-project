import win32evtlog
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MONITORED_EVENTS = {
    4625: {"description": "Login fallito", "severity": "MEDIUM", "filter": None},
    4688: {"description": "Nuovo processo creato", "severity": "LOW", "filter": "suspicious_parent"},
    4697: {"description": "Nuovo servizio installato", "severity": "HIGH", "filter": None},
    4698: {"description": "Nuovo scheduled task creato", "severity": "HIGH", "filter": None},
    4663: {"description": "Tentativo accesso a file/oggetto", "severity": "MEDIUM", "filter": None},
}

SUSPICIOUS_PARENT_PROCESSES = {
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
}

def load_checkpoint(checkpoint_path="data/checkpoint.json"):
    try:
        with open(checkpoint_path, "r") as f:
            content = f.read().strip()
            if not content:
                return {"last_record_number": 0}
            return json.loads(content)
    except FileNotFoundError:
        return {"last_record_number": 0}

def save_checkpoint(record_number, checkpoint_path="data/checkpoint.json"):
    with open(checkpoint_path, "w") as f:
        json.dump({"last_record_number": record_number}, f)

def check_logs():
    alerts = []
    checkpoint = load_checkpoint()
    last_record = checkpoint.get("last_record_number", 0)
    latest_record = last_record

    try:
        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        events = True
        while events:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            for event in events:
                if event.RecordNumber <= last_record:
                    continue

                if event.RecordNumber > latest_record:
                    latest_record = event.RecordNumber

                event_id = event.EventID & 0xFFFF

                if event_id in MONITORED_EVENTS:
                    event_info = MONITORED_EVENTS[event_id]

                    if event_info["filter"] == "suspicious_parent":
                        try:
                            parent_process = event.StringInserts[13] if event.StringInserts else None
                            if not parent_process:
                                continue
                            parent_name = os.path.basename(parent_process).lower()
                            if parent_name not in SUSPICIOUS_PARENT_PROCESSES:
                                continue
                        except (IndexError, TypeError):
                            continue

                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "alert_type": f"EVENT_{event_id}",
                        "severity": event_info["severity"],
                        "event_id": event_id,
                        "description": event_info["description"],
                        "record_number": event.RecordNumber,
                        "details": f"Event ID {event_id} rilevato: {event_info['description']}"
                    })

        win32evtlog.CloseEventLog(hand)

    except Exception as e:
        return [{"error": f"Errore lettura Event Log: {str(e)}"}]

    if latest_record > last_record:
        save_checkpoint(latest_record)

    return alerts