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
    4670: {"description": "Permessi oggetto modificati", "severity": "HIGH", "filter": None},
}

WMI_MONITORED_EVENTS = {
    5861: {"description": "WMI consumer permanente registrato", "severity": "HIGH"},
    5857: {"description": "Operazione WMI provider avviata", "severity": "MEDIUM"},
    5858: {"description": "Errore operazione WMI - possibile abuso", "severity": "MEDIUM"},
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
                return {"security_last_record": 0, "wmi_last_record": 0}
            data = json.loads(content)

            # Backward compatibility - converti vecchio formato
            if "last_record_number" in data:
                return {
                    "security_last_record": data["last_record_number"],
                    "wmi_last_record": 0
                }
            return data
    except FileNotFoundError:
        return {"security_last_record": 0, "wmi_last_record": 0}

def save_checkpoint(security_record, wmi_record, checkpoint_path="data/checkpoint.json"):
    with open(checkpoint_path, "w") as f:
        json.dump({
            "security_last_record": security_record, 
            "wmi_last_record": wmi_record
        }, f)

def check_logs():
    alerts = []
    checkpoint = load_checkpoint()
    last_record = checkpoint.get("security_last_record", 0)
    wmi_last_record = checkpoint.get("wmi_last_record", 0)
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
        save_checkpoint(latest_record, wmi_last_record)

    return alerts

def check_wmi_logs():
    alerts = []
    checkpoint = load_checkpoint()
    last_record = checkpoint.get("wmi_last_record", 0)
    security_last_record = checkpoint.get("security_last_record", 0)
    latest_record = last_record

    try:
        hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-WMI-Activity/Operational")
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
                if event_id in WMI_MONITORED_EVENTS:
                    event_info = WMI_MONITORED_EVENTS[event_id]
                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "alert_type": f"WMI_EVENT_{event_id}",
                        "severity": event_info["severity"],
                        "event_id": event_id,
                        "description": event_info["description"],
                        "record_number": event.RecordNumber,
                        "details": f"WMI Event ID {event_id}: {event_info['description']}" 
                    })

        win32evtlog.CloseEventLog(hand)

    except Exception as e:
        return [{"error": f"Errore lettura WMI Event Log: {str(e)}"}]
    
    if latest_record > last_record:
        save_checkpoint(security_last_record, latest_record)
    
    return alerts