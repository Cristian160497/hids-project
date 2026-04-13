import win32evtlog
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collector.log_monitor import load_checkpoint, save_checkpoint

SYSMON_MONITORED_EVENTS = {
    1: {"description": "Process creation da processo sospetto", "severity": "HIGH"},
    8: {"description": "CreateRemoteThread - possibile process injection", "severity": "CRITICAL"},
    10: {"description": "Accesso a lsass.exe - possibile credential dumping", "sevrity": "CRITICAL"},
}

def check_sysmon_logs():
    alerts = []
    checkpoint = load_checkpoint()
    last_record = checkpoint.get("sysmon_last_record", 0)
    security_last_record = checkpoint.get("security_last_record", 0)
    wmi_last_record = checkpoint.get("wmi_last_record", 0)
    latest_record = last_record

    try:
        hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
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

                if event_id in SYSMON_MONITORED_EVENTS:
                    event_info = SYSMON_MONITORED_EVENTS[event_id]
                    alerts.append({
                        "timestamp": datetime.now().isoformat(),
                        "alert_type": f"SYSMON_EVENT_{event_id}",
                        "severity": event_info["severity"],
                        "event_id": event_id,
                        "description": event_info["description"],
                        "record_number": event.RecordNumber,
                        "details": f"Sysmon Event ID {event_id}: {event_info['description']}",
                    })
        win32evtlog.CloseEventLog(hand)

    except Exception as e:
        return [{"error": f"Errore lettura Sysmon log: {str(e)}"}]
    
    if latest_record > last_record:
        save_checkpoint(security_last_record, wmi_last_record, latest_record)
    
    return alerts

    