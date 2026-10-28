import os
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
import win32evtlog

# Configurazione import per la struttura del progetto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collector.log_monitor import load_checkpoint, save_checkpoint
from splunk_exporter import SplunkExporter

# Inizializzazione dell'exporter per Splunk HEC
HEC_TOKEN = os.environ.get("HEC_TOKEN")
if not HEC_TOKEN:
    raise RuntimeError("Variabile d'ambiente HEC_TOKEN non impostata")
splunk = SplunkExporter(
    splunk_host="localhost",
    hec_port=8088,
    token=HEC_TOKEN,
    index="hids_alerts",
    use_ssl=True
)

# Mappatura Event ID Sysmon monitorati
SYSMON_MONITORED_EVENTS = {
    1: {"description": "Process creation da processo sospetto", "severity": "HIGH"},
    8: {"description": "CreateRemoteThread - possibile process injection", "severity": "CRITICAL"},
    10: {"description": "Accesso a lsass.exe - possibile credential dumping", "severity": "CRITICAL"},
}

def parse_sysmon_xml(xml_content):
    """Estrae EventID, RecordID e EventData dal payload XML dell'evento Sysmon."""
    root = ET.fromstring(xml_content)
    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    
    # Parsing Sezione System
    system = root.find('ns:System', ns)
    event_id = int(system.find('ns:EventID', ns).text)
    record_id = int(system.find('ns:EventRecordID', ns).text)
    
    # Parsing Sezione EventData (Coppie chiave-valore specifiche di Sysmon)
    event_data = {}
    event_data_node = root.find('ns:EventData', ns)
    if event_data_node is not None:
        for data in event_data_node.findall('ns:Data', ns):
            name = data.attrib.get('Name')
            if name:
                event_data[name] = data.text

    return event_id, record_id, event_data

def check_sysmon_logs():
    """Legge i nuovi eventi dal canale Sysmon e invia gli alert a Splunk."""
    alerts = []
    checkpoint = load_checkpoint()
    last_record = checkpoint.get("sysmon_last_record", 0)
    security_last_record = checkpoint.get("security_last_record", 0)
    wmi_last_record = checkpoint.get("wmi_last_record", 0)
    latest_record = last_record

    channel = "Microsoft-Windows-Sysmon/Operational"
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection

    try:
        query_handle = win32evtlog.EvtQuery(channel, flags)
    except Exception as e:
        print(f"[-] Errore apertura canale Sysmon: {e}")
        return []

    while True:
        events = win32evtlog.EvtNext(query_handle, 10)
        if not events:
            break

        for h_event in events:
            try:
                xml_content = win32evtlog.EvtRender(h_event, win32evtlog.EvtRenderEventXml)
                event_id, record_id, event_data = parse_sysmon_xml(xml_content)

                # Filtro basato su Checkpoint
                if record_id <= last_record:
                    continue

                if record_id > latest_record:
                    latest_record = record_id

                # Se l'Event ID è tra quelli monitorati dall'HIDS
                if event_id in SYSMON_MONITORED_EVENTS:
                    event_info = SYSMON_MONITORED_EVENTS[event_id]

                    alert_data = {
                        "timestamp": datetime.now().isoformat(),
                        "alert_type": f"SYSMON_EVENT_{event_id}",
                        "severity": event_info["severity"],
                        "event_id": event_id,
                        "description": event_info["description"],
                        "record_number": record_id,
                        "image": event_data.get("Image", "N/A"),
                        "command_line": event_data.get("CommandLine", "N/A"),
                        "user": event_data.get("User", "N/A"),
                        "details": f"Sysmon Event ID {event_id}: {event_info['description']}",
                    }

                    alerts.append(alert_data)

                    # Inoltro alert a Splunk
                    sent = splunk.send_alert(
                        rule_name=f"SYSMON_EVENT_{event_id}",
                        severity=event_info["severity"],
                        details={
                            "description": event_info["description"],
                            "record_number": record_id,
                            "image": alert_data["image"],
                            "command_line": alert_data["command_line"],
                            "user": alert_data["user"],
                            "raw_details": alert_data["details"]
                        },
                        sysmon_event_id=event_id
                    )
                    if sent:
                        print(f"[+] [{datetime.now().strftime('%H:%M:%S')}] Alert SYSMON_EVENT_{event_id} inviato a Splunk (Record #{record_id})")
                    else:
                        print(f"[-] [{datetime.now().strftime('%H:%M:%S')}] Alert SYSMON_EVENT_{event_id} NON inviato a Splunk (Record #{record_id})")    

            except Exception as parse_err:
                print(f"[-] Errore nel parsing dell'evento: {parse_err}")
                continue

    # Salva il checkpoint aggiornato se ci sono stati nuovi log
    if latest_record > last_record:
        save_checkpoint(security_last_record, wmi_last_record, latest_record)

    return alerts

if __name__ == "__main__":
    print("[*] Avvio il monitoraggio continuo di Sysmon HIDS...")
    print("[*] In ascolto per nuovi eventi...")
    
    try:
        while True:
            check_sysmon_logs()
            time.sleep(2)  # Polling ogni 2 secondi
    except KeyboardInterrupt:
        print("\n[*] Monitoraggio arrestato dall'utente.")