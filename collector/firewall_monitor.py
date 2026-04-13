import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FIREWALL_LOG_PATH = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
PORT_SCAN_THRESHOLD = 15
TIME_WINDOW_MINUTES = 1

# OP legittimi da ignorare
IP_WHITELIST = {
    "239.255.255.250", # SSDP multicast
    "255.255.255.255", # broadcast
    "127.0.0.1",       # localhost
}

def parse_firewall_log():
    entries = []

    try:
        with open(FIREWALL_LOG_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue

                fields = line.split()
                if len(fields) < 8:
                    continue

                try:
                    action = fields[2]
                    protocol = fields[3]
                    src_ip = fields[4]
                    dst_ip = fields[5]
                    dst_port = fields[6]
                    timestamp_str = f"{fields[0]} {fields[1]}"
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

                    if action == "DROP" and dst_ip not in IP_WHITELIST:
                        entries.append({
                            "timestamp": timestamp,
                            "protocol": protocol,
                            "src_ip": src_ip,
                            "dst_port": dst_port
                        })
                except (ValueError, IndexError):
                    continue

    except FileNotFoundError:
        return []
    except PermissionError:
        return []

    return entries

def check_firewall():
    alerts = []
    entries = parse_firewall_log()

    if not entries:
        return alerts

    # Finestra temporale - ultimi TIME_WINDOW_MINUTES minuti
    now = datetime.now()
    window_start = now - timedelta(minutes=TIME_WINDOW_MINUTES)

    # Raggruppa per IP sorgente
    ip_ports = defaultdict(set)

    for entry in entries:
        if entry["timestamp"] >= window_start:
            ip_ports[entry["src_ip"]].add(entry["dst_port"])

    # Rileva port scan
    for src_ip, ports in ip_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            alerts.append({
               "timestamp": datetime.now().isoformat(),
               "alert_type": "PORT_SCAN_DETECTED",
               "severity": "HIGH",
               "src_ip": src_ip,
               "ports_scanned": len(ports),
               "details": f"Possibile port scan da {src_ip} - {len(ports)} porte distinte in {TIME_WINDOW_MINUTES} minuto/i"
            })

    return alerts

                