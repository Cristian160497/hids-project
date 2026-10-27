import os
import json
import logging
from datetime import datetime, timezone
import requests
import urllib3

# Silenzia gli avvisi per i certificati SSL non verificati (self-signed di Splunk)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurazione logging locale per il modulo
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class SplunkExporter:
    def __init__(self, splunk_host="localhost", hec_port=8088, token="", index="hids_alerts", use_ssl=True):
        """
        Inizializza l'exporter per Splunk HEC.
        Di default use_ssl=True poiché Splunk HEC utilizza HTTPS sulla porta 8088.
        """
        protocol = "https" if use_ssl else "http"
        self.url = f"{protocol}://{splunk_host}:{hec_port}/services/collector/event"
        self.headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json"
        }
        self.index = index
        self.use_ssl = use_ssl
        
    def send_alert(self, rule_name: str, severity: str, details: dict, sysmon_event_id: int = None) -> bool:
        """
        Struttura l'alert HIDS e lo invia a Splunk.
        """
        payload = {
            "index": self.index,
            "sourcetype": "_json",
            "event": {
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "agent": "Python-HIDS-V2",
                "rule_name": rule_name,
                "severity": severity,
                "sysmon_event_id": sysmon_event_id,
                "details": details
            }
        }

        try:
            response = requests.post(
                self.url,
                headers=self.headers,
                data=json.dumps(payload),
                verify=False if self.use_ssl else True, # Disabilita verifica SSL per cert self-signed
                timeout=5
            )

            # CORRETTO: response.status_code anziché response.status.code
            if response.status_code == 200:
                logging.info(f"[+] Alert '{rule_name}' inviato con successo a Splunk.")
                return True
            else:
                logging.error(f"[-] Errore invio Splunk ({response.status_code}): {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"[-] Impossibile Connettersi a Splunk: {e}")
            return False

# --- TEST DI VERIFICA MANUALE ---
if __name__ == "__main__":
    HEC_TOKEN = os.environ.get("HEC_TOKEN")
    if not HEC_TOKEN:
        raise RuntimeError("Variabile d'ambiente HEC_TOKEN non impostata")
    splunk = SplunkExporter(
        splunk_host="localhost",
        hec_port=8088,
        token=HEC_TOKEN,
        index="hids_alerts",
        use_ssl=True # Impsotato a True per utilizzare HTTPS
    )

    # CORRETTO: test_details (senza la 's' finale)
    test_details = {
        "ProcessName": "powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Write-Host HIDS_Test",
        "User": "NT AUTHORITY\\SYSTEM",
        "ProcessId": 4820,
        "ParentProcessName": "cmd.exe"
    }

    # Invio di prova
    splunk.send_alert(
        rule_name="Suspicious_PowerShell_Execution",
        severity="HIGH",
        details=test_details,
        sysmon_event_id=1
    )