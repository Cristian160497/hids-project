import time
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzer.engine import run_engine
from alerter.alert import save_alerts, print_alerts
from baseline_generator import generate_baseline

SCAN_INTERVAL = 60

def check_baseline_exists():
    return os.path.exists("data/baseline.json") and \
           os.path.getsize("data/baseline.json") > 0

def main():
    print("="*50)
    print("  HIDS — Host Intrusion Detection System")
    print("  Avviato il:", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    print("="*50)

    if not check_baseline_exists():
        print("\n[!] Baseline non trovata — generazione in corso...")
        generate_baseline()
        print("[+] Baseline generata con successo\n")
    else:
        print("\n[+] Baseline esistente trovata")

    print(f"[*] Avvio monitoraggio — intervallo: {SCAN_INTERVAL} secondi")
    print("[*] Premi CTRL+C per fermare il sistema\n")

    cycle = 0
    try:
        while True:
            cycle += 1
            print(f"\n{'='*50}")
            print(f"CICLO #{cycle} — {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*50}")

            alerts = run_engine()
            print_alerts(alerts)

            if alerts:
                save_alerts(alerts)

            print(f"\n[*] Prossimo ciclo tra {SCAN_INTERVAL} secondi...")
            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print("\n\n[!] HIDS fermato dall'utente")
        print(f"[+] Cicli completati: {cycle}")
        print("[+] Arrivederci\n")

if __name__ == "__main__":
    main()