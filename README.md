# HIDS — Host Intrusion Detection System

Implementation of a host-based intrusion detection system for Windows systems. 
It monitors four attack surfaces targeted during system attacks: monitoring of 
critical system files, monitoring of system logs, network connection monitoring, 
and monitoring of system processes. Detection is performed according to specific 
rules based on the main attack techniques mapped within the MITRE ATT&CK framework.

---

## Motivation

This project was built from scratch in Python rather than using existing tools 
or infrastructure for several concrete reasons.

**Network-level detection was not feasible:** the initial goal was to deploy the 
system on the home WiFi network. However, the available router falls into the 
4/32 hardware category — 4MB Flash and 32MB RAM — explicitly marked as 
unsupported by recent OpenWrt versions. Without a custom firmware, full traffic 
visibility was not achievable.

**Cloud infrastructure was not an option:** deploying Wazuh components on cloud 
providers (Google Cloud, Oracle Cloud) was evaluated as an alternative. Both 
platforms require a credit or debit card for registration — including their free 
tiers — ruling out this approach without any financial investment.

**Resource constraints on local hardware:** a full Wazuh stack requires a minimum 
of 8GB RAM dedicated to its components alone. The available machine runs Windows 11 
on an entry-level processor with 8GB total RAM shared with the operating system, 
making a local virtualized deployment unfeasible.

**Learning objectives:** building a custom HIDS from scratch in Python provides 
genuine understanding of how intrusion detection systems work internally. Every 
architectural decision was made deliberately and documented — from Windows Event 
Log parsing to SHA-256 file integrity verification and process masquerading 
detection — rather than delegated to a pre-built tool.

---

## Architecture

The system is divided into four distinct layers following a **Separation of 
Concerns** principle — each module has a single, well-defined responsibility. 
This design also ensures **fault isolation**: if one collector fails, the others 
continue running independently.

```text
main.py
├── collector/
│   ├── file_integrity.py   → SHA-256 hash comparison against baseline
│   ├── process_monitor.py  → process whitelist and masquerading detection
│   ├── network_monitor.py  → behavioral rules for suspicious connections
│   └── log_monitor.py      → Windows Event Log parsing (5 critical Event IDs)
├── analyzer/
│   └── engine.py           → aggregates alerts from all collectors
├── alerter/
│   └── alert.py            → prints and persists alerts to disk
└── data/
    ├── baseline.json        → system snapshot (hashes, processes, connections)
    ├── checkpoint.json      → last processed Event Log record number
    └── alerts.json          → persistent alert history
```

**Data flow:** each collector independently detects anomalies and returns a list 
of alerts. The analyzer aggregates all results, applying fault isolation so that 
a failing collector does not block the others. The alerter then prints alerts to 
console sorted by severity and appends them to the persistent alert history.

**Detection approach:** a rule-based engine was chosen over anomaly-based 
detection for two reasons. First, rule-based detection is simpler to implement, 
explain, and audit. Second, anomaly-based detection requires a training period 
on historical data to establish a behavioral baseline — on a new system without 
historical data, it would generate excessive false positives and be unreliable. 
Anomaly-based detection is planned for V2.

**Main loop:** `main.py` acts as the entry point, automatically generating the 
baseline if not present, then running all collectors in a continuous loop with 
a configurable interval (default: 60 seconds). The loop can be interrupted 
cleanly with CTRL+C.

---

## Modules

### File Integrity Monitor (`collector/file_integrity.py`)
Monitors four critical Windows system files by comparing their current SHA-256 
hash against the value stored in the baseline snapshot. Any mismatch generates 
an alert indicating the file path, expected hash, current hash, timestamp, and 
severity level.

**Monitored files and severity:**

| File | Severity | Reason |
|---|---|---|
| `ntoskrnl.exe` | CRITICAL | Windows kernel — compromise means full system takeover |
| `lsass.exe` | CRITICAL | Manages authentication and credentials — primary target for credential dumping attacks |
| `cmd.exe` | HIGH | Replacement with a malicious version enables arbitrary code execution |
| `drivers\etc\hosts` | MEDIUM | Modification enables DNS hijacking and traffic redirection |

Severity levels were assigned based on the blast radius of a successful 
tampering — how much of the system would be compromised if that file were 
modified by an attacker.

---

### Process Monitor (`collector/process_monitor.py`)
Monitors running processes against a baseline snapshot and a curated whitelist 
of known legitimate Windows processes. Two distinct conditions generate an alert:

1. **Unknown process:** a running process is not present in the baseline and 
not included in the whitelist of known legitimate processes.

2. **Process masquerading (MITRE T1036):** a process matches a known legitimate 
name but runs from an unexpected path. This technique is commonly used by 
malware to impersonate system processes — for example, a malicious `lsass.exe` 
running from `AppData\Roaming` instead of `System32`.

To handle legitimate cases where the same process can run from multiple valid 
paths (e.g. `dllhost.exe` from both `System32` and `SysWOW64`), a 
`PROCESS_TRUSTED_PATHS` dictionary defines acceptable paths per process — 
preventing false positives without weakening detection.

**Alert severity:** CRITICAL for process masquerading, MEDIUM for unknown 
processes.

---

### Network Monitor (`collector/network_monitor.py`)
Unlike the other collectors, the Network Monitor does not compare against a 
static baseline. Network connections are inherently dynamic — created and closed 
within seconds — making baseline comparison unreliable and prone to excessive 
false positives. Instead, detection is based on three behavioral rules applied 
to all active connections in real time.

**Rule 1 — Suspicious port:** flags connections toward ports commonly associated 
with reverse shells and Command & Control (C2) infrastructure.

| Port | Known usage |
|---|---|
| 4444 | Metasploit default |
| 4445 | Metasploit alternative |
| 1337 | Common attack tooling |
| 31337 | Classic backdoor |
| 8888 | Common C2 |
| 9001 | Tor default |

**Rule 2 — Suspicious process connection:** flags connections initiated by 
processes that should never communicate over the network under normal 
circumstances (`lsass.exe`, `cmd.exe`, `regedit.exe`, `taskmgr.exe`). An 
outbound connection from any of these processes is a strong indicator of 
compromise.

**Rule 3 — Suspicious IP:** flags connections toward IP addresses documented 
as malicious in public threat intelligence sources. The current implementation 
uses a static list updated manually — automated threat intelligence feed 
integration is planned for V2.

**Alert severity:** CRITICAL for suspicious process connections, HIGH for 
suspicious ports and IPs.

---

### Log Monitor (`collector/log_monitor.py`)
Parses the Windows Security Event Log monitoring five critical Event IDs selected 
based on the **MITRE ATT&CK framework** — mapping known attack techniques to 
their corresponding Windows events.

| Event ID | Description | Severity | MITRE Tactic |
|---|---|---|---|
| 4625 | Failed login attempt | MEDIUM | Initial Access |
| 4688 | New process created | LOW | Execution |
| 4697 | New service installed | HIGH | Persistence |
| 4698 | New scheduled task created | HIGH | Persistence |
| 4663 | File/object access attempt | MEDIUM | Defense Evasion |

**Checkpoint pattern:** to avoid reprocessing already-analyzed events, the 
last processed record number is saved to `data/checkpoint.json` at the end 
of each cycle. The next cycle resumes from that record number — ensuring no 
events are missed or duplicated.

**Event 4688 filter:** new process creation events are extremely frequent on 
any active Windows system — generating hundreds of events per minute. To avoid 
alert fatigue, Event 4688 only generates an alert when the parent process is 
in a list of known suspicious processes associated with Living off the Land 
(LotL) attacks and reverse shell techniques: `cmd.exe`, `powershell.exe`, 
`wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`.

A parent process field is extracted from `StringInserts[13]` of the event 
record — the Windows-specific field containing the full path of the process 
that spawned the new one.

---

## Installation

### Prerequisites
- Windows 10 or Windows 11
- Python 3.x — verify with `python --version`
- Git — verify with `git --version`

### Steps

1. Clone the repository:
```bash
git clone https://github.com/yourusername/hids-project.git
cd hids-project
```

2. Create and activate the virtual environment:
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### ⚠️ Important
The HIDS must be run as **Administrator** — it requires elevated privileges 
to access the Windows Security Event Log and read protected system files.

Always open PowerShell with **"Run as Administrator"** before executing any 
script.

---

## Usage

### First run — Generate the baseline
Before starting the monitor, a baseline snapshot of the system must be generated.
Run this command on a **clean, uncompromised system**:

```bash
python baseline_generator.py
```

This captures the SHA-256 hashes of critical system files, the list of running 
processes, and active network connections. The baseline is saved to 
`data/baseline.json`.

⚠️ **Regenerate the baseline after Windows updates** — system file hashes 
change after updates, causing false positive FILE_MODIFIED alerts.

### Start the monitor
```bash
python main.py
```

The system will run continuously, executing all collectors every 60 seconds. 
Press `CTRL+C` to stop.

### Interpreting alerts

| Severity | Action required |
|---|---|
| CRITICAL | Immediate investigation — check Windows Event Viewer and isolate the affected file or process |
| HIGH | Prompt investigation — likely a real threat requiring attention |
| MEDIUM | Investigate when possible — could be a false positive, verify in Event Viewer |
| LOW | Log only — monitor for patterns over time |

### Investigating alerts
All alerts are saved to `data/alerts.json` with full details — timestamp, 
alert type, severity, and relevant metadata.

For log-based alerts, cross-reference with **Windows Event Viewer** 
(Windows Logs → Security) filtering by the Event ID included in the alert. 
This provides full context — account name, logon type, and workstation.

This investigation process is known as **alert triage**.

---

## Technical Decisions

### SHA-256 for file integrity verification
MD5 and SHA-1 were deliberately avoided despite being faster. Both algorithms 
are vulnerable to collision attacks — an attacker could craft a malicious file 
that produces the same hash as the original, defeating integrity checks entirely. 
SHA-256 has no known collisions and is the current standard for integrity 
verification in security contexts.

### Rule-based detection over anomaly-based
A rule-based engine was chosen for V1 for two reasons: it is auditable — every 
alert can be traced back to a specific rule — and it does not require a training 
period. Anomaly-based detection needs historical data to establish a behavioral 
baseline, making it unreliable on a new system with no prior history. It is 
planned for V2.

### Modular architecture — Separation of Concerns
Each layer (collector, analyzer, alerter) has a single responsibility. This 
enables fault isolation — a failing collector does not block the others — and 
makes the codebase easier to extend. Adding a new detection surface only 
requires adding a new collector without touching existing modules.

### Checkpoint pattern over timestamp in Log Monitor
The last processed Windows Event Log record number is saved instead of a 
timestamp. Record numbers are sequential unique integers — direct access with 
no ambiguity. Timestamps are not unique: multiple events can share the same 
millisecond timestamp, making timestamp-based filtering unreliable and 
potentially causing missed or duplicated events.

### Graceful degradation in Process Monitor
Process attributes like `exe` and `username` are collected in independent 
try/except blocks. If reading one attribute fails due to `AccessDenied`, the 
process is still added to the results with that field set to `null` — rather 
than discarding the entire process. This maximizes data collection without 
crashing on protected system processes.

---

## Known Limitations

### Windows only
The system relies on `pywin32` for Windows Event Log access and on 
Windows-specific APIs for process and file monitoring. Detection rules are 
also mapped to Windows-specific attack vectors. Porting to Linux or macOS 
would require rewriting all four collectors.

### Baseline requires manual regeneration after Windows updates
Windows updates replace system files with newer versions, changing their 
SHA-256 hashes. After a significant update, the baseline must be manually 
regenerated with `python baseline_generator.py` to avoid persistent 
FILE_MODIFIED false positives on legitimate system files.

### Whitelist bypass risk
The process whitelist introduces a known weakness: an attacker aware of the 
whitelisted process names could name their malware after a whitelisted process 
to evade detection. This is partially mitigated by the `PROCESS_TRUSTED_PATHS` 
check — a whitelisted process running from an unexpected path still generates 
a PROCESS_MASQUERADING alert — but does not fully eliminate the risk.

### Static threat intelligence
The Network Monitor uses a static list of known malicious IPs. New malicious 
IPs documented after the last manual update will not be detected. Automated 
threat intelligence feed integration — pulling updated IP lists periodically 
from sources like AbuseIPDB — is planned for V2.

---

## Roadmap

### V2 — Anomaly-based detection
Implement a machine learning model that learns normal system behavior over time 
and flags deviations automatically — moving from static rules to dynamic 
behavioral analysis. Requires a training period on historical data collected 
by the current rule-based engine.

### V2 — Dynamic threat intelligence
Replace static lists with automated feeds updated periodically from public 
threat intelligence sources (AbuseIPDB, emerging threats lists). This covers 
suspicious ports, malicious IPs, and known malicious process signatures — 
ensuring detection rules stay current without manual intervention.

### V2 — Event-driven baselining
Automatically detect when a Windows update is in progress (by monitoring 
`TiWorker.exe` and `TrustedInstaller.exe`) and regenerate the baseline 
automatically upon completion — eliminating the need for manual regeneration 
after every update.

### V3 — Alert notification system
Integrate real-time alert delivery via email, Telegram, or Slack — enabling 
monitoring without keeping a terminal open. CRITICAL alerts would trigger 
immediate notifications.

### V3 — Network-level monitoring expansion
Extend the system beyond a single host toward network-level monitoring — 
integrating with a properly configured router or a dedicated device to capture 
and analyze traffic across the entire local network.

### V3 — Visualization dashboard
Replace JSON-based alert storage with a lightweight web dashboard for 
real-time alert visualization, historical analysis, and trend detection.
