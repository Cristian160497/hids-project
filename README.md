# HIDS - Host Intrusion Detection System

Implementation of a host-based intrusion detection system for Windows systems. The process monitors four attack surfaces targeted during system attacks: monitoring critical system files, monitoring system logs, monitoring network connections and monitoring system processes. Detection is performed following precise rules based on the main attack techniques mapped within the MITRE ATT&CK framework. 

---

## Motivation

This project was built from scratch in Python rather than using existing tools of infrastructure for several concrete reasons.

**Network-level detection was not feasible:** the initial goal was to deploy the system on the home WiFi network. However, the available router falls into the 4/32 hardware category - 4MB Flash and 32MB RAM - explicitly marked as unsupported by recent OpenWrt versions. Without a custom firmware, full traffic visibility was not achievable.

**Cloud infrastructure was not an option:** deploying Wazuh components on cloud providers (Google Cloud, Oracle Cloud) was evaluated as an alternative. Both platforms require a credit or debit card for registration - including their free tiers - ruling out this approach without any financial investment.

**Resource constraints on local hardware:** a full Wazuh stack requires a minimum of 8GB RAM dedicated to its comoponents alone. The available machine runs Windows 11 on an entry-level processor with 8GB total RAM shared with the operating system, making a local virtualized deployment unfeasible.

**Learning objectives.** building a custom HIDS from scratch in Python provides genuine understanding of how intrusion detection systems work internally. Every architectural decision was made deliberately and documented - from Windows Event Log parsing to SHA-256 file integrity verification and process masquerading detection - rather than delegated to a pre-built tool.

## Architecture

The system is divided into four distinct layers following a **Separation of Concerns** principle - each module has a single, well-defined responsibility. This design also ensures **fault isolation**: if one collector fails, the others continue running independently.

```text
main.py
├── collector/
│   ├── file_integrity.py    → SHA-256 hash comparison against baseline
│   ├── process_monitor.py   → process whitelist and masquerading detection
│   ├── network_monitor.py   → behavioral rules for suspicious connections
│   ├── log_monitor.py       → Windows Event Log parsing (6 critical Event IDs + WMI)
│   ├── firewall_monitor.py  → port scan detection via Windows Firewall log
│   └── sysmon_monitor.py    → kernel-level detection via Sysmon (Event IDs 1, 8, 10)
├── analyzer/
│   └── engine.py            → aggregates alerts from all collectors
├── alerter/
│   └── alert.py             → prints and persists alerts to disk
└── data/
    ├── baseline.json         → system snapshot (hashes, processes, connections)
    ├── checkpoint.json       → last processed record number for Security, WMI and Sysmon logs
    └── alerts.json           → persistent alert history
```
**Data flow:** each collector independently detects anomalies and returns a list of alerts. The analyzer aggregates alla results, applying fault isolation so that a failing collector does not block the others. The alerter then prints alerts to console sorted by severity and appends them to the persistent alert history.

**Detection approach:** a rule-based engine was chosen over anomaly-based detection for two reasons. First, rule-based detection is simpler to implement, explain, and audit. Second, anomaly-based detection requires a training period on historical data to establish a behavioral baseline - on a new system without historical data, it would generate excessive false positives and be unreliable. Anomaly-based detection is planned for V2.

**Main loop:** `main.py` acts as the entry point, automatically generating the baseline if not present, then running all collectors in a continuos loop with a configurable interval (default: 60 seconds). The loop can be interrupted cleanly with CTRL+C.

---

## Modules

### File Integrity Monitor (`collector/file_integrity.py`)
Monitors four critical Windows system by comparing their current SHA-256 hash against the value stored in the baseline snapshot. Any mismatch generates an alert indicating the file path, expected hash, current hash, timestamp, and severity level.

**Monitored files and severity**

| File | Severity | Reason |
|---|---|---|
| `ntoskrnl.exe` | CRITICAL | Windows kernel - compromise means full system takeover |
| `lsass.exe` | CRITICAL | Manages authentication and credentials - primary target for credential dumping attacks |
| `cmd.exe` | HIGH | Replacement with a malicious version enables arbitrary code execution |
| `drivers\etc\hosts` | MEDIUM | Modification enables DNS hijacking and traffic redirection |

Severity levels were assigned based on the blast radius of a successful tampering - how much of the system would be compromised if that file were modified by an attacker.

---

### Process Monitor (`collector/process_monitor.py`)
Monitors running processes against a baseline snapshot and a curated whitelist of known legitimate Windows processes. Two distinct conditions generate an alert:

1. **Unknown process:** a running process is not present in the baseline and not included in the whitelist of known legitimate processes.

2. **Process masquerading (MITRE T1036):** a process matches a known legitimate name but runs from an unexpected path. This technique is commonly used by malware to impersonate system processes - for example, a malicious `lsass.exe` running from `AppData\Roaming` instead of `System32`.

To handle legitimate cases where the same process can run from multiple valid paths (e.g. `dllhost.exe` from both `System32` and `SysWOW64`), a `PROCESS_TRUSTED_PATHS` dictionary defines acceptable paths per process - preventing false positives without weakening detection.

**Alert severity:** CRITICAL for process masquerading, MEDIUM for unknown processes.

---

### Network Monitor (`collector/network_monitor.py`)
Unlike the other collectors, the Network Monitor does not compare against a static baseline. Network connections are inherently dynamic - created and closed within seconds - making baseline comparison unreliable and prone to excessive false positives. Instead, detection is based on three behavioral rules applied to all active connections in real time.

**Rule 1 - Suspicious port:** flags connections toward ports commonly associated with reverse shells and Command & Control (C2) infrastructure.

| Port | Known usage |
|---|---|
| 4444 | Metasploit default |
| 4445 | Metasploit alternative |
| 1337 | Common attack tooling |
| 31337 | Classic backdoor |
| 8888 | Common C2 |
| 9001 | Tor default |

**Rule 2 - Suspicious process connection:** flags connections initiated by processes that should never communicate over the network under normal circumstances (`lsass.exe`, `cmd.exe`, `regedit.exe`, `taskmgr.exe`). An outbound connection from any of these processes is a strong indicator of compromise.

**Rule 3 - Suspicious IP:** flags connections toward IP addresses documented as malicious in public threat intelligence sources. The current implementation uses a static list updated manually - automated threat intelligence feed integration is planned for V2.

**Alert severity:** CRITICAL for suspicious process connections, HIGH for suspicious ports and IPs.

---

### Log Monitor (`collector/log_monitor.py`)
Parses the Windows Security Event Log monitoring five critical Event IDs selected based on the **MITRE ATT&CK framework** - mapping known attack techniques to their corresponding Windows events.

| Event ID | Description | Severity | MITRE Tactic |
|---|---|---|---|
| 4625 | Failed login attempt | MEDIUM | Initial Access |
| 4688 | New process created | LOW | Execution |
| 4697 | New service installed | HIGH | Persistence |
| 4698 | New scheduled task created | HIGH | Persistence |
| 4663 | File/object access attempt | MEDIUM | Defense Evasion |

**Checkpoint pattern:** to avoid reprocessing already-analyzed events, the last processed record number is saved to `data/checkpoint.json` at the end of the cycle. The next cycle resumes from that record number - ensuring no events are missed or duplicated.

**Event 4688 filter:** new process creation events are extremely frequent on any active Windows system - generating hundreds of events per minute. To avoid alert fatigue, Event 4688 only generates an alert when the parent process is in a list of known suspicious processes associated with a Living off the Land (LotL) attacks and reverse shell techniques: `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`.

A parent process field is extracted from `StringInserts[13]` of the event record - the Windows-specific filed containing the full path of the process that spawned the new one.

### WMI Monitor (`collector/log_monitor.py`)
Monitors the `Microsoft-Windows-WMI-Activity/Operational` Event Log for suspicious WMI activity - a technique commonly used by attackers to execute malicious commands without installing new software.

| Event ID | Description | Severity |
|---|---|---|
| 5857 | WMI provider operation started | MEDIUM |
| 5858 | WMI operation error - possible abuse | MEDIUM |
| 5861 | Permanent WMI consumer registered | HIGH |

Event ID 5861 is particularly critical - it indicates the registration of a permanent WMI subscription, a technique used to achieve fileless persistence that survives reboots and does not appear in the Task Scheduler.

---

### Firewall Monitor (`collector/firewall_monitor.py`)
Reads the Windows Firewall log (`pfirewall.log`) to detect inbound port scanning - the reconnaissance phase that typically precedes an attack.

The collector groups DROP connections by source IP using a `defaultdict(set)` and generates a PORT_SCAN_DETECTED alert when a single source IP attempts connections to more than **15 distinct destination ports** within a 60-second window. Known legitimate multicast addresses (e.g. SSDP on `239.255.255.250`) are excluded via an IP whitelist.

**Prerequisite:** Windows Firewall logging must be enabled before the collector can function:
```powershell
netsh advfirewall set allprofiles logging must be enabled before the collector can function:
```

**Alert severity:** HIGH

---

### Sysmon Monitor (`collector/sysmon_monitor.py`)
Reads the `Microsoft-Windows-Sysmon/Operational` Event Log to provide kernel-level visibility into attack techniques that the Windows Security Event Log cannot detect natively.

Sysmon v15.20 is configured via a custom XML file that limits logging to three critical Event IDs - minimizing resource consumption while maximizing detection coverage.

| Event ID | Description | Severity |
|---|---|---|
| 1 | Process creation from suspicious parent process | HIGH |
| 8 | CreateRemoteThread - process injection attempt | CRITICAL |
| 10 | lsass.exe access - credential dumping attempt | CRITICAL |

**Prerequisite:** Sysmon must be installed and configured before this collector can function:
```powershell
.\Sysmon64.exe -accepteula -i sysmon-config.xml
```

---

## Installation

### Prerequisites
- Windows 10 or Windows 11
- Python 3.x - verify with `python --version`
- Git - verify with `git --version`

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
The HIDS must be run as **Administrator** - it requires elevated privileges to access the Windows Security Event Log and read protected system files.

Always open PowerShell with **"Run as Administrator"** before executing any scripts.

---

## Usage

### First run - generate the baseline
Before starting the monitoring loop, generate the system baseline:
```bash
python baseline_generator.py
```
This creates a snapshot of the current system state - file hashes, running processes, and active network connections - saved to `data/baseline.json`.

> **Note:** the baseline must be regenerated manually after Windows updates,
> as system file hashes change with each update. Failure to do so will generate
> false positive FILE_MODIFIED alerts.

### Start the monitoring loop
```bash
python main.py
```
The system will automatically verify the baseline exists, the start monitoring all four attack surfaces in a continuous loop with a 60-second interval.
Press `CTRL+C` to stop.

### Interpreting alerts
Each alert includes: timestamp, alert type, severity level, and details.

| Severity | Action required |
|---|---|
| CRITICAL | Immediate investigation - isolate the affected file or processes |
| HIGH | Investigate within minutes - check Windows Event Viewer for details |
| MEDIUM | Investigate within the hour - may be a false positive |
| LOW | Review at next opportunity - likely benign |

### Investigating CRITICAL and HIGH alerts
1. Note the `alert_type`, `filepath` or `process_name`, and `timestamp`
2. Open **Windows Event Viewer** -> **Windows Logs -> Security**
3. Filter by the relevant Event ID
4. Analyze the details - account name, logon type, workstation
5. Conclude whether it is a genuine threat or a false positive

This process is known as **alert triage** - the standard SOC analyst workflow.

---

## Technical Decision

### SHA-256 for file integrity verification
MD5 and SHA-1 were deliberately avoided despite being faster. Both algorithms are vulnerable to collision attacks - an attacker could craft a malicious file that produces the same hash as the original, defeating integrity checks entirely. SHA-256 has no known collisions and is the current standard for integrity verification in security contexts.

### Rule-based detection over anomaly-based
A rule-based engine was chosen for V1 for two reasons: it is auditable - every alert can be traced back to a specific rule - and it does not require a training period. Anomaly-based detection needs historical data to establish a behavioral baseline, making it unreliable on a new system with no prior history. It is planned for V2.

### Modular architecture - Separation of Concerns
Each layer (collector, analyzer, alerter) has a single responsibility. This enables fault isolation - a failing collector does not block the others - and makes the codebase easier to extend. Adding a new detection surface only requires adding a new collector without touching existing modules.

### Checkpoint pattern over timestamp in Log Monitor
The last processed Windows Event Log record number is saved instead of a timestamp. Record numbers are sequential unique integers - direct access with no ambiguity. Timestamps are not unique: multiple events can share the same millisecond timestamp, making timestamp-based filtering unreliable and potentially causing missed or duplicated events.

### Graceful degradation in Process Monitor
Process attributes like `exe` and `username` are collected in independent try/except blocks. If reading one attribute fails due to `AccessDenied`, the process is still added to the results with that field set to `null` - rather than discarding the entire process. This maximizes data collection without crashing on protected system processes.

---

## Known Limitations

### Windows only
The system relies on `pywin32` for Windows Event Log access and on Windows-specific APIs for process and file monitoring. Detection rules are also mapped to Windows-specific attack vectors. Porting to Linux or macOS would require rewriting all four collectors.

### Baseline requires manual regeneration after Windows updates
Windows updates replace system files with newer versions, changing their SHA-256 hashes. After a significant update, the baseline must be manually regenerated with `python baseline_generator.py` to avoid persisent FILE_MODIFIED false positives on legitimate system files.

### Whitelist bypass risk - Partially mitigated in V2
The process whitelist introduces a known weakness: an attacker aware of the whitelisted process names could name their malware after a whitelisted process to evade detection. This risk has been partially mitigated in V2 through Sysmon integration - kernel-level monitoring detects anomalous behaviors like process injection (Event ID 8) and lsass.exe access (Event ID 10) regardless of process name. However, the Sysmon configuration is scoped to specific attack techniques - techniques outside this scope remain undetected.

### Static threat intelligence - Partially mitigated in V2
The Network Monitor uses a static list of known malicious IPs. New malicious IPs documented after the last manual update will not be detected. This has been partially mitigated by the Firewall Monitor - which uses behavioral detection (port scan pattern analysis) rather than static lists - but IP-based threat intelligence remains static and requires manual updates.

---

## Roadmap

### ✅ Implemented post-assessment (V2)
Following the Security Assessment Report, four recommendations were prioritized 
over the original V2 roadmap items — addressing structural coverage gaps 
identified through MITRE ATT&CK analysis.

- **EVENT_4670** — File and directory permission modification detection
- **WMI Activity Monitor** — Dedicated WMI abuse detection
- **Firewall Monitor** — Behavioral port scan detection
- **Sysmon Integration** — Kernel-level detection for process injection and credential dumping

### V2 — In progress
- **Anomaly-based detection** — ML model requiring historical data collection period before training
- **Dynamic threat intelligence** — Automated IP feed integration from sources like AbuseIPDB
- **Event-driven baselining** — Automatic baseline regeneration triggered by Windows Update processes

### V3 — Planned
- **Alert notification system** — Real-time delivery via email, Telegram, or Slack
- **Network-level monitoring expansion** — Integration with router or dedicated device for full network visibility
- **Visualization dashboard** — Lightweight web dashboard for real-time alert visualization