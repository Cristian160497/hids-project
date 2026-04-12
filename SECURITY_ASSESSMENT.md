# Security Assessment Report
## Custom Python HIDS - Threat Coverage Analysis

**Date:** April 2026
**Author:** Cristian
**Target:** Custom Python-based Host Intrusion Detection System (HIDS)
**Framework:** MITRE ATT&CK for Enterprise - Windows Systems

---

## Executive Summary

I analyzed the previously created detection system, comparing it with techniques documented in the MITRE ATT&CK framework for Windows systems, and identified several coverage gaps requiring remediation. Of the five techniques analyzed, three were not detected, two were partially detected, and none were fully detected by the current ruleset. An update to the underlying detection logic is therefore necessary, starting with the integration of Sysmon (System Monitor) to extend visibility into attack surfaces currently outside the system's detection scope.

---

## Scope

### Included
- The custom Python-based HIDS previously developed, including all four collectors: File Integrity Monitor, Process Monitor, Network Monitor, and Log Monitor.
- Five attack techniques selected from the MITRE ATT&CK framework for Windows Systems: T1047, T1556, T1222, T1046, T1674.
- Theoretical analysis of each techniques against the four detection criteria defined by the system architecture.

### Excluded and Limitations

**Limited technique coverage:** only five techniques were selected from the MITRE ATT&CK framework, wich documents hundreds of techniques and sub-techniques. The remaining techniques were not evaluated - coverage gaps may exist beyond those identified in this report.

**Theoretical assessment only:** this evaluation was conducted through logical analysis of the system's detection rules against known behaviors. No real attacks were executed against the system. Practical validation - executing actual attack techniques in a controlled environment and observing system behavior - is planned as a follow-up activity.

**Self-assessment:** this report was produced by the same individual who designed and built the system. An indipendent third-party assessment may identity additional gaps not covered here.

---

## Methodology

### Technique Selection
Attack techniques were selected from the MITRE ATT&CK framework for Windows systems, cross-referencing documented behaviors with the detection logic already implemented in the system. Selection prioritized techniques relevant to the attack surfaces monitored by the four collectors - file integrity, process execution, network connections, and Windows Event Log.

### Detection Criteria
Each technique was evaluated against four detection criteria, one per collector:

| Criterion | Collector | Detection condition |
|---|---|---|
| C1 | File Integrity Monitor | SHA-256 hash mismatch against baseline |
| C2 | Process Monitor | Process not in the withelist or running from unexpected path |
| C3 | Network Monitor | Suspicious process connection, port, or IP address |
| C4 | Log Monitor | Event ID matching monitored events |

A technique is classified as:
- **Detected** - if at least one criterion is satisfied in all attack scenarios
- **Partially detected** - if criteria are satisfied only in specific scenarios
- **Not detected** - if no criterion is satisfied

### Analysis Process
For each technique, the following elements were analyzed:

1. **Attack behavior** - what the attacker does concretely at the system level
2. **Affected files** - which files are modified, if any
3. **Process execution** - which processes are involved and from which paths
4. **Network activity** - whther the technique generates network connections
5. **Event Log activity** - which Windows Event IDs are generated, if any

Each element was then compared against the detection surface covered by the system to determine coverage gaps and potential improvements.

---

## Findings

### Coverage Summary

| Technique | ID | Result | Modules |
|---|---|---|---|
| Windows Management Instrumentation | T1047 | ❌ Not Detected | - |
| Modify Authentication Process | T1556 | ⚠️ Partially Detected | C3, C4 |
|  File and Directory Permissions Modification | T1222 | ❌ Not Detected | - |
| Network Service Discovery | T1046 | ❌ Not Detected | C4 partial |
| Input Injection | T1674 | ⚠️ Partially Detected | C4 partial |

---

### T1047 - Windows Management Instrumentation
**Result: Not Detected**

Adversaries abuse WMI to execute malicious commands and payloads without installing new software. The primary process involved is `WmiPrvSE.exe` - the legitimate WMI provider host.

| Criterion | Result | Reason |
|---|---|---|
| C1 - File Integrity | ❌ | WMI abuse does not modify files on disk |
| C2 - Process Monitor | ❌ | `WmiPrvSE.exe` is whitelisted and runs from a legitimate path |
| C3 - Network Monitor | ⚠️ |  Only detected if WMI establishes connections to suspicious ports or IPs |
| C4 - Log Monitor | ❌ | EVENT_4688 is filtered - `WmiPrvSE.exe` is not in `SUSPICIOUS_PARENT_PROCESSES` | 

**Root cause:** `WmiPrvSE.exe` is a legitimate Windows Process present in the whitelist. No dedicated WMI activity log is monitored.

---

### T1556 - Modify Authentication Process
**Result: Partially Detcted**

Adversaries modify authentication mechanisms to access credentials or enable unauthorized access. The primary target is `lsass.exe` - the Local Security Authority Subsystem Service managing authentication and credentials.

The critical attack variant is **process injection** - injecting malicious code directly into `lsass.exe` memory without modifying the file on disk. The SHA-256 hash remains unchanged, rendering the File Integrity Monitor blind.

| Criterion | Result | Reason |
|---|---|---|
| C1 - File Integrity | ❌ | Process injection does not modify the file on disk - hash unchanged |
| C2 - Process Monitor | ⚠️ | Detected only if `lsass.exe` runs from an unexpected path |
| C3 - Netwokr Monitor | ✅ | Detected - `lsass.exe` is in `SUSPICIOUS_PROCESSES`, any outbound connection generates a CRITICAL alert |
| C4 - Log Monitor | ⚠️ | EVENT_4625 detects failed authentications but not the process modification itself |

**Root cause:** the File Integrity Monitor cannot detect in-memory attacks.
Process injection leaves no trace on disk.

---

### T1222 - File and Directory Permissions Modification
**Result: Not Detected**

Adversaries modify ACL permissions on files or directories to access protected resources or evade access controls. The most common tool is `icacls.exe` - a legitimate Windows executable running from `C:\Windows\System32\`.

| Criterion | Result | Reason |
|---|---|---|
| C1 - File Integrity | ❌ | ACL permissions are NTFS metadata - they do not affect SHA-256 hash |
| C2 - Process Monitor | ❌ | `icacls.exe` runs from a legitimate path and does not meet alert conditions |
| C3 - Netwokr Monitor | ❌ | Permission modification is a local operation - no network connections generated |
| C4 - Log Monitor | ❌ | EVENT_4670 (permission modification) is not in the monitored Event ID list |

**Root cause:** SHA-256 hashing covers file content only - not filesystem metadata. EVENT_4670 is not monitored.

---

### T1046 - Network Service Discovery
**Result: Not Detected**

Adversaries perform port scans to enumerate exposed services before selecting an attack vector. This technique represents the **reconnaissance** phase - the first step of most attacks.

| Criterion | Result | Reason |
|---|---|---|
| C1 - File Integrity | ❌ | Port scanning does not modify files |
| C2 - Process Monitor | ❌ | No processes are created on the target system |
| C3 - Netwokr Monitor | ❌ | The Network Monitor covers outbound traffic only - inbound port scans are not visible |
| C4 - Log Monitor | ⚠️ | Aggressive scans attempting authentication may generate EVENT_4625 |

**Root cause:** the Network uses `psutil.net_connections()` which skips connections without a remote address - covering only established outbound connections. Inbound scan traffic is not captured.

---

### T1674 - Input Injection
**Result: Partially Detected**

Adversaries simulate keyboard and mouse input via Windows APIs(`SendIpunt`, `keybd_event`) to execute actions on behalf of the user. From the operating system perspective, simulated input is indistinguishable from real user input.

| Criterion | Result | Reason |
|---|---|---|
| C1 - File Integrity | ❌ | Input injection does not modify files on disk |
| C2 - Process Monitor | ❌ | The process calling `SendIpunt` runs from a legitimate path |
| C3 - Netwokr Monitor | ❌ | Input injection is a local operation - no network connections generated |
| C4 - Log Monitor | ⚠️ | EVENT_4663 detects access to protected objects only in specific scenarios - `SendIput` does not natively generate a dedicated Event ID |

**Root cause:** `SendIpunt` and `keybd_event` are legitimate Windows APIs with no native logging in the windows Security Event Log. Detection requires Sysmon or equivalent kernel-level monitoring.

## Recommendations

The following recommendations are prioritized based on the impact/effort ratio - high-impact, low-effort improvements are addressed first.

---

### REC-01 - Add EVENT_4670 to Log Monitor
**Priority: High | Effort: Low | Addresses: T1222**

Add Windoes Event ID 4670 (permissions on an object were changed) to the `MONITORED_EVENTS` dictionary in `collector/log_monitor.py`.

```python
4670: {"descritpion": "Object permissions modified", "severity": "HIGH", "filter": None},
```

This single-line change enables detection of file and directory permission modifications - a technique currently completely outside the system's detection scope. The high severity assignment reflects the risk of an attacker gaining access to protected resources by modifying ACL permissions on critical files.

---

### REC-02 - Integrate WMI Activity Event Log
**Priority: High | Effort: Medium | Addresses: T1047**

Extend `collector/log_monitor.py` to read the `Microsoft-Windows-WMI-Activity/Operational` Event Log in addition to the existing Security Event Log. This dedicated log captures WMI-specific operations with higher precision than EVENT_4688 filtered by parent process.

```python
hand = win32ectlog.OpenEventLog(None, "Microsoft-Windows-WMI-Activity/Operational")
```
This eliminates the primary coverage gap for T1047 without requiring external tools or architectural changes.

---

### REC-03 - Add Firewall Monitor Collector
**Priority: High | Effort: Medium | Addresses: T1046**

Implement a new collector `collector/firewall_monitor.py` that reads the Windows Firewall log file:
`C:\Windows\System32\LogFiles\Firewall\pfirewall.log`

The collector should detect port scanning patterns - multiple inbound connection attempts toward different ports within a short time interval - and generate alerts during the reconnaissance phase, before an attack is executed. This is strategically important: detecting reconnaissance gives the defender time to respond before the actual attack begins.

---

### REC-04 - Integrate Sysmon
**Priority: Medium | Effort: High | Addresses: T1556, T1674**

Install and configure **Microsoft Sysmon** (System Monitor) from the Sysinternals suite. Sysmon provides kernel-level visibility into events that the Windows Security Event Log does not capture natively:

- **Event ID 8** - CreateRemote Thread -> detects process injection (T1556)
- **Event ID 1** - Process creation with full command line and hash
- **Event ID 3** - Network connection per process 
- **Event ID 10** - Process access -> detects `lsass.exe` access attempts

Extend `collector/log_monitor.py` to read the Sysmon Event Log (`Microsoft-Windows-Sysmon/Operational`) as an additional data source - maintaining the existing architecture without refactoring.

This recommendations is assigned medium priority due to the higher implementation effort - Sysmon requires installation, XML-based configuration, and integration testing - despite addressing the most technically complex coverage gaps.

## Conclusion

This assessment demonstrates that no detection system is immune to evolution in attack techniques. Of the five MITRE ATT&CK techniques evaluated, three were not detected and two were noly partially detected - confirming that the current ruleset, while architecturally sound, requires continuous updates to maintain effective coverage. 

The system's underlying architecture - modular collectors, rule-based detection mapped to MITRE ATT&CK, and fault isolation - provides a solid foundation for improvement. However, the static nature of its detection rules represents the primary limitation: whitelists, monitored Event IDs, and network rules must be actively maintained to remain effective against an evolving threat landscape.

The immediate next steps are the four recommendations outlined in this report, prioritied by impact and implementation effort:

1. **REC-01** - Add EVENT_4670 to the Log Monitor *(Low effort, immediate impact)*
2. **REC-02** - Integrate WMI Activitu Event Log *(medium effort, high impact)*
3. **REC-03** - Add Firewall Monitor Collector *(medium effort, strategic value)*
4. **REC-04** - Integrate Sysmon *(high effort, closes most complex gaps)*

This assessment will be used as the technical roadmap for V2 development - each recommendation translating directly into an implementation task.

---
*Assessment conducted by Cristian - April 2026*
*Target system: Custom Python HIDS for Windows*
*Framework: MITRE ATT&CK for Enterprise*