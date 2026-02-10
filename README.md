# Threat Hunt: Internal Network Degradation and PowerShell-Based Port Scanning

## Context
The server team reported significant network performance degradation affecting several legacy devices within the `10.0.0.0/16` internal network. After ruling out external DDoS activity, the security team suspected that the issue might be caused by internally generated traffic. The environment allows unrestricted east-west traffic, and PowerShell usage is not restricted, increasing the risk of internal reconnaissance or abuse.

---

## Goal
Determine whether internal network degradation is being caused by unauthorized or suspicious internal activity such as excessive internal connections, lateral movement, or network reconnaissance originating from within the `10.0.0.0/16` address space.

---

## Hypothesis
Given the lack of internal network restrictions and unrestricted PowerShell usage, it is possible that an internal host is generating excessive traffic by performing actions such as port scanning or service enumeration against other internal hosts, contributing to network performance issues.

---

## Environment
- Security Platform: Microsoft Defender for Endpoint  
- Network Range: `10.0.0.0/16`  
- Affected Host: `sa-mde-vm`  
- Suspected IP Address: `10.0.0.123`  
- Telemetry Sources:
  - `DeviceNetworkEvents`
  - `DeviceProcessEvents`

---

## Investigation

### Identify Abnormal Internal Network Activity
The hunt began by identifying hosts generating a high volume of failed internal network connections.

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount
```

<img width="632" height="130" alt="Screenshot 2026-02-10 at 1 54 46 PM" src="https://github.com/user-attachments/assets/dafdceff-be28-4509-af1c-88c3370347b5" />

This query revealed that the host sa-mde-vm was responsible for a disproportionately high number of failed internal connection attempts targeting multiple internal hosts.

### Confirmation of Reconnaissance Activity
To determine whether the behavior was consistent with reconnaissance, failed connection events originating from the suspected IP were reviewed chronologically.

```kql
let IPInQuestion = "10.0.0.123";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

The destination ports increased sequentially across multiple internal hosts, strongly indicating automated internal port scanning behavior rather than normal application traffic.

### Process Execution Correlation
To identify the root cause of the network activity, process execution events were reviewed around the time the scanning behavior began.

```kql
let VMName = "sa-mde-vm";
let specificTime = datetime(2026-02-10T04:56:03.7018164Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
<img width="646" height="151" alt="Screenshot 2026-02-10 at 1 59 50 PM" src="https://github.com/user-attachments/assets/bf082777-9fae-4d40-9356-b6edfd975afa" />

This analysis revealed the execution of a PowerShell script named portscan.ps1 shortly before the observed spike in failed connection attempts.

### Host Validation

A manual review of the affected system confirmed:
	- The portscan.ps1 script was explicitly designed to conduct internal port scanning
	- The script was executed using the SA (privileged) account
	- The activity was not authorized, documented, or part of any approved administrative task

<img width="646" height="215" alt="Screenshot 2026-02-10 at 2 01 24 PM" src="https://github.com/user-attachments/assets/53eadad0-8c45-4efc-b999-2b532e6ec75d" />

### MITRE ATT&CK Mapping (TTPs)
Tactic: Discovery
Technique: T1046 – Network Service Discovery
Procedure: Automated internal port scanning across multiple hosts using PowerShell

Tactic: Execution
Technique: T1059.001 – Command and Scripting Interpreter: PowerShell
Procedure: Execution of a custom PowerShell script (portscan.ps1)

Tactic: Privilege Escalation / Defense Evasion
Technique: T1078 – Valid Accounts
Procedure: Unauthorized use of a privileged service account to perform reconnaissance

## Response Actions
	- Immediately isolated the affected device from the network
	- Conducted a full malware scan (no malware detected)
	- Maintained isolation due to confirmed unauthorized reconnaissance behavior
	- Opened a ticket for full device reimage and rebuild

  
## Conclusion
This threat hunt confirmed that internal network performance degradation was caused by unauthorized PowerShell-based port scanning originating from a privileged account within the internal network. While no malware was detected, the activity aligned with known adversary discovery techniques and represented a significant security risk. Full containment and remediation were executed to prevent further internal reconnaissance or potential lateral movement.

