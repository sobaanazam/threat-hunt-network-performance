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



