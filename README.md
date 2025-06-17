# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Jeremiah-Rojas/Threat-Hunting/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any tor related files or activity and found what appears to be the installer on the desktop of the suspect computer and many other tor-related files. 
**This was the query used to search the event:**

```kql
DeviceFileEvents  
| where DeviceName == "rojas-mde"  
| where FileName contains "tor"  
| where Timestamp >= datetime(Jun 16, 2025 8:34:20 AM)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/7ad2e754-617d-4933-9f20-10a5fed6742d">


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `ProcessProcessEvents` table for any `ProcessCommandLine` that contained the installer string `tor-browser-windows-x86_64-portable-14.5.3.exe` and it was found that the user download Tor browser using the command `tor-browser-windows-x86_64-portable-14.5.3.exe /S` to download it without prompts.
**This was the query used to search the event:**

```kql

DeviceProcessEvents  
| where DeviceName == "rojas-mde"  
| where ProcessCommandLine contains "tor-browser"
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` to determine if the user actually opened tor browser. It was verified that the user opened it at `Jun 16, 2025 8:54:50 AM`.
**This was the query used to search the event:**

```kql
DeviceProcessEvents  
| where DeviceName == "rojs-mde"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ActionType, ProcessCommandLine 
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` for any indication that the tor browser was used to establish a connection using any of the known ports. At `Jun 16, 2025 8:50:12 AM`, the user connected to the remote IP address `77.174.62.158` on port `9001`.
**This was the query used to search the event:**

```kql
DeviceNetworkEvents  
| where DeviceName == "rojs-mde"  
| where InitiatingProcessAccountName != "system"  
| where RemotePort in ("9001", "9030", "9050", "9051", "9150")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Summary

The user `thanos` on the `rojas-mde` workstation initiated and completed the installation of tor browser. They established connections within the tor network creating various files on their desktop. Due to the nature of tor browser, it was most likely used to browse anonymously and/or view illicit or illegal content.

---

## Response Taken

TOR usage was confirmed on endpoint `rojas-mde` by the user `thanos`. The device was isolated and the user's direct manager was notified.

---
