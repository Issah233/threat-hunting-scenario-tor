# threat-hunting-scenario-tor

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Issah233/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

I searched the DeviceFileEvents table for any files containing the string “tor” and identified activity suggesting that the user Hajia24 downloaded a Tor installer. Subsequent activity indicates that numerous Tor-related files were copied to the desktop, along with the creation of a file named tor-shopping-list.txt on the desktop. These events began at: 2026-05-21T10:48:14.2956556Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-isa"
| where InitiatingProcessAccountName == "hajia24"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-05-21T10:48:14.2956556Z)
| order by Timestamp
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="743" height="346" alt="hunt 1" src="https://github.com/user-attachments/assets/0d0d160c-eaf7-4ef9-856d-222f3652cc15" />


---

### 2. Searched the `DeviceProcessEvents` Table

I searched the DeviceProcessEvents table for any process command lines containing the string tor-browser-windows-x86_64-portable-15.0.14.exe. Based on the returned logs, at approximately 11:41 AM on May 21, 2026, the user hajia24 executed a legitimate Tor Browser installer from their Downloads folder on the device threat-hunt-isa, likely initiating the setup of a portable anonymous web-browsing environment that was not flagged as malicious by any antivirus engines. 

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-isa"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.14.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine

```

<img width="634" height="157" alt="image" src="https://github.com/user-attachments/assets/7b7736aa-10d2-4c0f-9f05-d751e633c9f0" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched the DeviceProcessEvents table for any indication that the user Hajia24 opened the tor browser and the results actually shows that the user indeed opened the browser on May 21, 2026 3:24:51 PM . There were several instances of firefox.tor as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-isa"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser-windows-x86_64-portable-15.0.14.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1232" height="361" alt="image" src="https://github.com/user-attachments/assets/3bd57121-eabd-41aa-824c-c9a8827be41f" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I searched the DeviceNetworkEvents table for indications that the Tor Browser was used to establish network connections over known Tor-related ports. The results showed that at approximately 11:47 AM on May 21, 2026, the user hajia24 successfully established a network connection from the device threat-hunt-isa using firefox.exe over remote port 9150, a port commonly associated with the Tor Browser proxy service. The connection was initiated by the process tor.exe located in the folder 
"C:\Users\Hajia24\Desktop\Tor Browser\Browser\firefox.exe". 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-isa"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemotePort, RemoteUrl, InitiatingProcessFileName

```
<img width="1258" height="368" alt="image" src="https://github.com/user-attachments/assets/b21b8094-bde0-42a5-9aa5-14c072d65ae3" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-05-21T10:48:14.2956556Z`
- **Event:** The user "Hajia24" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Hajia24\Desktop\Tor Browser\Browser\firefox.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-05-21T10:43:01.0488511Z` 
- **Event:** The user "hajia24" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.14.exe /S`
- **File Path:** `C:\Users\Hajia24\Desktop\Tor Browser\Browser\firefox.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-05-21T10:58:12.6764338Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\Hajia24\Desktop\Tor Browser\Browser\firefox.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-05-21T10:58:12.6764338Z` - Connected to `194.164.169.85` on port `443`.
  - `2026-05-21T10:58:12.6764338Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "hajia24" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-05-21T10:48:14.2956556Z`
- **Event:** The user "hajia24" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\hajia24\Desktop\tor-shopping-list.txt`

---

## Summary

On May 21, 2026, user 'hajia24' on device threat-hunt-isa downloaded, installed, and actively used the Tor Browser (version 15.0.14) within the corporate environment. The activity spanned approximately four hours, during which the user established multiple anonymous Tor circuits connecting to known Tor relay nodes, browsed via the anonymised network across at least three distinct browser sessions, silently reinstalled the software, deleted the installer (a likely anti-forensic action), and created a file on the Desktop titled "tor-shopping-list.txt" — a filename that raises concern about the intent of the anonymous browsing activity.

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lsa` by the user `hajia24`. The device was isolated, and the user's direct manager was notified.

---
