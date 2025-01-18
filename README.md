<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/ryanbynoe/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the `DeviceFileEvents` table for ANY file that had the string `tor` in it and discovered the user `ryan` downloaded a `tor installer` resulting in ample `tor-related files` being downloaded to the `desktop`. These events began at:

**Query used to locate events: 2025-01-18T13:45:29.0368279Z**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "ryan-lab-threat"
| where InitiatingProcessAccountName == "ryan"
| where Timestamp >= datetime(2025-01-18T13:45:29.0368279Z)
| order by Timestamp desc
| project Timestamp, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1212" alt="image" src="/assets/torinstall.png">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any `ProcessCommandLine` that contain the string `tor-browser-windows-x86_64-portable-14.0.4.exe`. Based on the logs returned [`01/18/25 0847`] `Silent Tor Browser` installation detected on `ryan's threat lab machine`, executed from `Downloads` with `hidden install parameter`.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ryan-lab-threat"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="/assets/torinstall2.png">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that user `ryan` opened the `tor browser`. There was evidence that they did open it at `2025-01-18T13:48:06.7270137Z`. There were several other instances of `firefox.exe` (`tor`) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ryan-lab-threat"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="image" src="/assets/processcreation.png">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any indication the `tor browser` was used to establish a connection using any of the known `tor ports`.
[`01/18/25 0848`] `2025-01-18T13:48:26.0541486Z` `Tor` process successfully established connection to `Austrian IP 193.30.123.132` over port `9001` from `ryan's threat lab machine`, suggesting initial relay connection.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ryan-lab-threat"
| where InitiatingProcessAccountName  != "system"
| where RemotePort in ("9001", "9030", "9040", "9051", "9150")
| project Timestamp, InitiatingProcessAccountName, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName

```
<img width="1212" alt="image" src="/assets/knowntorports.png">

---

### 5. Searched the `DeviceFileEvents` Table for Suspicious Tor Files

Searched the `DeviceFileEvents` for any suspicious files containing `tor-shopping` and found a file `tor-shopping-list.txt` created at `2025-01-18T14:48:05.1270045Z`


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ryan-lab-threat"
| where FileName contains "tor-shopping"

```
<img width="1212" alt="image" src="/assets/shoppinglist.png">

---

## Chronological Event Timeline 

### 1. Tor Browser Download
- [08:47:30 AM] User `ryan` downloaded `tor-browser-windows-x86_64-portable-14.0.4.exe` from the Downloads folder.
- [08:47:47 AM] Several Tor-related files, such as `tor.exe` and `Torbutton.txt`, were created in `C:\Users\ryan\Desktop\Tor Browser\Browser\TorBrowser\Data`.
- [08:47:48 AM] A `Tor Browser.lnk` shortcut was created on the Desktop.

### 2. Silent Installation of Tor Browser
- [08:47:30 AM] Tor Browser installation was initiated from the Downloads folder using a silent install parameter, indicating an attempt to install without user prompts.

### 3. Execution of Tor Browser
- [08:48:06 AM] User `ryan` launched `tor.exe`, confirming the execution of the Tor Browser.
- [08:52:01 AM - 08:52:36 AM] Multiple instances of `firefox.exe` (Tor Browser) were spawned, showing activity within the browser.

### 4. Establishment of Tor Network Connection
- [08:48:26 AM] `tor.exe` successfully connected to a Tor relay node at `193.30.123.132` over port 9001.
- [08:48:34 AM] An internal localhost (`127.0.0.1`) connection was established on port 9150, which is commonly used for routing traffic through Tor.

### 5. Suspicious File Creation
- [09:48:05 AM] A file named `tor-shopping-list.txt` was created, indicating potential activity conducted over the Tor network.


---

## Summary

On `January 18, 2025`, a concerning sequence of events was detected on the `ryan-lab-threat` workstation. At `8:47 AM`, user `ryan` downloaded and executed a silent installation of the `Tor Browser`, deliberately bypassing normal user prompts. Within minutes, multiple browser processes were spawned, followed by a rapid connection to an Austrian Tor relay node (`193.30.123.132:9001`), establishing anonymous network connectivity. The speed and methodical nature of these actions suggest pre-planned execution. Most notably, approximately one hour after establishing the Tor connection, a file named `tor-shopping-list.txt` was created, raising significant concerns about potential darknet marketplace activity. The combination of `silent installation`, `immediate Tor network connectivity`, and the subsequent creation of a suspicious shopping list file warrants immediate security investigation.

---

## Response Taken

TOR usage was confirmed on the endpoint `ryan-lab-threat` by the user `ryan`. The device was isolated, and the user's direct manager was notified.

---
