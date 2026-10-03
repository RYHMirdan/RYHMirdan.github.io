---
title: "C2 Incident Investigation"
date: 2026-09-03 20:00:00 -0400
categories: [DFIR, Incident Response]
tags: [Splunk, Sysmon, Wireshark, Volatility, C2, EZ tools, TimeSketch, Log2Timeline]
---

# 1. Case Overview

## 1.1 Case Summary

On August 30, 2024, at **22:50:27 UTC**, the Security Operations Center (SOC) detected suspicious activity originating from an employee workstation.

The user **Alice**, operating the workstation **CLIENT2**, was observed downloading a potentially malicious payload from:

```text
h22p://w1ndowsupdate[.]com:8000/update.exe.hta
```

A security alert was generated following the download, initiating an incident response investigation. The purpose of the investigation was to determine the scope and impact of the suspected compromise, reconstruct attacker activity, identify indicators of compromise (IOCs), and determine whether additional compromise or data exfiltration occurred.

### Provided Artifacts

The following forensic artifacts were provided for analysis:

- Disk triage collection from Alice's workstation
- Memory image and `pagefile.sys`
- PCAP containing captured network activity
- Windows Event Logs exported from Splunk

### Rules of Engagement

**System in Scope**

- Alice's `CLIENT2` workstation

**Investigation Timeframe**

- August 30, 2024, at 22:50:27 UTC and onward

**Relevant IPv4 Addresses**

| System | IPv4 Address |
|---|---|
| CLIENT2 | `192.168.0.104` |
| Domain Controller (DC) | `192.168.0.10` |
| Gateway / Splunk Server | `192.168.0.1` |

> The CLIENT2 workstation did not have antivirus or other security tools installed by default.

### Analysis Tools

The following tools were used throughout the investigation:

- Wireshark
- Splunk
- Velociraptor
- Volatility
- Eric Zimmerman's Tools
- Plaso / Log2Timeline
- Timesketch

---

## 1.2 Forensic Artifacts

The evidence provided for forensic analysis consisted of several sources containing disk, memory, network, and Windows event data.

| Artifact | Purpose |
|---|---|
| `Memdump.mem` | Memory image used to examine volatile artifacts and process activity |
| `Pagefile.sys` | Used to identify residual memory artifacts and potentially swapped process data |
| `Splunk_logs_export.csv` | Windows event data exported from Splunk |
| `Traffic.pcapng` | Packet capture containing network traffic from the incident timeframe |
| `Triage.7z` | Disk triage collection containing relevant endpoint forensic artifacts |

### Intended Analysis Areas

The investigation focuses on identifying and reconstructing:

- Initial infection vector
- Malicious process execution
- Persistence mechanisms
- Suspicious network communications
- Potential credential-access activity
- Lateral movement attempts
- Indicators of compromise (IOCs)
- Possible data exfiltration
- User and attacker activity timelines

### Tools Planned for Analysis

The forensic evidence will be examined using:

- Volatility 3
- Wireshark
- NetworkMiner
- Splunk
- Eric Zimmerman's Tools
- Chainsaw
- Log2Timeline / Plaso
- Timesketch


# 2. Forensic Analysis

## 2.1 Splunk — Windows Log Analysis

### 2.1.1 Event Triage and Validation

Upon receiving the security alert, the initial goal was to understand the scope and validate the alert associated with Alice's workstation. The alert provided the suspected user's name, system name, time of the event, and details of the suspicious activity.

Since the endpoint telemetry was ingested into a centralized SIEM, I focused on validating the alert, identifying the available telemetry sources, and determining the scope of suspicious activity.

### 2.1.2 Initial Visibility — Locating the Alert Event

I began by searching the `client2_v6` index for events associated with the suspicious `w1ndowsupdate[.]com` domain during the incident timeframe.

```spl id="0nux5j"
index=client2_v6 host="kali" earliest="08/30/2024:22:50:00" latest="08/30/2024:24:00:00"
| search *w1ndowsupdate.com*
```

<!-- IMAGE 1: Pasted image 20260711153350.png -->

The investigation identified two events associated with the alert.

The first was **Sysmon Event ID 22 — DNS Query**, which indicated that Alice's device resolved the suspected domain, consistent with the activity reported by the SIEM alert. The DNS result showed:

```text id="e0i0ja"
w1ndowsupdate[.]com → 3.140[.]33[.]120
```

This identified the destination IP address that Alice's workstation could subsequently communicate with.

The second event was **Sysmon Event ID 15 — File Create Stream Hash**. This event captured the creation of a named file stream, in this case the `Zone.Identifier`. Windows can attach this "Mark of the Web" metadata to downloaded files to identify their source security zone.

**Sysmon Event ID 3 — Network Connection** was also relevant to the investigation and was later used to examine network connections established by suspicious processes.

---

### 2.1.3 HTA File Presence and Download Source

**Time: 22:56:21 UTC**

<!-- IMAGE 2: Pasted image 20260711184704.png -->

The original SIEM alert reported a potentially malicious payload from:

```text id="8vebsh"
h22p://w1ndowsupdate[.]com:8000/update.exe.hta
```

Sysmon Event ID 15 captured the `update.exe.hta` file on Alice's system with the following stream:

```text id="3pnigp"
C:\Users\alice\Downloads\update.exe.hta:Zone.Identifier
```

The metadata also contained:

```text id="6h5r8p"
ZoneId=3
```

`ZoneId=3` indicates that Windows associated the downloaded resource with the Internet Zone.

This helped validate the suspicious activity reported in the original alert by confirming the presence of the HTA file on Alice's workstation and identifying it as a file originating from an external source.

---

### 2.1.4 Payload Execution and Process Chain

The next step was determining whether `update.exe.hta` was actually executed.

I searched **Sysmon Event ID 1 — Process Creation** for the HTA file:

```spl id="xl2p96"
index=client2_v6 host="kali" EventCode=1
| search *update.exe.hta*
```

<!-- IMAGE 3: Pasted image 20260712005933.png -->

#### `mshta.exe` — 22:57:54 UTC

Relevant fields included:

```text id="ikc2on"
ParentProcessGuid: {4cd32793-4aff-66d2-a100-000000001900}
ParentImage: C:\Windows\explorer.exe

Image: C:\Windows\SysWOW64\mshta.exe
ProcessGuid: {4cd32793-4e72-66d2-d901-000000001900}
```

Sysmon Event ID 1 confirmed the execution of the HTA file.

The `Image` field identified `mshta.exe` as the process created. `mshta.exe` is a Windows system utility capable of executing HTML Application (`.hta`) files. The `CommandLine` field confirmed that `update.exe.hta` was executed through `mshta.exe`.

The process was launched from Alice's Downloads directory under the `BCS\alice` user account.

The `ParentImage` was:

```text id="ywvygz"
C:\Windows\explorer.exe
```

This suggests that Alice launched:

```text id="6zv8k9"
C:\Users\alice\Downloads\update.exe.hta
```

through Windows File Explorer, causing `explorer.exe` to launch `mshta.exe`.

#### `powershell.exe` — 22:57:56 UTC

<!-- IMAGE 4: Pasted image 20260712021714.png -->

Approximately two seconds later, Sysmon Event ID 1 recorded the creation of `powershell.exe`.

```text id="s8fh09"
ParentProcessGuid: {4cd32793-4e72-66d2-d901-000000001900}
ParentImage: C:\Windows\SysWOW64\mshta.exe

Image: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
ProcessGuid: {4cd32793-4e74-66d2-da01-000000001900}
```

The `ParentImage` and `ParentProcessGuid` fields identified `mshta.exe` as the parent process, confirming that the previously executed HTA payload launched PowerShell.

The process chain was therefore:

```text id="tvj3iz"
explorer.exe → mshta.exe → powershell.exe
```

The `CommandLine` field also captured several arguments passed to PowerShell:

```powershell id="kmfgsc"
-NoP -Sta -W 1 -Enc
```

- **`-NoP` — No Profile:** Starts PowerShell without loading the user's PowerShell profile.
- **`-Sta` — Single-Threaded Apartment:** Starts PowerShell using STA threading, which can be relevant when working with COM objects.
- **`-W 1` — Window Style:** Controls the PowerShell window state and can reduce visible execution.
- **`-Enc` — Encoded Command:** Indicates that the supplied PowerShell command is Base64-encoded.

Base64 is encoding rather than encryption, but it can be used to make a command less immediately readable.

This validated that `update.exe.hta` was executed through `mshta.exe` on Alice's workstation. The HTA served as the **stager** in the C2 operation, initiating the next stage of execution through PowerShell.

---

### 2.1.5 Following PowerShell via ProcessGUID

After identifying the suspicious PowerShell process, I used its ProcessGUID to follow the activity generated by that specific process.

```text id="itss3j"
{4cd32793-4e74-66d2-da01-000000001900}
```

The following SPL query searched for events where the GUID appeared as either the process itself or the parent of another process:

```spl id="a7xjhn"
index=client2_v6 host="kali"
| search ProcessGuid="{4cd32793-4e74-66d2-da01-000000001900}"
    OR ParentProcessGuid="{4cd32793-4e74-66d2-da01-000000001900}"
| stats count by EventCode
```

<!-- IMAGE 5: Pasted image 20260715035645.png -->

The PowerShell process performed several actions, including:

- **Event ID 3** — Network connections
- **Event ID 11** — File creation
- **Event ID 13** — Registry modifications
- **Event ID 22** — DNS queries

A separate search also showed that the PowerShell process spawned three child processes through **Event ID 1**.

This gave me a way to follow the PowerShell process across multiple types of Sysmon telemetry.

---

### 2.1.6 Port 9001 Network Activity

I then focused on **Sysmon Event ID 3 — Network Connection** activity associated with the PowerShell ProcessGUID.

```spl id="u4bxfh"
index=client2_v6 host="kali"
(ProcessGuid="{4cd32793-4e74-66d2-da01-000000001900}"
OR ParentProcessGuid="{4cd32793-4e74-66d2-da01-000000001900}")
EventCode=3
| stats count by DestinationIp DestinationPort
```

<!-- IMAGE 6: Pasted image 20260715175301.png -->

The aggregated search for destination IP addresses and ports showed that PowerShell established network connections and repeatedly communicated with the same external server over port `9001`.

The destination was:

```text id="o7f18e"
3.140[.]33[.]120:9001
```

At this point, the malware had established an external connection.

Sysmon provided the network connection metadata, but there was not enough application-layer telemetry in these events to determine exactly what was being transmitted. The provided PCAP would therefore be examined later in Wireshark.

<!-- IMAGE 7: Pasted image 20260719013239.png -->

The repeated connections occurred at approximately **one-second intervals**, which was a strong indicator of potential beaconing behavior. Alice's workstation appeared to be repeatedly checking in with the suspected server.

---

### 2.1.7 Sysmon Event ID 13 — Run-Key Persistence

I next examined registry modifications associated with the PowerShell ProcessGUID.

```spl id="p5u2wm"
index=client2_v6 host="kali"
(ProcessGuid="{4cd32793-4e74-66d2-da01-000000001900}"
OR ParentProcessGuid="{4cd32793-4e74-66d2-da01-000000001900}")
| search EventCode=13
```

<!-- IMAGE 8: Pasted image 20260714192452.png -->

**Sysmon Event ID 13** captures modifications to Windows Registry values, making it useful for identifying persistence activity.

The event showed a target object under:

```text id="c9l8d3"
CurrentVersion\Run
```

Within the Run location, a value named:

```text id="9fdrfb"
Updater
```

was created or modified.

The `Image` field identified `powershell.exe` as the executable responsible for the registry modification.

The `Details` field contained:

```powershell id="1aev0n"
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x"
```

The `-c` (`-Command`) argument tells PowerShell to execute the command that follows.

Within the command:

```powershell id="qu9znc"
gp HKCU:Software\Microsoft\Windows\CurrentVersion\Debug
```

`gp` is the PowerShell alias for `Get-ItemProperty`. It retrieves the registry properties stored at the specified location.

The `.Debug` portion specifies the `Debug` value, and its contents are stored in the `$x` variable.

A second PowerShell instance then executes:

```powershell id="0r7vy5"
powershell -Win Hidden -enc $x
```

The `Run` key therefore functions as a launcher. It stores a PowerShell command that retrieves a payload hidden in a separate registry value and then executes it.

This provided evidence that the attacker had established a registry-based persistence mechanism on the workstation.

---

### 2.1.8 Second Persistence Method — Scheduled Task

Analysis of **Sysmon Event ID 1** identified a second persistence mechanism through `schtasks.exe`.

<!-- IMAGE 9: Pasted image 20260719182132.png -->

A scheduled task named:

```text id="k5yqh7"
Updater
```

was configured to execute a PowerShell command.

The observed command was:

```powershell id="0u3v64"
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))"
```

The command retrieves the `debug` registry value under:

```text id="zvnlnj"
HKLM\Software\Microsoft\Network
```

It then Base64-decodes the stored data and passes the resulting PowerShell code to `IEX` (`Invoke-Expression`) for execution.

This identified a second method of persistence in addition to the previously observed `Run` key.

---

### 2.1.9 Port 9003 Network Activity

A search correlating destination ports associated with the suspected server:

```text id="n5ly6h"
3.140[.]33[.]120
```

identified both port `9001` and port `9003`.

<!-- IMAGE 10: Pasted image 20260728143638.png -->

I isolated the network connection events associated with port `9003` and correlated events sharing the same ProcessGUID.

The relevant ProcessGUID was:

```text id="y6qecv"
{4cd32793-4f07-66d2-fc01-000000001900}
```

I then used:

```spl id="l1ylb6"
index=client2_v6 host="kali"
ProcessGuid="{4cd32793-4f07-66d2-fc01-000000001900}"
| stats count by EventCode
```

<!-- IMAGE 11: Pasted image 20260728151001.png -->

This allowed me to reconstruct other activity performed by the same PowerShell process.

#### Event ID 1 — 23:00:23.104 UTC

<!-- IMAGE 12: Pasted image 20260728160533.png -->

The `ParentCommandLine` field documented a script using `Get-ItemProperty` to read the `Update` value located under:

```text id="i6tvm1"
HKCU\Software\Microsoft\Windows Update
```

The retrieved contents were stored in the `$x` variable.

This indicated that a Base64-encoded PowerShell payload had been stored in the registry. A secondary PowerShell process then executed the encoded payload stored in `$x`.

The activity also showed a brief pause before the following command was executed:

```powershell id="5s6ymj"
cleanmgr.exe /autoclean /d C:
```

#### ProcessGUID Correlation and Persistence

Using the `ParentProcessGuid`, I traced execution back to determine how the later PowerShell process had been launched.

The original process chain had been:

```text id="56a1pr"
explorer.exe → mshta.exe → powershell.exe
```

However, the later PowerShell processes associated with the `{fc01...}` and `{fa01...}` GUIDs were not launched by `mshta.exe`. Their parent was `svchost.exe`.

This suggested that the payload had moved beyond its initial HTA execution and was now being executed through an established persistence mechanism.

---

### 2.1.10 PowerShell Script Block Analysis — Event ID 4104

I then examined PowerShell Script Block telemetry to gain more visibility into the PowerShell code associated with the persistence activity.

```spl id="9a5b8m"
index=client2_v6 host="kali" *SQBmACgAJABQAFMA* EventCode!=600
| reverse
| table UtcTime EventCode Message
```

<!-- IMAGE 13: Pasted image 20260731150340.png -->

The script contained:

```powershell id="v1kcr5"
$RegPath = 'HKCU:Software\Microsoft\Windows\CurrentVersion\Debug'
```

This created or referenced the registry location used to store the Base64 payload.

The script then used:

```powershell id="0l4wbe"
Set-ItemProperty -Force -Path $path -Name $name -Value SQBmACgAJABQAFMA...
```

to write the Base64-encoded payload into the registry.

Another `Set-ItemProperty` command created the `Updater` value under the Windows Run key:

```powershell id="ebum95"
Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\
-Name Updater
-Value '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion\Debug).Debug); powershell -Win Hidden -enc $x"'
```

Every time the Run-key entry is triggered, PowerShell retrieves the `Debug` registry value and stores its contents in `$x`.

A second hidden PowerShell process then executes the encoded payload held in `$x`.

The Script Block telemetry also contained the message:

```text id="2pr0a8"
Registry persistence established using listener http_9003 stored in HKCU:Software\Microsoft\Windows\CurrentVersion\Debug
```

This further connected the registry persistence activity with the previously observed port `9003` communication.

<!-- IMAGE 14: Pasted image 20260803024332.png -->

---

### 2.1.11 Splunk Analysis Summary

The Splunk analysis allowed me to validate the original alert and follow the activity from the initial HTA execution into later PowerShell and persistence activity.

The main findings were:

- `w1ndowsupdate[.]com` resolved to `3.140[.]33[.]120`.
- `update.exe.hta` was present in Alice's Downloads directory with Internet-origin metadata.
- `explorer.exe` launched `mshta.exe`, which executed the HTA payload.
- `mshta.exe` launched an encoded PowerShell command.
- ProcessGUID correlation linked the PowerShell process with network connections, registry modifications, file activity, DNS queries, and additional process creation.
- PowerShell communicated with `3.140[.]33[.]120` over port `9001`.
- Repeated connections occurred at approximately one-second intervals.
- A registry Run key named `Updater` was used for persistence.
- A scheduled task named `Updater` provided an additional persistence method.
- Additional PowerShell activity was associated with port `9003`.
- PowerShell Script Block telemetry showed the encoded payload being stored in the registry and the `Updater` Run-key entry being configured to retrieve and execute it.

The Splunk evidence provided an endpoint view of the compromise. The next phase of the investigation focuses on the provided PCAP to examine the external network communication in greater detail.