# Investigation 04: Suspicious Service Installed for Persistence (T1543.003)

**Analyst:** Mahir Mahmood
**Host:** DESKTOP-H1NTMT3
**Data sources:** Windows System event log (Splunk)
**MITRE ATT&CK:** T1543.003 (Create or Modify System Process: Windows Service)
**Verdict:** True positive
**Severity:** High

## Executive summary
A new Windows service called "EvilSvc" was installed on DESKTOP-H1NTMT3, set to start automatically, with its binary path pointing at a cmd.exe command rather than a normal program. Installing a service that runs a command interpreter and auto-starts is a common persistence technique, it gives an attacker something that runs again every time the machine reboots. The mismatch between what a real service looks like and what this one points at is the giveaway.

## How it came in
I searched the Windows System log for service installation events, which are Event ID 7045:

```
index=main source="WinEventLog:System" EventCode=7045
| table _time, Service_Name, Service_File_Name, Service_Type, Service_Start_Type
| sort _time
```

That returned a single new service, and the details were enough on their own to call it suspicious.

## What I found
At 21:57:36 a service was installed with these properties:

- **Service name:** EvilSvc
- **Binary path:** cmd.exe /c echo persistence
- **Start type:** auto start
- **Service type:** user mode service

The binary path is the part that stands out. A legitimate service almost always points at a proper executable (a signed .exe or .dll in a sensible location like Program Files or System32). This one runs cmd.exe with a command instead. Pointing a service at cmd.exe or powershell.exe is a well-known way to get an arbitrary command or script to run as a service, which is not something normal software does.

On top of that, the service is set to **auto start**, so it would run on every boot. That is the persistence angle: even if an attacker's other access is cleaned up, an auto-starting service quietly brings their code back every time the machine restarts. Services are attractive to attackers for exactly this reason, they start automatically, often run with high privilege, and survive reboots.

The name "EvilSvc" makes it obvious in a lab, but in a real case you would be alerting on the behaviour, a new service whose binary path is a command interpreter or sits in an odd location, not on the name.

## Timeline
| Time (14/06/2026) | Event | Detail |
|-------------------|-------|--------|
| 21:57:36 | service installed (7045) | EvilSvc, binary path "cmd.exe /c echo persistence", auto start |

## Assessment
- **Verdict:** True positive. A new auto-start service running cmd.exe matches service-based persistence (T1543.003).
- **Severity:** High. Service persistence means an attacker can survive reboots and potentially run with high privilege, so it needs removing and investigating.
- **Confidence:** High. A real service does not normally point at cmd.exe, so this is not something you would expect from legitimate software.

## Recommended next steps
- **Contain:** stop and delete the EvilSvc service, and confirm it is gone from the service list so it cannot start on the next reboot.
- **Find the root cause:** work out what installed the service and under what account. Installing a service usually requires admin rights, so this is typically a follow-on action after an attacker already has elevated access. Tie it back to any earlier suspicious activity on the host.
- **Check scope:** look for other recently installed services with command-interpreter binary paths or binaries in temp or user folders, on this host and others.
- **Escalate:** persistence should go to incident response.
- **Improve the detection:** alert on Event ID 7045 where the binary path contains cmd.exe or powershell.exe, or where the path is somewhere unusual. A starting point in Splunk:

```
index=main source="WinEventLog:System" EventCode=7045
| search Service_File_Name="*cmd.exe*" OR Service_File_Name="*powershell*" OR Service_File_Name="*\\Temp\\*" OR Service_File_Name="*\\Users\\*"
| table _time, Service_Name, Service_File_Name, Service_Start_Type
```

This focuses on the services most likely to be persistence while staying quiet on normal vendor services installing into Program Files.

## Lab note
This was generated and investigated in a controlled home lab. I created the EvilSvc service myself on my own Windows VM to produce the log, then investigated it in Splunk. The service runs a harmless echo command. The detection and analysis are my own.
