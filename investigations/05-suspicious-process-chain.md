# Investigation 05: Suspicious Process Chain (Shell Spawning Shell) (T1059)

**Analyst:** Mahir Mahmood
**Host:** DESKTOP-H1NTMT3
**Data sources:** Sysmon process creation (Event ID 1), via Splunk
**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)
**Verdict:** True positive (suspicious technique)
**Severity:** Medium to High

## Executive summary
A chain of processes on DESKTOP-H1NTMT3 showed PowerShell launching cmd.exe, which launched PowerShell again, which then launched another application. No single process here is unusual on its own, but the way they spawned each other is the kind of lineage that does not happen in normal use and is a common shape for malware being delivered and run. The point of this investigation is following the parent-child relationships to spot a process tree that should not exist.

## How it came in
I was looking at Sysmon process-creation events (Event ID 1). A real machine generates a lot of these from normal Windows background activity, so the first job was filtering down to the processes I cared about and cutting the system noise:

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*powershell.exe*" OR Image="*notepad.exe*" OR Image="*cmd.exe*") NOT CommandLine="*splunk*" NOT ParentImage="*svchost.exe*"
| table _time, User, ParentImage, Image, CommandLine
| sort _time
```

That left a short list where the chain was clear.

## What I found
Three linked events at 22:01:38 to 22:01:39, all under the analyst account, formed a clear chain (the ParentImage column is what ties each step to the one before it):

- **22:01:38.167:** powershell.exe launched **cmd.exe**, running `cmd.exe /c "powershell.exe -Command Start-Process notepad.exe"`
- **22:01:38.188:** that **cmd.exe** launched **powershell.exe** (ParentImage = cmd.exe)
- **22:01:39.573:** that **powershell.exe** launched **notepad.exe** (ParentImage = powershell.exe)

So the full lineage was: powershell, then cmd, then powershell, then notepad.

The reason this matters is the chain itself, not any single process. Command interpreters launching other command interpreters, and then launching an application, is the pattern you see when something is being run through layers of scripting rather than a user simply opening a program. The classic real-world version of this is a document (for example winword.exe) spawning powershell.exe. A document has no legitimate reason to launch a shell, so that exact parent-child relationship is treated as a high-severity sign of malware delivered through an attachment. What I simulated here is the same idea: you trace the ParentImage back up the tree to find a process ancestry that does not belong.

This is process ancestry analysis, and it is one of the most useful triage skills because it catches things where each individual step looks harmless and only the relationship between them gives it away.

## Timeline
| Time (14/06/2026) | Event | Detail |
|-------------------|-------|--------|
| 22:01:38.167 | cmd.exe started | parent powershell.exe, command launches more PowerShell |
| 22:01:38.188 | powershell.exe started | parent cmd.exe |
| 22:01:39.573 | notepad.exe started | parent powershell.exe |

## Assessment
- **Verdict:** True positive for a suspicious chain. The shell-spawning-shell-spawning-app lineage matches the use of scripting interpreters to run code (T1059).
- **Severity:** Medium to High. In this lab the end result is just Notepad opening, but the same chain shape is exactly how malicious code is commonly delivered and run, so in production it would warrant a proper look at what the final process actually did.
- **Confidence:** High on the chain being unusual. The judgement call in a real case is what sits at the top of the tree (what originally launched the first shell) and what the final process did.

## Recommended next steps
- **Trace the top of the tree:** find what launched the very first process in the chain. If the original parent is something like a browser, email client or Office application, that points to how the host was reached and raises the severity.
- **Check what the final process did:** look at Sysmon network (Event ID 3) and file creation (Event ID 11) events for the processes in the chain, in case the real payload reached out or dropped a file.
- **Contain if confirmed malicious in production:** isolate the host and review the account's activity.
- **Improve the detection:** alert on suspicious parent-child relationships rather than single processes. The highest-value version is flagging when an Office application or other non-shell program spawns a command interpreter. A starting point in Splunk:

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe*"
| search ParentImage="*winword.exe*" OR ParentImage="*excel.exe*" OR ParentImage="*outlook.exe*" OR ParentImage="*cmd.exe*"
| table _time, User, ParentImage, Image, CommandLine
```

Detections like this work on the relationship between processes, which is harder for an attacker to avoid than any single command string.

## Lab note
This was generated and investigated in a controlled home lab. I ran a command that deliberately chained cmd and PowerShell together to open Notepad on my own Windows VM, to produce a clear process tree to investigate in Splunk. The detection and analysis are my own.
