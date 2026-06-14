# Investigation 02: Encoded PowerShell Command Execution (T1059.001)

**Analyst:** Mahir Mahmood
**Host:** DESKTOP-H1NTMT3
**Data sources:** Sysmon process creation (Event ID 1), via Splunk
**MITRE ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell)
**Verdict:** True positive (malicious technique)
**Severity:** High

## Executive summary
A PowerShell process was launched on DESKTOP-H1NTMT3 using an encoded command, started by cmd.exe. The command was base64 encoded and, once decoded, was deliberately obfuscated to hide what it did. Encoding and obfuscating commands like this is a common way for attackers to run code without it being obvious in the logs, so this is the kind of activity that should be treated as malicious until proven otherwise. I decoded the payload to confirm what it actually ran.

## How it came in
The starting point was looking for PowerShell launches in the Sysmon process-creation logs. The first pass was noisy because Splunk runs its own PowerShell processes constantly in the background, so the real first step was filtering those out:

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine="*powershell*" NOT CommandLine="*splunk*"
| table _time, User, ParentImage, Image, CommandLine
| sort - _time
```

Filtering out the Splunk noise left a small number of real PowerShell launches, and two of them stood out immediately.

## What I found
At 21:42:37 there were two related events:

- **cmd.exe** ran `cmd.exe /c powershell.exe -e <base64>` (parent process)
- **powershell.exe** then ran with `powershell.exe -e <base64>` (child process)

So the chain was cmd.exe spawning an encoded PowerShell command, under the analyst account on DESKTOP-H1NTMT3.

Two things made this suspicious straight away:
- The **-e flag** is shorthand for EncodedCommand, meaning the actual instructions were base64 encoded rather than written in plain text. Legitimate software occasionally does this, but it is also a classic way for attackers to hide what a command does.
- The command line was a long blob of base64, which on its own tells you nothing, which is the whole point of encoding it.

To find out what it really did, I decoded the base64 (PowerShell uses Unicode for encoded commands):

```
$enc = "JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYA...AA=="
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($enc))
```

The decoded command was:

```
& (gcm ('ie{0}' -f 'x')) ("Wr"+"it"+"e-H"+"ost 'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+"ell!'")
```

This is harmless in itself (it just prints "Hello, from PowerShell!"), but the way it is written is the interesting part. It uses two layers of hiding:

- `'ie{0}' -f 'x'` builds the string "iex" without ever writing it directly. "iex" is Invoke-Expression, which runs whatever text it is given.
- `gcm` (Get-Command) is used to resolve that into the IEX command, again avoiding the literal word.
- The actual instruction `Write-Host 'Hello, from PowerShell!'` is chopped into fragments and glued back together, so a simple search for "Write-Host" or "iex" would not match it.

In a real incident the harmless message could just as easily be a download-and-run or a credential-dumping command. The encoding and the string tricks are the red flags, not the specific payload.

## Timeline
| Time (14/06/2026) | Event | Detail |
|-------------------|-------|--------|
| 21:42:37.553 | cmd.exe process start | cmd.exe /c powershell.exe -e (base64), user analyst |
| 21:42:37.778 | powershell.exe process start | powershell.exe -e (base64), parent cmd.exe |
| (analysis) | decoded payload | obfuscated Write-Host built from string fragments via IEX |

## Assessment
- **Verdict:** True positive. Encoded plus obfuscated PowerShell launched from cmd.exe matches a known attacker technique (T1059.001).
- **Severity:** High. The encoding and obfuscation are designed specifically to evade detection, so any hit like this needs to be treated seriously regardless of what the decoded payload turns out to be.
- **Confidence:** High. The decode confirms deliberate obfuscation rather than a normal admin command.

## Recommended next steps
- **Investigate the source:** work out what launched cmd.exe in the first place. If it was spawned by something like a browser, email client or Office app, that points to how the host was reached.
- **Check what else the process did:** look at Sysmon network (Event ID 3) and file (Event ID 11) events around 21:42:37 for the same process, in case the real payload reached out or wrote anything to disk.
- **Contain if confirmed malicious in production:** isolate the host and review the analyst account's activity.
- **Improve the detection:** alert on PowerShell launched with the -e or -EncodedCommand flag, and raise the priority when the parent process is cmd.exe or an unusual application. A starting point in Splunk:

```
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe*"
| search CommandLine="*-e *" OR CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
| table _time, User, ParentImage, Image, CommandLine
```

Decoding the base64 automatically (or at least flagging it for an analyst to decode) makes this even more useful, since the encoding is the whole point of the technique.

## Lab note
This was generated and investigated in a controlled home lab using Atomic Red Team test T1059.001 against my own Windows VM, with Sysmon logging into Splunk. The decoded payload is the harmless test string. The detection, decoding and analysis are my own.
