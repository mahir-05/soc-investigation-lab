# soc-investigation-lab

This is a home lab I built to practise the day-to-day work of a Tier-1 SOC analyst: watching logs come in, spotting something that looks off, and working out whether it's a real attack or just noise. Rather than just standing up the tools and stopping there, the point of this repo is the investigations. Each one takes a simulated attack, walks through how I found it and what the logs actually showed, and ends with a verdict and what I'd do next.

I set it up because reading about alerts and actually triaging one are different things, and this gives me somewhere to do the second.

## How it works
A Windows machine generates the logs, Splunk collects them, and I investigate from there.

- A Windows 10/11 virtual machine acts as the endpoint being attacked.
- Sysmon runs on it for detailed process, network and registry logging, on top of the standard Windows Security and System event logs.
- All of those logs feed into Splunk, which is where I search and investigate using SPL.
- Attacks are run against the machine on purpose, then I investigate them as if the alert had come in cold.

```
Windows endpoint (Sysmon + Windows event logs)  ->  Splunk (SIEM)  ->  investigated with SPL
```

## Tools
- Splunk, as the SIEM and search platform
- Sysmon plus Windows Security and System event logs, as the log sources
- VirtualBox, to run the endpoint
- MITRE ATT&CK, to map each attack to a known technique

## Investigations
Each write-up follows the same layout: what triggered it, how I investigated, a timeline, an assessment with a verdict and severity, and recommended next steps.

| # | Investigation | Technique | Verdict |
|---|---------------|-----------|---------|
| 01 | [Brute force against a local account](investigations/01-brute-force.md) | T1110 Brute Force | True positive |
| 02 | [Encoded PowerShell command execution](investigations/02-malicious-powershell.md) | T1059.001 PowerShell | True positive |
| 03 | [New local admin account created](investigations/03-new-admin-account.md) | T1136.001 Create Account | True positive |
| 04 | [Suspicious service installed for persistence](investigations/04-persistence-service.md) | T1543.003 Windows Service | True positive |
| 05 | [Suspicious process chain (shell spawning shell)](investigations/05-suspicious-process-chain.md) | T1059 Scripting Interpreter | True positive |
| 06 | [Phishing email header analysis](investigations/06-phishing-header-analysis.md) | T1566 Phishing | True positive |

## What I'm getting out of it
- Reading Windows Security and Sysmon logs and knowing which event IDs matter (4625, 4624, and so on)
- Writing SPL to pull out and pivot on suspicious activity
- Telling a real detection apart from normal noise, and being able to say why
- Turning a one-off finding into a detection that would catch it next time
- Writing the whole thing up clearly enough to hand to someone else

## A note on the data
Everything here was generated and investigated in a controlled lab. The attacks are simulated by me against my own virtual machine so I can practise the detection and investigation process safely. The analysis, queries and conclusions are my own.
