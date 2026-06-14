# Investigation 01: Brute Force Against Local Account "analyst" (T1110)

**Date:** 14/06/2026
**Analyst:** Mahir Mahmood
**Host:** DESKTOP-H1NTMT3
**Data sources:** Windows Security event log (Splunk)
**MITRE ATT&CK:** T1110 (Brute Force)
**Verdict:** True positive
**Severity:** High

## Executive summary
A local account on DESKTOP-H1NTMT3 was hit with a burst of failed logins, six in about fifteen seconds, and then logged in successfully a couple of minutes later. The speed and pattern of the failures don't match someone just mistyping their password, and the fact a successful login followed means the account was very likely accessed by whoever was guessing. I've treated this as a confirmed brute force that succeeded and would escalate it.

## How it came in
The trigger was a spike in Windows failed-logon events (Event ID 4625) for a single account in a short window. I started from the raw failures in Splunk:

```
index=main source="WinEventLog:Security" EventCode=4625
```

That returned six events, all for the same account, all clustered within seconds of each other. A handful of failures on its own isn't always interesting, people fat-finger passwords all the time, so the job from here was to work out whether this was noise or something real.

## What I found
I pulled the failures into a table to see the shape of them clearly:

```
index=main source="WinEventLog:Security" EventCode=4625
| table _time, Account_Name, Failure_Reason, Logon_Type, Source_Network_Address
| sort _time
```

Every one of the six events was:
- against the **analyst** account
- failure reason **"unknown user name or bad password"**
- **Logon Type 2** (an interactive logon, meaning someone at the machine's own console rather than coming in over the network)
- from **127.0.0.1** (the local machine itself)

The timing is the part that stands out. All six failures landed between **21:15:45 and 21:16:00**, so roughly one every three seconds. That's faster and more regular than a real person mistyping and re-trying, and it's a single account being hit over and over, which is the basic signature of a password-guessing attempt.

One thing I noticed live while reproducing it: after several quick failures, Windows started throttling the attempts (a "delaying next attempt" message), which is the built-in protection that slows brute forcing down. That lines up with the gap you see in the timeline before the successful login.

To check whether the guessing actually worked, I pivoted to successful logons (Event ID 4624) for the same account and logon type:

```
index=main source="WinEventLog:Security" EventCode=4624 Account_Name="analyst" Logon_Type=2
| table _time, Account_Name, Logon_Type, Source_Network_Address
| sort _time
```

That came back with a successful interactive logon for **analyst at 21:18:36**, about two and a half minutes after the last failure. So the sequence is: repeated failures, a short throttling delay, then a success. That's exactly the pattern you don't want to see, because it means the account was probably accessed off the back of the guessing.

## Timeline
| Time (14/06/2026) | Event | Detail |
|-------------------|-------|--------|
| 21:15:45 to 21:16:00 | 6 failed logons (4625) | analyst, Logon Type 2, "unknown user name or bad password", from 127.0.0.1 |
| around 21:16:00 onward | account throttled | Windows delayed further attempts after repeated failures |
| 21:18:36 | successful logon (4624) | analyst, Logon Type 2, same host |

## Assessment
- **Verdict:** True positive. The failure burst plus the following success is consistent with a brute force that ended in a successful logon.
- **Severity:** High. This isn't just failed attempts, the account was actually accessed, so it has to be treated as a potential account compromise until proven otherwise.
- **Confidence:** High on the brute-force pattern itself. One caveat worth being straight about: all activity was Logon Type 2 from 127.0.0.1, so this was local console activity rather than a remote network attack. In a real environment that would shift the question towards who had local or session access to the box, rather than an external attacker hammering it over RDP or SMB.

## Recommended next steps
- **Contain:** force a password reset on the analyst account, and review everything that account did from 21:18:36 onward to see whether the access was used for anything.
- **Check scope:** look for the same failure-then-success pattern against other accounts on this host, and across other hosts, in case this is one of several.
- **Escalate:** because a successful logon followed the brute force, this should go to incident response rather than being closed at Tier 1.
- **Improve the detection:** rather than relying on someone eyeballing 4625 events, alert automatically when one account racks up several failures in a short window. A starting point in Splunk:

```
index=main source="WinEventLog:Security" EventCode=4625
| bucket _time span=1m
| stats count by _time, Account_Name
| where count >= 5
```

A stronger version would also correlate that burst with a 4624 success for the same account shortly after, so the alert specifically flags guessing that worked and stays quiet on one-off mistypes, which keeps the false-positive rate down.

## Lab note
This was generated and investigated in a controlled home lab (a Windows VM logging into Splunk), with the failed logins produced deliberately to practise the detection and investigation workflow. The analysis, queries and reasoning are my own.
