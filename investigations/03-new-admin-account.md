# Investigation 03: New Local Admin Account Created (T1136.001)

**Analyst:** Mahir Mahmood
**Host:** DESKTOP-H1NTMT3
**Data sources:** Windows Security event log (Splunk)
**MITRE ATT&CK:** T1136.001 (Create Account: Local Account), with privilege escalation / persistence
**Verdict:** True positive
**Severity:** High

## Executive summary
A new local account called "backdoor" was created on DESKTOP-H1NTMT3 and then added to the Administrators group about three seconds later, both actions carried out by the analyst account. Creating an account and immediately giving it admin rights is a common way for an attacker to set up a way back into a machine that survives even if their original access is cut off. The speed and the jump straight to admin make this look deliberate rather than normal account setup.

## How it came in
I was looking for account-management activity in the Windows Security log, specifically account creation (Event ID 4720) and accounts being added to groups (Event ID 4732):

```
index=main source="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| table _time, EventCode, Account_Name, Target_Account_Name, Group_Name
| sort _time
```

That returned three events within a few seconds of each other, which told the whole story.

## What I found
Three related events, all carried out by the **analyst** account:

- **21:53:16.082 (4720):** a new account named **backdoor** was created.
- **21:53:16.127 (4732):** that account was added to the **Users** group. This one is normal, Windows adds new accounts to Users automatically, so it is not interesting on its own.
- **21:53:19.460 (4732):** the same account was added to the **Administrators** group. This is the one that matters.

The thing that makes this suspicious is the combination and the timing. A brand new account being promoted to local administrator within about three seconds of being created is not how a person normally sets up a genuine user, it looks scripted and purposeful. An attacker who already has access to a machine will often create their own admin account like this so they have a reliable way back in later, even if the original foothold is removed. The account name "backdoor" is obviously a giveaway in a lab, but the behaviour pattern is what you would actually alert on, not the name.

It is worth being clear about which event is the real signal here. The 4732 into Users is noise, every new account triggers it. The 4732 into Administrators is the one that turns this from "an account was made" into "an account was made and handed full control of the machine."

## Timeline
| Time (14/06/2026) | Event | Detail |
|-------------------|-------|--------|
| 21:53:16.082 | account created (4720) | new account "backdoor", created by analyst |
| 21:53:16.127 | added to group (4732) | added to Users (automatic, normal) |
| 21:53:19.460 | added to group (4732) | added to Administrators (the red flag) |

## Assessment
- **Verdict:** True positive. A new account created and promoted to local admin within seconds matches account-creation for persistence (T1136.001).
- **Severity:** High. The new account has full administrative control of the host, and if this were real it would represent attacker persistence that needs removing.
- **Confidence:** High. The create-then-promote-to-admin sequence is clear in the logs and is not normal user setup.

## Recommended next steps
- **Contain:** disable or remove the backdoor account and confirm it is out of the Administrators group. Review what it was used for after creation.
- **Find the root cause:** the activity was done by the analyst account, so work out whether that account was itself compromised, and how. Creating an admin account is usually a follow-on action after an attacker already has access.
- **Check scope:** look for other newly created accounts or unexpected additions to Administrators on this host and others.
- **Escalate:** persistence via a new admin account should go to incident response, not be closed at Tier 1.
- **Improve the detection:** alert whenever an account is added to the Administrators group, and raise the priority when it happens close in time to a 4720 account creation. A starting point in Splunk:

```
index=main source="WinEventLog:Security" EventCode=4732 Group_Name="Administrators"
| table _time, Account_Name, Target_Account_Name, Group_Name
```

Correlating a 4720 (account created) with a 4732 into Administrators for the same account within a short window would flag this specific create-then-promote pattern while ignoring the normal additions to Users.

## Lab note
This was generated and investigated in a controlled home lab. I created the "backdoor" account and added it to Administrators myself on my own Windows VM to produce the logs, then investigated them in Splunk. The detection and analysis are my own.
