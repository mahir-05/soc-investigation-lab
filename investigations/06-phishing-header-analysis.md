# Investigation 06: Phishing Email Header Analysis (T1566)

**Analyst:** Mahir Mahmood
**Data sources:** Raw email headers
**MITRE ATT&CK:** T1566 (Phishing)
**Verdict:** True positive (phishing / spoofed sender)
**Severity:** High

## Executive summary
An email claiming to be from PayPal was reported for analysis. Reading the raw headers shows the sender is spoofed: the visible From address does not match the Reply-To or Return-Path, the message originated from an unrelated server rather than PayPal's infrastructure, and the email failed SPF, DKIM and DMARC authentication. Combined with an urgent "verify within 24 hours" subject line, this is a credential-phishing attempt impersonating PayPal.

## How it came in
The email came in looking like a normal PayPal account-security notice. The visible parts of an email can say anything, so the real check is the raw headers, which show where the message actually came from and whether it passed the standard authentication checks. I worked through the From, Reply-To and Return-Path, the Received chain, and the authentication results.

## The headers
```
From: "PayPal Service" <service@paypal.com>
Reply-To: support@paypal-account-verify.com
Return-Path: <bounce@mail-secure-ru.ru>
Subject: Your account has been limited - verify within 24 hours

Received: from mail-secure-ru.ru (185.220.101.47) by mx.example.com ...
Received: from unknown (87.120.254.13) by mail-secure-ru.ru ...

Authentication-Results: mx.example.com;
 spf=fail (sender IP 185.220.101.47 not permitted by paypal.com) smtp.mailfrom=bounce@mail-secure-ru.ru;
 dkim=none;
 dmarc=fail (p=reject) header.from=paypal.com
```

## What I found

**1. The sender addresses do not match each other.**
The From says service@paypal.com, but:
- the Reply-To is support@paypal-account-verify.com
- the Return-Path is bounce@mail-secure-ru.ru

That is three different domains in one email. The From line is just a label and can be set to anything, so it cannot be trusted on its own. The Reply-To is the address any reply would actually go to, here a lookalike domain (paypal-account-verify.com) designed to look PayPal-ish while being controlled by the attacker. The Return-Path is the real envelope sender, an unrelated .ru domain. A genuine PayPal email would have these aligned to paypal.com.

**2. The Received chain shows it came from the wrong place.**
Reading the Received headers from the bottom up, the message originated from mail-secure-ru.ru at IP 185.220.101.47, then handed off to the recipient's mail server. That originating server has nothing to do with PayPal. The domain name uses the word "secure" to look reassuring, but it is just an unrelated host, not PayPal infrastructure.

**3. It failed every authentication check.**
This is the strongest evidence:
- **SPF = fail.** The sending IP (185.220.101.47) is not authorised to send mail for paypal.com.
- **DKIM = none.** There is no valid cryptographic signature at all.
- **DMARC = fail**, against a policy of reject (p=reject), for header.from=paypal.com.

When a major brand like PayPal shows SPF and DMARC failing, that is a very strong indicator the mail is spoofed, because real PayPal mail is configured specifically to pass these checks.

**4. The content uses pressure.**
The subject ("Your account has been limited, verify within 24 hours") uses urgency and fear to push the target into acting quickly without thinking, which is standard for credential phishing.

## Indicators
| Type | Value |
|------|-------|
| Spoofed brand | PayPal (From: service@paypal.com) |
| Reply-To (attacker) | support@paypal-account-verify.com |
| Return-Path | bounce@mail-secure-ru.ru |
| Originating server | mail-secure-ru.ru |
| Originating IP | 185.220.101.47 |
| Upstream IP | 87.120.254.13 |
| Auth results | SPF fail, DKIM none, DMARC fail |

## Assessment
- **Verdict:** True positive. A spoofed sender impersonating PayPal, with mismatched addresses, a foreign originating server, failed authentication and an urgency hook. This is phishing (T1566).
- **Severity:** High. The intent is almost certainly to harvest PayPal credentials. If a user clicked through and entered details, that is an account compromise.
- **Confidence:** High. The authentication failures plus the address mismatches leave little doubt.

## Recommended next steps
- **Contain:** block the sender domains (paypal-account-verify.com, mail-secure-ru.ru) and the originating IPs at the mail gateway, and quarantine or remove the email from any other inboxes that received it.
- **Check for clicks:** look at web proxy and mail logs to see whether anyone opened the link or replied. Anyone who did should have their PayPal credentials treated as exposed.
- **Notify users:** warn staff about the campaign and remind them not to act on urgent account warnings without checking the real site directly.
- **Improve the detection:** flag inbound mail that fails DMARC while claiming to be from a high-value brand, and flag mismatches between the From domain and the Reply-To or Return-Path domain. Those two checks catch a large share of brand-impersonation phishing.

## Note
This investigation uses a representative phishing email sample to demonstrate the header-analysis method, rather than a live captured email. The analysis approach (checking sender alignment, the Received chain, and SPF/DKIM/DMARC results) is exactly what I would apply to a real reported email. The analysis is my own.
