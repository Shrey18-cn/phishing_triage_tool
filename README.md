# Phishing Awareness Analysis & Triage Tool

A Python tool that analyzes email/message text for common phishing red flags and classifies it as **Safe**, **Suspicious**, or **Malicious**, recommending an action for each. Built as **Project 3** of the DecodeLabs Cybersecurity Industrial Training Kit (2026 batch).

## Overview

Modern security isn't just about firewalls — the majority of breaches begin with a human being tricked into clicking, replying, or paying. This project focuses on the "human firewall": training analytical instincts to catch deceptive tactics in communication before damage is done.

This tool automates the "Pause" step of the golden rule taught in this project — **Pause, Verify, Report** — by scanning a message for known red flags and producing a triage recommendation, the same way a junior analyst would triage an inbox.

## How it works

The tool checks a message against several categories of known phishing indicators:

| Category | What it looks for |
|---|---|
| **Urgency/pressure language** | "urgent", "act now", "account suspended", "expires in 24 hours" |
| **Authority impersonation** | References to CEOs, government agencies, demands for secrecy or bypassing procedure |
| **Credential/sensitive info requests** | Passwords, OTPs, MFA codes, card numbers |
| **Financial requests** | Wire transfers, billing updates, overdue payment notices |
| **Generic greetings** | "Dear Customer", "Dear User" — a hallmark of mass phishing |
| **Suspicious links** | Combosquatted domains (e.g. `company-secure-login.xyz`), abused free TLDs, link shorteners |
| **Dangerous attachments** | Executable/script file types (`.exe`, `.js`, `.scr`, `.iso`) |
| **Sender/domain mismatch** | A display name implying an official role (e.g. "CEO", "IT Support") paired with a free consumer email domain (Gmail, Yahoo, etc.) |

Each match adds to a risk score. The final score maps to the triage model used throughout this project:

```
Score 0        -> Safe        -> Close
Score 1-4      -> Suspicious  -> Warn User
Score 5+       -> Malicious   -> Block & Escalate
```

### A note on negation handling

Naive keyword matching has a known weakness: it can't tell "URGENT: wire funds now" from "No immediate action is required." This tool includes basic negation filtering (checking for "non-", "not", "no" immediately before a matched keyword) so a message that explicitly denies urgency isn't mistakenly flagged for containing the word "urgent."

## Usage

Requires Python 3.6+ (no external dependencies).

```bash
python3 phishing_triage_tool.py
```

The program automatically runs three built-in sample analyses, then offers an interactive mode where you can paste in your own message (plus optional sender display name/email) for analysis.

## Sample Analyses Included

### Sample 1 — Fake CEO Wire Transfer Request (Business Email Compromise)
**Classification: Malicious (Score: 13)**

Modeled on real-world BEC attacks like the Quanta Computer exploit that cost Google and Facebook over $100 million. Red flags include urgency language, authority impersonation, demands for secrecy, an explicit request to bypass procedure, a wire transfer demand, a generic greeting, and — most critically — a display name of "CEO Name" paired with a `gmail.com` sender address.

**Why it's unsafe:** No real executive conducts confidential wire transfers over a free consumer email account, and legitimate financial requests are never paired with instructions to bypass standard verification.

### Sample 2 — Fake IT Password Reset
**Classification: Malicious (Score: 9)**

Modeled on credential-harvesting phishing. Red flags include artificial urgency (password "expiring" in 24 hours), a direct request tied to credentials, a generic greeting, and a combosquatted link (`yourcompany-secure-login.xyz`).

**Why it's unsafe:** Legitimate password resets are initiated by the user, not demanded via unsolicited email, and the domain doesn't match any real company's actual login page.

### Sample 3 — Legitimate Internal Email (control example)
**Classification: Safe (Score: 0)**

An ordinary, low-stakes internal status update included specifically to prove the tool doesn't over-flag normal correspondence — a triage tool that cries wolf on every message is as useless as one that catches nothing.

## Triage Decision Model

```
Incoming Message
        |
   Risk Analysis
        |
   +----+----+----------+
   |         |           |
 Safe   Suspicious   Malicious
   |         |           |
 Close   Warn User   Block & Escalate
```

## Project Structure

```
phishing-triage-project/
├── phishing_triage_tool.py   # Main program
└── README.md                 # This file
```

## Key Skills Demonstrated

- Threat analysis and pattern recognition
- Regex and keyword-based text analysis
- Understanding of social engineering tactics (urgency, authority, fear/greed, curiosity)
- Awareness of technical phishing indicators (domain spoofing, combosquatting, malicious attachments)
- Decision-tree based triage logic

## Important Note

This tool is an educational aid, not a production security control. Real-world phishing detection requires layered defenses (email authentication protocols like SPF/DKIM/DMARC, security awareness training, and human judgment) — no keyword-matching script should be the sole line of defense against social engineering.

## Author

Shreya C N — DecodeLabs Industrial Training Kit, 2026 Batch
