"""
==================================================================
 DecodeLabs Industrial Training Kit — Project 3
 PHISHING AWARENESS ANALYSIS & TRIAGE TOOL
==================================================================

Goal:
    Analyze a message (email/SMS/etc.) to identify phishing red
    flags, and classify it using the triage model from the
    project brief:

        Safe        -> Close
        Suspicious  -> Warn User
        Malicious   -> Block & Escalate

Key Requirements covered:
    - Identify suspicious links or keywords
    - List red flags found in the message
    - Explain why the message is unsafe

This tool doesn't replace human judgement (no automated system
should be the only line of defense against social engineering),
but it demonstrates the "Pause, Verify, Report" logic taught in
the DecodeLabs slides by automating the "Pause" step: quickly
flagging patterns a human should look closer at.

Author: Shrey
==================================================================
"""

import re


# ------------------------------------------------------------------
# STEP 1: Define the red flag indicators we scan for.
# Each category maps to a list of (pattern, description) pairs.
# Patterns are simple keyword/regex checks — a real production
# system would use NLP/ML, but this demonstrates the underlying
# logic clearly, matching the project's "logic building" goal.
# ------------------------------------------------------------------

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "act now",
    "expires in", "locked", "24 hours", "final notice",
    "verify your account", "suspended", "immediate action"
]

AUTHORITY_KEYWORDS = [
    "ceo", "director", "law enforcement", "irs", "government",
    "strictly confidential", "do not discuss", "bypass",
    "bypass standard procedure"
]

CREDENTIAL_REQUEST_KEYWORDS = [
    "password", "otp", "one-time code", "mfa code", "pin",
    "social security", "card number", "cvv", "login details",
    "confirm your password"
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "bank details", "payment overdue",
    "update your billing", "invoice attached", "gift card",
    "transfer funds", "account number"
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear (customer|user|valued customer|member)\b",
    r"\bdear sir/madam\b",
]

SUSPICIOUS_LINK_PATTERNS = [
    r"https?://[^\s]*-(secure|login|update|verify)[^\s]*\.[a-z]{2,}",  # combosquatting style
    r"https?://[^\s]*\.(xyz|top|click|info|zip|gq|tk)\b",              # commonly abused free TLDs
    r"bit\.ly|tinyurl\.com|t\.co\b",                                    # link shorteners hiding real destination
]

SUSPICIOUS_ATTACHMENT_PATTERN = r"\.(exe|scr|js|iso|vbs|bat|jar)\b"


def find_matches(text: str, keyword_list) -> list:
    """
    Returns which keywords from a list appear in the text (case-insensitive),
    while filtering out simple negated matches (e.g. "Non-Urgent", "No immediate
    action required") so we don't flag a message for explicitly denying urgency.
    """
    text_lower = text.lower()
    negation_prefixes = ("non-", "non ", "not ", "no ")

    hits = []
    for kw in keyword_list:
        start = text_lower.find(kw)
        if start == -1:
            continue

        # Look at the ~6 characters right before the match to catch negation.
        preceding = text_lower[max(0, start - 6):start]
        if any(preceding.endswith(neg) for neg in negation_prefixes):
            continue  # negated — don't count it as a red flag

        hits.append(kw)

    return hits


def find_pattern_matches(text: str, patterns: list) -> list:
    """Returns which regex patterns match somewhere in the text."""
    matches = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern)
    return matches


def analyze_message(text: str, sender_display_name: str = "", sender_email: str = "") -> dict:
    """
    Analyzes a message and returns a dictionary with:
        - 'red_flags'    : list of human-readable red flags found
        - 'risk_score'   : numeric score
        - 'classification': "Safe" / "Suspicious" / "Malicious"
        - 'action'       : recommended action per the triage model
    """
    red_flags = []
    score = 0

    # ---- Check 1: Urgency / pressure tactics ----
    urgency_hits = find_matches(text, URGENCY_KEYWORDS)
    if urgency_hits:
        red_flags.append(f"Urgency/pressure language detected: {', '.join(urgency_hits)}")
        score += 2

    # ---- Check 2: Authority impersonation / bypass requests ----
    authority_hits = find_matches(text, AUTHORITY_KEYWORDS)
    if authority_hits:
        red_flags.append(f"Authority impersonation or bypass request: {', '.join(authority_hits)}")
        score += 3

    # ---- Check 3: Requests for credentials/sensitive info ----
    cred_hits = find_matches(text, CREDENTIAL_REQUEST_KEYWORDS)
    if cred_hits:
        red_flags.append(f"Requests sensitive information: {', '.join(cred_hits)}")
        score += 3

    # ---- Check 4: Financial/wire transfer requests ----
    financial_hits = find_matches(text, FINANCIAL_KEYWORDS)
    if financial_hits:
        red_flags.append(f"Financial/payment request language: {', '.join(financial_hits)}")
        score += 3

    # ---- Check 5: Generic greeting (mass phishing indicator) ----
    greeting_hits = find_pattern_matches(text, GENERIC_GREETING_PATTERNS)
    if greeting_hits:
        red_flags.append("Generic greeting instead of a personal name (mass phishing indicator)")
        score += 1

    # ---- Check 6: Suspicious links ----
    link_hits = find_pattern_matches(text, SUSPICIOUS_LINK_PATTERNS)
    if link_hits:
        red_flags.append("Suspicious or obscured link detected (lookalike domain / shortener)")
        score += 3

    # ---- Check 7: Dangerous attachment types ----
    if re.search(SUSPICIOUS_ATTACHMENT_PATTERN, text, re.IGNORECASE):
        red_flags.append("Dangerous attachment file type referenced (executable/script)")
        score += 3

    # ---- Check 8: Sender display name vs. actual email domain mismatch ----
    if sender_display_name and sender_email:
        # crude but effective: does the display name's implied company
        # appear anywhere in the actual email domain?
        display_lower = sender_display_name.lower()
        domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
        # Flag common free-mail domains pretending to be a company/exec
        free_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
        if any(word in display_lower for word in ["ceo", "support", "admin", "security", "it "]) and domain in free_domains:
            red_flags.append(
                f"Sender display name ('{sender_display_name}') implies an official role, "
                f"but the email domain ('{domain}') is a free consumer email provider"
            )
            score += 4

    # ---- Classification per the DecodeLabs triage model ----
    if score == 0:
        classification = "Safe"
        action = "Close — no action needed."
    elif score <= 4:
        classification = "Suspicious"
        action = "Warn User — advise caution, verify through a separate channel before acting."
    else:
        classification = "Malicious"
        action = "Block & Escalate — report to security team, do not click links or reply."

    if not red_flags:
        red_flags.append("No red flags detected based on current checklist.")

    return {
        "red_flags": red_flags,
        "risk_score": score,
        "classification": classification,
        "action": action
    }


def display_analysis(message_label: str, text: str, sender_display_name="", sender_email=""):
    """Nicely prints the triage result for a message."""
    result = analyze_message(text, sender_display_name, sender_email)

    print("\n" + "=" * 65)
    print(f" MESSAGE: {message_label}")
    print("-" * 65)
    print(f" Risk Score      : {result['risk_score']}")
    print(f" Classification  : {result['classification']}")
    print(f" Recommended Action: {result['action']}")
    print("-" * 65)
    print(" Red Flags Identified:")
    for flag in result["red_flags"]:
        print(f"   - {flag}")
    print("=" * 65)


# ------------------------------------------------------------------
# MAIN PROGRAM — includes 3 sample messages modeled directly on
# the attack patterns described in the DecodeLabs slides, plus an
# interactive mode for analyzing your own messages.
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("DecodeLabs Cybersecurity Analyst Toolkit")
    print("Project 3: Phishing Awareness Analysis & Triage Tool\n")

    # Sample 1: Business Email Compromise (BEC) - "Lost Wallet" / CEO wire transfer
    sample_1 = (
        "Subject: URGENT - Immediate Action Required\n\n"
        "Dear Valued Customer,\n\n"
        "This is the CEO. I am traveling and lost my wallet at the airport. "
        "I need you to wire transfer funds immediately before the close of business. "
        "This is strictly confidential, do not discuss with anyone. Bypass standard procedure "
        "and process the attached wire transfer instruction right away.\n\n"
        "Thank you."
    )
    display_analysis(
        "Sample 1 - Fake CEO Wire Transfer Request",
        sample_1,
        sender_display_name="CEO Name",
        sender_email="hacker@gmail.com"
    )

    # Sample 2: Fake IT/password reset phishing
    sample_2 = (
        "Subject: Mandatory: Password expires in 24 hrs\n\n"
        "Dear User,\n\n"
        "Your password will expire in 24 hours. Please verify your account "
        "immediately by clicking the secure link below to avoid suspension:\n"
        "http://yourcompany-secure-login.xyz/reset\n\n"
        "IT Security Team"
    )
    display_analysis("Sample 2 - Fake IT Password Reset", sample_2)

    # Sample 3: A genuinely safe/normal email for comparison
    sample_3 = (
        "Subject: Q3 Project Status Update - Non-Urgent\n\n"
        "Hi Team,\n\n"
        "Please review the attached project status for Q3 at your earliest convenience. "
        "No immediate action is required.\n\n"
        "Thanks,\nSarah"
    )
    display_analysis("Sample 3 - Legitimate Internal Email (control example)", sample_3)

    # ---- Interactive mode ----
    print("\nYou can also analyze your own message below.")
    while True:
        choice = input("\nAnalyze a custom message? (y/n): ").strip().lower()
        if choice != "y":
            print("Goodbye! Stay vigilant.")
            break

        custom_text = input("Paste the message text: ")
        custom_name = input("Sender display name (optional, press Enter to skip): ")
        custom_email = input("Sender email address (optional, press Enter to skip): ")
        display_analysis("Custom Message", custom_text, custom_name, custom_email)
