import re

RULES = {
    "AADHAAR": r"\b\d{4}\s\d{4}\s\d{4}\b",
    "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "EMAIL": r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
    "PASSWORD": r"(password\s*[:=]\s*['\"].+['\"])",
    "API_KEY": r"(AIza[0-9A-Za-z\-_]{35})"
}

def detect_sensitive_data(text):
    findings = {}

    for key, pattern in RULES.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            findings[key] = len(matches)

    return findings
