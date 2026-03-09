from app import models
from datetime import datetime, timedelta
import random
import re
import requests
from datetime import datetime

def _infer_tech_level(user_text: str) -> str:
    lowered = (user_text or "").lower()
    advanced_markers = ["dns", "payload", "tls", "xss", "sql", "certificate", "header", "port", "endpoint"]
    basic_markers = ["help", "what", "why", "safe", "scam", "real", "fake", "click"]

    if any(marker in lowered for marker in advanced_markers):
        return "advanced"
    if any(marker in lowered for marker in basic_markers):
        return "beginner"
    return "intermediate"


def educational_explainer_agent(threat: str, user_context: str = "") -> str:
    """Translate a detected threat into plain language tuned to apparent user tech level."""
    level = _infer_tech_level(user_context)
    threat_text = (threat or "Suspicious behavior detected").strip()

    beginner_prefix = (
        "In simple terms: "
        if level == "beginner"
        else ""
    )

    if "http" in threat_text.lower() and "https" not in threat_text.lower():
        body = "This site does not use secure encryption, so attackers could read data you send (like passwords)."
    elif "ssl" in threat_text.lower() or "certificate" in threat_text.lower():
        body = "The website's identity check failed, which can happen when a fake or unsafe site is pretending to be trusted."
    elif "xss" in threat_text.lower() or "script" in threat_text.lower():
        body = "This means the site may allow malicious code to run in your browser and steal session or form data."
    elif "sql" in threat_text.lower():
        body = "This issue can let attackers query or steal database data by injecting harmful input."
    elif "port" in threat_text.lower():
        body = "An open network entry point was found; if unnecessary, it gives attackers more ways to probe the system."
    elif "phishing" in threat_text.lower() or "verify" in threat_text.lower() or "otp" in threat_text.lower():
        body = "This message shows phishing patterns and may be trying to trick you into sharing passwords or one-time codes."
    elif "error" in threat_text.lower() or "suspicious" in threat_text.lower():
        body = "Something unusual was detected, which could indicate unauthorized access attempts."
    else:
        body = "This finding indicates behavior that could be abused by attackers if not fixed."

    if level == "advanced":
        suffix = " Recommended: verify exposure scope and remediate based on severity and exploitability."
    elif level == "intermediate":
        suffix = " Recommended: investigate this issue and apply security best-practice fixes."
    else:
        suffix = " Recommendation: avoid entering sensitive info until this is verified as safe."

    return f"{beginner_prefix}{body}{suffix}"

def password_strength_analyzer(password):

    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add at least one number.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add at least one special character.")

    if len(password) >= 12:
        score += 1

    return {
        "score": score,
        "feedback": feedback
    }

# ================= SIMPLE AGENTS =================
