from app import models
from datetime import datetime, timedelta
import random
import re
import requests
from datetime import datetime

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

# ================= SIMPLE SCAN AGENTS =================

def port_scanner_agent(target):
    open_ports = random.sample(range(20, 100), 5)
    risk = random.choice(["low", "medium", "high"])
    return f"Open ports on {target}: {open_ports}", risk

def vulnerability_agent(target):
    issues = ["SQL Injection", "XSS", "Weak SSL"]
    risk = random.choice(["low", "medium", "high"])
    return f"Vulnerabilities found: {random.choice(issues)}", risk

def log_analyzer_agent(logs):
    if "error" in logs.lower():
        return "Suspicious activity detected.", "high"
    return "Logs normal.", "low"

# ================= PLATFORM RISK MONITOR =================

def platform_risk_monitor(db):
    today = datetime.utcnow()
    yesterday = today - timedelta(days=1)

    today_count = db.query(models.ScanLog).filter(
        models.ScanLog.created_at >= yesterday
    ).count()

    previous_count = db.query(models.ScanLog).filter(
        models.ScanLog.created_at < yesterday
    ).count()

    if previous_count == 0:
        return

    increase = ((today_count - previous_count) / previous_count) * 100

    if increase > 30:
        alert = models.PlatformAlert(
            message="⚠️ High-risk activity spike detected."
        )
        db.add(alert)
        db.commit()

def ip_intelligence(ip):
    return {"ip": ip}

# ================= USER BEHAVIOR AGENT =================

def behavioral_risk_agent(actions):

    score = 0

    for action in actions:

        if action == "scan":
            score += 5

        if action == "exploit_test":
            score += 20

    return score

# ================= WEEKLY REPORT AGENT =================

def weekly_report_agent(db):
    users = db.query(models.User).all()

    for user in users:
        logs_count = db.query(models.ScanLog).filter(
            models.ScanLog.user_id == user.id
        ).count()

        report = models.WeeklyReport(
            user_id=user.id,
            content=f"Weekly scans: {logs_count}, Risk Score: {user.risk_score}"
        )

        db.add(report)

    db.commit()