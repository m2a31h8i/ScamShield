from fastapi import FastAPI, Request, Form, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from app.database import engine, SessionLocal
from app import models, auth, agents
from app.config import SECRET_KEY
import os
import requests
import re
from app import models
from app import agents
from app.database import SessionLocal
from app.agents import password_strength_analyzer
from app.agents import *
from app.queue import add_task


app = FastAPI()

models.Base.metadata.create_all(bind=engine)

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.mount("/static", StaticFiles(directory="static"), name="static")

def _template_path(*parts: str) -> str:
    return os.path.join("templates", *parts)


def _read_template(*parts: str) -> str:
    with open(_template_path(*parts), "r", encoding="utf-8") as f:
        return f.read()


def _text_risk_analysis(text: str) -> dict:
    lowered = text.lower()
    risk = 0.05
    explanation = []

    urgent_words = ["urgent", "immediately", "now", "asap", "limited time"]
    if any(word in lowered for word in urgent_words):
        risk += 0.25
        explanation.append("Urgency language detected")

    suspicious_words = ["verify", "login", "otp", "reward", "free", "bank", "account"]
    hits = sum(1 for word in suspicious_words if word in lowered)
    if hits:
        risk += min(0.35, hits * 0.08)
        explanation.append("Suspicious scam keywords detected")

    if re.search(r"https?://\S+", text):
        risk += 0.2
        explanation.append("Message contains a URL")

    if not explanation:
        explanation.append("No obvious scam indicators detected")

    score = round(min(risk, 1), 2)
    category = "safe message" if score < 0.4 else "phishing scam"
    return {"risk_score": score, "category": category, "explanation": explanation}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request):
    return request.session.get("user")


# ================= HOME =================

@app.get("/", response_class=HTMLResponse)
def home():
    return open("templates/index.html")

# ================= CONTACT =================

@app.post("/contact")
def contact(name: str = Form(...),
            email: str = Form(...),
            message: str = Form(...)):
    
    print(name, email, message)

    return HTMLResponse("""
    <h2>Message Sent Successfully</h2>
    <a href="/">Back to Home</a>
    """)

# ================= REGISTER =================

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return open("templates/register.html")

@app.post("/register")
def register(username: str = Form(...),
            email: str = Form(...),
            password: str = Form(...),
            role: str = Form(...),
            db: Session = Depends(get_db)):

    try:
        # 🔐 Password Strength Check
        strength = password_strength_analyzer(password)

        if strength["score"] < 3:
            return HTMLResponse(
                f"<h3>Weak Password</h3>"
                f"<p>Suggestions: {', '.join(strength['feedback'])}</p>"
                f"<a href='/register'>Go Back</a>"
            )

        hashed = auth.hash_password(password)

        user = models.User(
            username=username,
            email=email,
            password=hashed,
            role=role
        )

        db.add(user)
        db.commit()

        return RedirectResponse(url="/login", status_code=303)

    except Exception as e:
        return HTMLResponse(f"<h1>Registration Error</h1><p>{str(e)}</p>")

# ================= ABOUT =================

@app.get("/about", response_class=HTMLResponse)
def about():
    return _read_template("about.html")

# ================= HELP =================

@app.get("/help", response_class=HTMLResponse)
def help_page():
    return _read_template("help.html")

# ================= LOGIN =================

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return _read_template("login.html")

@app.post("/login")
def login(request: Request,
        email: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db)):

    user = auth.authenticate_user(db, email, password)
    if not user:
        return RedirectResponse("/login", status_code=303)

    request.session["user"] = {"id": user.id, "role": user.role}
    
    if user.role == "admin":
        return RedirectResponse("/admin", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)

# ================= LOGOUT =================

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)

# ================= USER DASHBOARD =================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not get_current_user(request):
        return RedirectResponse("/login", status_code=303)
    return _read_template("dashboard.html")

# @app.get("/tool/ip-intel/{ip}")
# def ip_tool(ip: str):

#     return "<h3>IP Intelligence Tool</h3>"

# @app.get("/tool/security-advisor/{issue}")
# def advisor(issue: str):

#     return "<h3>AI Security Advisor</h3>"

# @app.get("/tool/behavior-risk")
# def behavior_risk():

#     actions = ["scan", "scan", "login_fail"]

#     risk = behavioral_risk_agent(actions)

#     return f"""
#     <h2>Behavioral Risk Agent</h2>
#     <p>User Activity: {actions}</p>
#     <p>Calculated Risk Score: {risk}</p>
#     """

# @app.get("/tool/domain-scan/{domain}")
# def domain_scan(domain: str):

#     return "<h3>Multi-Agent Security Scan</h3>"

# @app.get("/tool/threat-spike/{events}")
# def spike(events: int):

#     return "<h3>Threat Spike Detector</h3>"

# @app.get("/tool/weekly-summary")
# def weekly():

#     return "<h3>Weekly Intelligence Summary</h3>"

# ================= PROFILE =================

@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    return _read_template("profile.html")

# ================= ADMIN DASHBOARD =================

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/login", status_code=303)
    return _read_template("admin_dashboard.html")

# ================= TOOLS =================

@app.get("/tools/port-scanner", response_class=HTMLResponse)
def port_page():
    return _read_template("tools", "port_scanner.html")

@app.post("/tools/port-scanner")
def run_port_scanner(request: Request,
                    target: str = Form(...),
                    db: Session = Depends(get_db)):
    
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    result = agents.port_scanner_agent(target)

    log = models.ScanLog(user_id=user["id"], tool="Port Scanner", target=target, result=result)
    db.add(log)
    db.commit()

    return _read_template("tools", "vuln_scanner.html")

# ================= VULN =================

@app.get("/tools/vuln-scanner", response_class=HTMLResponse)
def vuln_page():
    return open("templates/tools/vuln_scanner.html").read()

@app.post("/tools/vuln-scanner")
def run_vuln_scanner(request: Request,
                    target: str = Form(...),
                    db: Session = Depends(get_db)):

    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    result = agents.vulnerability_agent(target)

    log = models.ScanLog(user_id=user["id"], tool="Vulnerability Scanner", target=target, result=result)
    db.add(log)
    db.commit()

    return HTMLResponse(f"<h2>{result}</h2><a href='/dashboard'>Back</a>")

# ================= LOG ANALYZER =================

@app.get("/tools/log-analyzer", response_class=HTMLResponse)
def log_page():
    return _read_template("tools", "log_analyzer.html")

@app.post("/tools/log-analyzer")
def run_log_analyzer(request: Request,
                    logs: str = Form(...),
                    db: Session = Depends(get_db)):

    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    result = agents.log_analyzer_agent(logs)

    log = models.ScanLog(user_id=user["id"], tool="Log Analyzer", target="Logs Input", result=result)
    db.add(log)
    db.commit()

    return HTMLResponse(f"<h2>{result}</h2><a href='/dashboard'>Back</a>")

# ================= URL SCANNER =================

@app.get("/tools/url-scanner", response_class=HTMLResponse)
def url_scanner_page():
    return _read_template("tools", "url", "frontend", "templates", "main.html")


@app.get("/url-scanner", response_class=HTMLResponse)
def url_scanner_alias():
    return url_scanner_page()

@app.post("/tools/url-scanner")
def run_url_scanner(request: Request,
                    url: str = Form(...),
                    db: Session = Depends(get_db)):
    
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    try:
        # Call the Flask backend
        response = requests.post("http://localhost:5000/scan", json={"url": url}, timeout=30)
        if response.status_code == 200:
            data = response.json()
            result = f"Scan completed. Risk Level: {data['data']['risk_level']}. Vulnerabilities: {len(data['data']['vulnerabilities'])}"
        else:
            result = f"Error: {response.text}"
    except Exception as e:
        result = f"Failed to scan: {str(e)}"

    log = models.ScanLog(user_id=user["id"], tool="URL Scanner", target=url, result=result)
    db.add(log)
    db.commit()

    return HTMLResponse(f"<h2>{result}</h2><a href='/dashboard'>Back</a>")

@app.post("/scan")
def proxy_url_scan(payload: dict):
    try:
        response = requests.post("http://localhost:5000/scan", json=payload, timeout=60)
    except Exception as e:
        return {"success": False, "error": f"URL scanner backend unavailable: {str(e)}"}

    try:
        return response.json()
    except Exception:
        return {"success": False, "error": response.text}


@app.get("/history")
def proxy_url_history():
    try:
        response = requests.get("http://localhost:5000/history", timeout=30)
        return response.json()
    except Exception as e:
        return {"success": False, "error": f"URL scanner backend unavailable: {str(e)}"}


@app.get("/scan/{scan_id}")
def proxy_url_scan_by_id(scan_id: int):
    try:
        response = requests.get(f"http://localhost:5000/scan/{scan_id}", timeout=30)
        return response.json()
    except Exception as e:
        return {"success": False, "error": f"URL scanner backend unavailable: {str(e)}"}


@app.get("/report/{scan_id}")
def proxy_url_report(scan_id: int):
    return RedirectResponse(url=f"http://localhost:5000/report/{scan_id}", status_code=307)


@app.get("/qr-scanner", response_class=HTMLResponse)
def qr_scanner_page():
    return _read_template("tools", "text_qr_analyzer", "templates", "my_dashboard.html")


@app.post("/analyze-text")
async def analyze_text(request: Request):
    payload = await request.json()
    text = payload.get("text", "") if isinstance(payload, dict) else ""
    if not text.strip():
        return {"risk_score": 0, "category": "safe message", "explanation": ["No text provided"]}
    return _text_risk_analysis(text)


@app.post("/scan-qr")
async def scan_qr(file: UploadFile = File(...)):
    try:
        data = await file.read()
        files = {"file": (file.filename or "qr.png", data, file.content_type or "application/octet-stream")}
        response = requests.post("http://localhost:8002/scan-qr", files=files, timeout=60)
        return response.json()
    except Exception:
        return {
            "risk_score": 0,
            "category": "unavailable",
            "explanation": ["QR analyzer service is not running on localhost:8002"],
        }

@app.get("/analysis", response_class=HTMLResponse)
def user_analysis(request: Request, db: Session = Depends(get_db)):

    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    logs = db.query(models.ScanLog).filter(
        models.ScanLog.user_id == user["id"]
    ).all()

    high = len([l for l in logs if l.risk_level == "high"])
    medium = len([l for l in logs if l.risk_level == "medium"])
    low = len([l for l in logs if l.risk_level == "low"])

    html = _read_template("analysis.html")

    html = html.replace("{{total}}", str(len(logs)))
    html = html.replace("{{high}}", str(high))
    html = html.replace("{{medium}}", str(medium))
    html = html.replace("{{low}}", str(low))

    return HTMLResponse(html)

@app.get("/admin/analysis", response_class=HTMLResponse)
def admin_analysis(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/login", status_code=303)

    logs = db.query(models.ScanLog).all()

    high = len([l for l in logs if l.risk_level == "high"])

    return HTMLResponse(f"""
    <h1>Platform Analysis</h1>
    <p>Total Platform Scans: {len(logs)}</p>
    <p>Total High Risk Activity: {high}</p>
    <a href='/admin'>Back</a>
    """)

@app.get("/admin/users", response_class=HTMLResponse)
def manage_users(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/login", status_code=303)

    users = db.query(models.User).all()

    html = "<h1>User Management</h1>"
    for u in users:
        html += f"<p>{u.username} | {u.email} | Risk: {u.risk_score}</p>"

    html += "<a href='/admin'>Back</a>"
    return HTMLResponse(html)