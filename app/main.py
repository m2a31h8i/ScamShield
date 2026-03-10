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
from fastapi.templating import Jinja2Templates
from templates.tools.text_qr_analyzer import text_router
from templates.tools.text_qr_analyzer import qr_router
from templates.tools.text_qr_analyzer import explainer_router
from templates.tools.text_qr_analyzer.educational_explainer import explainer_router

app = FastAPI()

# sam added
templates = Jinja2Templates(directory="app/templates/tools/text_qr_analyzer/templates")

@app.get("/my-tools", response_class=HTMLResponse)
def my_dashboard(request: Request):
    return templates.TemplateResponse("my_dashboard.html", {"request": request})

app.include_router(text_router)
app.include_router(qr_router)
app.include_router(explainer_router)
# sam added end

models.Base.metadata.create_all(bind=engine)

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(explainer_router)
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

def _build_educational_explanations(threats, user_context: str = ""):
    return [agents.educational_explainer_agent(threat, user_context) for threat in threats if threat]

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
    return _read_template("index.html")

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
    return _read_template("register.html")

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

    result, risk = agents.port_scanner_agent(target)
    ports = re.findall(r"\d+", result)
    threats = [f"Port {port} appears open" for port in ports]
    educational = _build_educational_explanations(threats, target)

    rendered_result = result + "\n\nEducational Explainer Agent:\n- " + "\n- ".join(educational)

    log = models.ScanLog(user_id=user["id"], tool="Port Scanner", target=target, result=rendered_result, risk_level=risk)

    db.add(log)
    db.commit()

    return HTMLResponse(f"<h2>{result}</h2><p><b>Educational Explainer Agent</b></p><ul>{''.join(f'<li>{line}</li>' for line in educational)}</ul><a href='/dashboard'>Back</a>")

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

    result, risk = agents.vulnerability_agent(target)
    findings = [part.strip() for part in result.split(":", 1)]
    threats = [findings[-1]]
    educational = _build_educational_explanations(threats, target)
    rendered_result = result + "\n\nEducational Explainer Agent:\n- " + "\n- ".join(educational)

    log = models.ScanLog(user_id=user["id"], tool="Vulnerability Scanner", target=target, result=rendered_result, risk_level=risk)
    db.add(log)
    db.commit()

    return HTMLResponse(f"<h2>{result}</h2><p><b>Educational Explainer Agent</b></p><ul>{''.join(f'<li>{line}</li>' for line in educational)}</ul><a href='/dashboard'>Back</a>")

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

    result, risk = agents.log_analyzer_agent(logs)
    threats = [result] if risk in {"medium", "high"} else []
    educational = _build_educational_explanations(threats, logs)
    rendered_result = result
    if educational:
        rendered_result += "\n\nEducational Explainer Agent:\n- " + "\n- ".join(educational)

    log = models.ScanLog(user_id=user["id"], tool="Log Analyzer", target="Logs Input", result=rendered_result, risk_level=risk)
    db.add(log)
    db.commit()

    details = f"<p><b>Educational Explainer Agent</b></p><ul>{''.join(f'<li>{line}</li>' for line in educational)}</ul>" if educational else ""
    return HTMLResponse(f"<h2>{result}</h2>{details}<a href='/dashboard'>Back</a>")

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
            vulnerabilities = data.get("data", {}).get("vulnerabilities", [])
            risk_level = data.get("data", {}).get("risk_level", "low").lower()
            threats = [v.get("title", "Detected security threat") for v in vulnerabilities]
            educational = _build_educational_explanations(threats, url)
            agentic = agents.generate_scan_explainer(
                threat_type=vulnerabilities[0].get("title", "Suspicious URL") if vulnerabilities else "Suspicious URL",
                target=url,
                risk_score={"low": 30, "medium": 65, "high": 90}.get(risk_level, 30),
                indicators=threats,
            )
            result = f"Scan completed. Risk Level: {data['data']['risk_level']}. Vulnerabilities: {len(vulnerabilities)}"
            if educational:
                result += "\n\nEducational Explainer Agent:\n- " + "\n- ".join(educational)
        else:
            risk_level = "low"
            educational = []
            agentic = None
            result = f"Error: {response.text}"
    except Exception as e:
        risk_level = "low"
        educational = []
        agentic = None
        result = f"Failed to scan: {str(e)}"

    log = models.ScanLog(user_id=user["id"], tool="URL Scanner", target=url, result=result, risk_level=risk_level)
    db.add(log)
    db.commit()

    details = f"<p><b>Educational Explainer Agent</b></p><ul>{''.join(f'<li>{line}</li>' for line in educational)}</ul>" if educational else ""
    if agentic:
        details += (
            f"<p><b>{agentic['title']}</b></p>"
            f"<p><b>What's wrong:</b> {agentic['whats_wrong']}</p>"
            f"<p><b>What would happen:</b> {agentic['what_would_happen']}</p>"
            f"<p><b>What to do:</b> {agentic['what_to_do']}</p>"
            f"<p><b>Tip:</b> {agentic['tip']}</p>"
        )
    first_line = result.splitlines()[0] if result else "Scan result unavailable"
    return HTMLResponse(f"<h2>{first_line}</h2>{details}<a href='/dashboard'>Back</a>")

@app.post("/scan")
def proxy_url_scan(payload: dict):
    try:
        response = requests.post("http://localhost:5000/scan", json=payload, timeout=60)
    except Exception as e:
        return {"success": False, "error": f"URL scanner backend unavailable: {str(e)}"}

    try:
        data = response.json()
        vulnerabilities = data.get("data", {}).get("vulnerabilities", []) if isinstance(data, dict) else []
        for vuln in vulnerabilities:
            title = vuln.get("title", "Detected security threat")
            vuln["educational_explanation"] = agents.educational_explainer_agent(title, str(payload.get("url", "")))
            vuln["agentic_explainer"] = agents.generate_scan_explainer(
                threat_type=title,
                target=str(payload.get("url", "")),
                risk_score={"low": 30, "medium": 65, "high": 90}.get(data.get("data", {}).get("risk_level", "low").lower(), 30),
                indicators=[title],
            )            
        return data
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
    return _read_template("tools", "text_qr_analyzer", "templates", "qr_scanner.html")

@app.get("/text-analyzer", response_class=HTMLResponse)
def text_analyzer_page():
    return _read_template("tools", "text_qr_analyzer", "templates", "my_dashboard.html")

@app.get("/educational-explainer", response_class=HTMLResponse)
def educational_explainer_page():
    return _read_template("tools", "text_qr_analyzer", "educational_explainer.html")

from fastapi import Body

@app.post("/educational-explainer/analyze-text")
def analyze_text(data: dict = Body(...)):

    text = data.get("scan_text", "").lower()

    # simple threat detection
    if "login" in text or "password" in text:
        threat = "Phishing"
    elif "urgent" in text or "verify" in text:
        threat = "Scam Message"
    else:
        threat = "Suspicious Content"

    return {
        "title": f"{threat} Detected",
        "whats_wrong": "The message contains patterns commonly used in scams.",
        "what_would_happen": "Attackers may try to steal your personal or login information.",
        "what_to_do": "Do not click links or share sensitive data.",
        "tip": "Always verify the sender before responding."
    }

@app.post("/analyze-text")
async def analyze_text(request: Request):
    payload = await request.json()
    text = payload.get("text", "") if isinstance(payload, dict) else ""
    if not text.strip():
        return {"risk_score": 0, "category": "safe message", "explanation": ["No text provided"], "educational_explanations": []}
    analysis = _text_risk_analysis(text)
    threats = [item for item in analysis.get("explanation", []) if "No obvious" not in item]
    analysis["educational_explanations"] = _build_educational_explanations(threats, text)
    return analysis

@app.post("/scan-qr")
async def scan_qr(file: UploadFile = File(...)):
    try:
        data = await file.read()
        files = {"file": (file.filename or "qr.png", data, file.content_type or "application/octet-stream")}
        response = requests.post("http://localhost:8002/scan-qr", files=files, timeout=60)
        data = response.json()
        threats = [item for item in data.get("explanation", []) if "no" not in item.lower()]
        data["educational_explanations"] = _build_educational_explanations(threats, file.filename or "")
        data["agentic_explainer"] = agents.generate_scan_explainer(
            threat_type=str(data.get("category", "Suspicious QR")),
            target=file.filename or "QR code",
            risk_score=int(round(float(data.get("risk_score", 0)) * 100)) if isinstance(data.get("risk_score", 0), (int, float)) else 0,
            indicators=threats,
        )
        return data
    except Exception:
        return {
            "risk_score": 0,
            "category": "unavailable",
            "explanation": ["QR analyzer service is not running on localhost:8002"],
            "educational_explanations": [],
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
    medium = len([l for l in logs if l.risk_level == "medium"])
    low = len([l for l in logs if l.risk_level == "low"])

    html = _read_template("admin_analysis.html")
    html = html.replace("{{total_scans}}", str(len(logs)))
    html = html.replace("{{high}}", str(high))
    html = html.replace("{{medium}}", str(medium))
    html = html.replace("{{low}}", str(low))

    return HTMLResponse(html)

@app.get("/admin/users", response_class=HTMLResponse)
def manage_users(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        return RedirectResponse("/login", status_code=303)

    users = db.query(models.User).all()

    rows = ""
    for u in users:
        rows += (
            f"<tr>"
            f"<td>{u.id}</td>"
            f"<td>{u.username}</td>"
            f"<td>{u.email}</td>"
            f"<td>{u.role}</td>"
            f"<td>{u.risk_score}</td>"
            f"</tr>"
        )

    html += "<a href='/admin'>Back</a>"
    return HTMLResponse(html)