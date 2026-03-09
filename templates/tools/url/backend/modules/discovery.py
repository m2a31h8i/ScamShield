"""
backend/modules/discovery.py
Handles technology detection, SSL checking, header analysis, and port probing.
"""

import re
import ssl
import socket
import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


# ─────────────────────────────────────────────
# Request helper
# ─────────────────────────────────────────────

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

TIMEOUT = 10


def _fetch(url: str) -> tuple[requests.Response | None, str | None]:
    """
    Perform a GET request.
    Returns (response, error_message).
    """
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=True, allow_redirects=True)
        return resp, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL Error: {e}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection Error: {e}"
    except requests.exceptions.Timeout:
        return None, "Request timed out."
    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────────
# Technology fingerprints
# ─────────────────────────────────────────────

# Map of technology name → list of (location, pattern) tuples
# location: "header:<name>", "body", "meta", "script_src", "link_href"
FINGERPRINTS: dict[str, dict] = {
    # CMS
    "WordPress": {
        "body": [r"wp-content/", r"wp-includes/", r"/wp-json/"],
        "meta_generator": [r"WordPress"],
    },
    "Joomla": {
        "body": [r"/components/com_", r"Joomla!"],
        "meta_generator": [r"Joomla"],
    },
    "Drupal": {
        "body": [r"/sites/default/files/", r"Drupal\.settings"],
        "header_x-generator": [r"Drupal"],
    },
    "Shopify": {
        "body": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    },
    "Wix": {
        "body": [r"static\.wixstatic\.com", r"wix-warmup-data"],
    },
    "Squarespace": {
        "body": [r"squarespace\.com", r"static1\.squarespace\.com"],
    },
    "Magento": {
        "body": [r"Mage\.Cookies", r"/skin/frontend/"],
    },
    # Frontend Frameworks
    "React": {
        "body": [r"react\.development\.js", r"react\.production\.min\.js",
                r"__reactFiber", r"__REACT_DEVTOOLS"],
        "script_src": [r"react(\.min)?\.js", r"react-dom"],
    },
    "Vue.js": {
        "body": [r"vue\.js", r"vue\.min\.js", r"__vue__", r"data-v-"],
        "script_src": [r"vue(\.min)?\.js"],
    },
    "Angular": {
        "body": [r"ng-version=", r"angular\.js", r"angular\.min\.js"],
        "script_src": [r"angular(\.min)?\.js"],
    },
    "Next.js": {
        "body": [r"__NEXT_DATA__", r"/_next/static/"],
    },
    "Nuxt.js": {
        "body": [r"__nuxt", r"/_nuxt/"],
    },
    "jQuery": {
        "script_src": [r"jquery(\.min)?\.js", r"jquery-\d"],
        "body": [r"jquery\.min\.js"],
    },
    "Bootstrap": {
        "link_href": [r"bootstrap(\.min)?\.css"],
        "script_src": [r"bootstrap(\.min)?\.js"],
    },
    "Tailwind CSS": {
        "body": [r"tailwindcss", r"class=\"[^\"]*\b(flex|grid|px-|py-|text-|bg-)"],
    },
    # Servers (via response headers)
    "Apache": {
        "header_server": [r"Apache"],
    },
    "Nginx": {
        "header_server": [r"nginx"],
    },
    "IIS": {
        "header_server": [r"Microsoft-IIS"],
    },
    "LiteSpeed": {
        "header_server": [r"LiteSpeed"],
    },
    "Cloudflare": {
        "header_server": [r"cloudflare"],
        "header_cf-ray": [r".+"],
    },
    # Analytics / Marketing
    "Google Analytics": {
        "body": [r"google-analytics\.com/analytics\.js",
                r"gtag\(", r"UA-\d{4,}-\d+", r"G-[A-Z0-9]+"],
    },
    "Google Tag Manager": {
        "body": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
    },
    "Hotjar": {
        "body": [r"static\.hotjar\.com", r"hjSiteSettings"],
    },
    "Intercom": {
        "body": [r"widget\.intercom\.io", r"intercomSettings"],
    },
    # CDN
    "Cloudfront": {
        "header_x-amz-cf-id": [r".+"],
        "header_via": [r"CloudFront"],
    },
    "Fastly": {
        "header_x-served-by": [r"cache-"],
        "header_fastly-restarts": [r".+"],
    },
    "jsDelivr": {
        "script_src": [r"cdn\.jsdelivr\.net"],
    },
    # Languages / Backends (heuristic)
    "PHP": {
        "header_x-powered-by": [r"PHP"],
        "body": [r"\.php[\"'\s?#]", r"PHPSESSID"],
    },
    "Python": {
        "header_x-powered-by": [r"Python", r"Flask", r"Django", r"FastAPI"],
        "header_server": [r"Werkzeug", r"uvicorn", r"gunicorn"],
    },
    "Ruby on Rails": {
        "header_x-powered-by": [r"Phusion Passenger"],
        "header_server": [r"Phusion Passenger"],
    },
    "Node.js": {
        "header_x-powered-by": [r"Express"],
        "header_server": [r"Node\.js"],
    },
    "ASP.NET": {
        "header_x-powered-by": [r"ASP\.NET"],
        "header_x-aspnet-version": [r".+"],
    },
}

TECHNOLOGY_CATEGORIES = {
    "CMS": ["WordPress", "Joomla", "Drupal", "Shopify", "Wix",
            "Squarespace", "Magento"],
    "Frontend Framework": ["React", "Vue.js", "Angular", "Next.js",
                        "Nuxt.js", "jQuery", "Bootstrap", "Tailwind CSS"],
    "Server": ["Apache", "Nginx", "IIS", "LiteSpeed", "Cloudflare"],
    "Analytics": ["Google Analytics", "Google Tag Manager", "Hotjar", "Intercom"],
    "CDN": ["Cloudfront", "Fastly", "jsDelivr", "Cloudflare"],
    "Backend Language": ["PHP", "Python", "Ruby on Rails", "Node.js", "ASP.NET"],
}


def detect_technologies(url: str) -> dict:
    """
    Fetch the page and match fingerprints against headers + HTML body.
    Returns a categorised dict: { category: [tech, ...], ... }
    """
    resp, err = _fetch(url)
    if err or resp is None:
        return {"error": err or "No response"}

    soup = BeautifulSoup(resp.text, "lxml")
    body_text = resp.text
    headers = {k.lower(): v for k, v in resp.headers.items()}

    # Collect script srcs and link hrefs for pattern matching
    script_srcs = " ".join(
        s.get("src", "") for s in soup.find_all("script") if s.get("src")
    )
    link_hrefs = " ".join(
        l.get("href", "") for l in soup.find_all("link") if l.get("href")
    )
    meta_generator = ""
    gen_tag = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    if gen_tag:
        meta_generator = gen_tag.get("content", "")

    detected: set[str] = set()

    for tech, rules in FINGERPRINTS.items():
        for location, patterns in rules.items():
            matched = False
            for pattern in patterns:
                if location == "body":
                    if re.search(pattern, body_text, re.I):
                        matched = True
                elif location == "script_src":
                    if re.search(pattern, script_srcs, re.I):
                        matched = True
                elif location == "link_href":
                    if re.search(pattern, link_hrefs, re.I):
                        matched = True
                elif location == "meta_generator":
                    if re.search(pattern, meta_generator, re.I):
                        matched = True
                elif location.startswith("header_"):
                    header_name = location[len("header_"):]
                    header_val = headers.get(header_name, "")
                    if re.search(pattern, header_val, re.I):
                        matched = True
                if matched:
                    break
            if matched:
                detected.add(tech)
                break

    # Organise into categories
    categorised: dict[str, list[str]] = {cat: [] for cat in TECHNOLOGY_CATEGORIES}
    categorised["Other"] = []

    for tech in detected:
        placed = False
        for cat, members in TECHNOLOGY_CATEGORIES.items():
            if tech in members:
                categorised[cat].append(tech)
                placed = True
                break
        if not placed:
            categorised["Other"].append(tech)

    # Remove empty categories
    return {k: v for k, v in categorised.items() if v}


# ─────────────────────────────────────────────
# SSL Certificate Check
# ─────────────────────────────────────────────

def check_ssl(url: str) -> dict:
    """
    Verify SSL certificate validity, expiry, and issuer for the given URL.
    Returns a dict with ssl_valid, issuer, expiry_date, days_remaining, error.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443

    result = {
        "ssl_valid": False,
        "issuer": None,
        "subject": None,
        "expiry_date": None,
        "days_remaining": None,
        "protocol": None,
        "error": None,
    }

    if parsed.scheme != "https":
        result["error"] = "Site does not use HTTPS."
        return result

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=TIMEOUT),
            server_hostname=hostname,
        ) as ssock:
            cert = ssock.getpeercert()
            result["protocol"] = ssock.version()

            # Parse expiry
            expiry_str = cert.get("notAfter", "")
            if expiry_str:
                expiry_dt = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                result["expiry_date"] = expiry_dt.strftime("%Y-%m-%d")
                result["days_remaining"] = (expiry_dt - datetime.datetime.utcnow()).days

            # Issuer
            issuer_dict = {item[0][0]: item[0][1] for item in cert.get("issuer", [])}
            result["issuer"] = issuer_dict.get("organizationName", "Unknown")

            # Subject
            subj_dict = {item[0][0]: item[0][1] for item in cert.get("subject", [])}
            result["subject"] = subj_dict.get("commonName", hostname)

            result["ssl_valid"] = True

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "SSL check timed out."
    except Exception as e:
        result["error"] = str(e)

    return result


# ─────────────────────────────────────────────
# Security Headers Analysis
# ─────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS).",
        "severity": "High",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks.",
        "severity": "High",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks.",
        "severity": "Medium",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing.",
        "severity": "Medium",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information in requests.",
        "severity": "Low",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access (camera, mic, etc.).",
        "severity": "Low",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still useful).",
        "severity": "Low",
    },
    "Cache-Control": {
        "description": "Controls caching behaviour for sensitive pages.",
        "severity": "Low",
    },
}


def check_security_headers(url: str) -> dict:
    """
    Check which recommended security headers are present or missing.
    Returns { present: [...], missing: [...] }
    """
    resp, err = _fetch(url)
    if err or resp is None:
        return {"error": err or "No response", "present": [], "missing": []}

    headers = {k.lower(): v for k, v in resp.headers.items()}

    present = []
    missing = []

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() in headers:
            present.append({
                "name": header,
                "value": headers[header.lower()],
                "description": meta["description"],
                "severity": meta["severity"],
            })
        else:
            missing.append({
                "name": header,
                "description": meta["description"],
                "severity": meta["severity"],
            })

    # Also flag exposed server/technology headers
    exposed = []
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if h in headers:
            exposed.append({"name": h, "value": headers[h]})

    return {
        "present": present,
        "missing": missing,
        "exposed_headers": exposed,
        "raw_headers": dict(resp.headers),
    }


# ─────────────────────────────────────────────
# Port Scanner (safe, limited subset)
# ─────────────────────────────────────────────

COMMON_PORTS = {
    21:  "FTP",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    53:  "DNS",
    80:  "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

RISKY_PORTS = {21, 23, 25, 445, 3306, 3389, 5432, 6379, 27017}


def scan_ports(hostname: str, timeout: float = 1.0) -> dict:
    """
    Probe a limited set of common ports via TCP connect.
    Returns { open: [...], closed: [...], risky_open: [...] }
    """
    open_ports = []
    closed_ports = []

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((hostname, port))
            sock.close()
            info = {"port": port, "service": service, "risky": port in RISKY_PORTS}
            if result == 0:
                open_ports.append(info)
            else:
                closed_ports.append(info)
        except Exception:
            closed_ports.append({"port": port, "service": service, "risky": False})

    risky_open = [p for p in open_ports if p["risky"]]

    return {
        "open": open_ports,
        "closed": closed_ports,
        "risky_open": risky_open,
        "total_scanned": len(COMMON_PORTS),
    }