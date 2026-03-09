"""
modules/scanner.py
==================
Discovery Module — detects technologies used by a target website.

Detection methods:
• HTTP response headers  (Server, X-Powered-By, …)
• HTML meta tags & script src attributes
• Cookie names
• builtwith library
• SSL certificate inspection
• Basic open-port fingerprinting (via socket)
"""

import re
import ssl
import socket
import datetime
import logging
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ── Signature databases ────────────────────────────────────────────────────────

CMS_SIGNATURES = {
    "WordPress": [
        r"/wp-content/", r"/wp-includes/", r"wp-json", r"WordPress",
        r"<meta name=\"generator\" content=\"WordPress",
    ],
    "Joomla": [
        r"/components/com_", r"Joomla!", r"/media/jui/", r"generator.*Joomla",
    ],
    "Drupal": [
        r"Drupal.settings", r"/sites/default/files/", r"X-Generator.*Drupal",
        r"<meta name=\"Generator\" content=\"Drupal",
    ],
    "Magento": [
        r"Mage.Cookies", r"/skin/frontend/", r"Magento",
    ],
    "Shopify": [
        r"cdn.shopify.com", r"Shopify.theme", r"myshopify.com",
    ],
    "Wix": [
        r"static.wixstatic.com", r"X-Wix-", r"wix-warmup-data",
    ],
    "Squarespace": [
        r"squarespace.com", r"static1.squarespace.com",
    ],
    "Ghost": [
        r"/ghost/", r"ghost.io", r"content=\"Ghost",
    ],
    "Django": [
        r"csrfmiddlewaretoken", r"__admin_media_prefix__", r"djdt",
    ],
    "Laravel": [
        r"laravel_session", r"XSRF-TOKEN.*laravel",
    ],
}

FRONTEND_SIGNATURES = {
    "React":         [r"react\.min\.js", r"react-dom", r"_reactFiber", r"__REACT_DEVTOOLS"],
    "Vue.js":        [r"vue\.min\.js", r"vue\.js", r"__vue__", r"v-cloak"],
    "Angular":       [r"angular\.min\.js", r"ng-version", r"ng-app", r"angular/core"],
    "jQuery":        [r"jquery\.min\.js", r"jquery\.js", r"jQuery v"],
    "Bootstrap":     [r"bootstrap\.min\.css", r"bootstrap\.css", r"bootstrap\.min\.js"],
    "Tailwind CSS":  [r"tailwindcss", r"tailwind\.css"],
    "Next.js":       [r"_next/static", r"__NEXT_DATA__"],
    "Nuxt.js":       [r"__nuxt", r"_nuxt/"],
    "Ember.js":      [r"ember\.min\.js", r"Ember.Application"],
    "Svelte":        [r"__svelte", r"svelte-"],
    "Alpine.js":     [r"alpinejs", r"x-data=", r"x-bind="],
    "HTMX":          [r"htmx\.min\.js", r"hx-get=", r"hx-post="],
    "Three.js":      [r"three\.min\.js", r"THREE\.WebGLRenderer"],
}

SERVER_SIGNATURES = {
    "Apache":    [r"Apache", r"Apache/"],
    "Nginx":     [r"nginx", r"openresty"],
    "IIS":       [r"Microsoft-IIS", r"IIS/"],
    "LiteSpeed": [r"LiteSpeed", r"ls-"],
    "Caddy":     [r"Caddy"],
    "Cloudflare": [r"cloudflare"],
    "Vercel":    [r"Vercel", r"x-vercel-"],
    "Netlify":   [r"Netlify", r"x-nf-"],
}

CDN_SIGNATURES = {
    "Cloudflare":   [r"cf-ray", r"cloudflare", r"__cfduid"],
    "AWS CloudFront": [r"x-amz-cf-", r"cloudfront\.net"],
    "Fastly":       [r"x-served-by.*cache", r"fastly"],
    "Akamai":       [r"akamai", r"akamainetworks"],
    "jsDelivr":     [r"cdn\.jsdelivr\.net"],
    "Bunny CDN":    [r"b-cdn\.net"],
}

ANALYTICS_SIGNATURES = {
    "Google Analytics":    [r"google-analytics\.com", r"gtag\(", r"ga\.js"],
    "Google Tag Manager":  [r"googletagmanager\.com", r"gtm\.js"],
    "Matomo":              [r"matomo\.js", r"piwik\.js"],
    "Hotjar":              [r"hotjar\.com", r"hjid"],
    "Mixpanel":            [r"mixpanel\.com", r"mixpanel\.init"],
    "Segment":             [r"segment\.com", r"analytics\.js"],
    "Facebook Pixel":      [r"connect\.facebook\.net", r"fbq\("],
    "Heap":                [r"heap\.io", r"heap\.load"],
    "Amplitude":           [r"amplitude\.com"],
    "Plausible":           [r"plausible\.io"],
}

BACKEND_SIGNATURES = {
    "PHP":        [r"X-Powered-By.*PHP", r"\.php", r"PHPSESSID"],
    "Python":     [r"X-Powered-By.*Python", r"Django", r"Flask", r"Gunicorn", r"Werkzeug"],
    "Node.js":    [r"X-Powered-By.*Express", r"X-Powered-By.*Node"],
    "Ruby":       [r"X-Powered-By.*Phusion Passenger", r"X-Runtime", r"Ruby"],
    "Java":       [r"X-Powered-By.*Servlet", r"JSESSIONID", r"JSF", r"Tomcat"],
    "Go":         [r"X-Powered-By.*Go", r"gorilla"],
    "ASP.NET":    [r"X-Powered-By.*ASP\.NET", r"__VIEWSTATE", r"\.aspx"],
    "ColdFusion": [r"CFID=", r"CFTOKEN=", r"ColdFusion"],
}

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


class TechScanner:
    """Orchestrates all technology detection sub-tasks."""

    TIMEOUT = 10  # seconds for HTTP requests

    def scan(self, url: str) -> dict:
        """
        Main scan entry-point.
        Returns a structured dict of discovered technologies.
        """
        result: dict = {
            "url": url,
            "scanned_at": datetime.datetime.utcnow().isoformat() + "Z",
            "reachable": False,
            "http_status": None,
            "protocol": "https" if url.startswith("https") else "http",
            "cms": [],
            "frontend_frameworks": [],
            "backend_technologies": [],
            "server": [],
            "cdn": [],
            "analytics": [],
            "ssl": {},
            "open_ports": [],
            "headers": {},
            "raw_headers": {},
        }

        # ── Fetch page ────────────────────────────────────────────────────────
        response, html = self._fetch(url)
        if response is None:
            logger.warning(f"Could not reach {url}")
            return result

        result["reachable"]    = True
        result["http_status"]  = response.status_code
        result["raw_headers"]  = dict(response.headers)
        result["headers"]      = self._parse_notable_headers(response.headers)

        soup = BeautifulSoup(html, "html.parser")

        # ── Run detectors ─────────────────────────────────────────────────────
        result["cms"]                  = self._detect(html, response, CMS_SIGNATURES)
        result["frontend_frameworks"]  = self._detect(html, response, FRONTEND_SIGNATURES)
        result["backend_technologies"] = self._detect(html, response, BACKEND_SIGNATURES)
        result["server"]               = self._detect(html, response, SERVER_SIGNATURES)
        result["cdn"]                  = self._detect(html, response, CDN_SIGNATURES)
        result["analytics"]            = self._detect(html, response, ANALYTICS_SIGNATURES)

        # ── Extras ────────────────────────────────────────────────────────────
        result["ssl"]        = self._check_ssl(url)
        result["open_ports"] = self._scan_ports(url)
        result["meta_info"]  = self._extract_meta(soup)

        return result

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _fetch(self, url: str):
        """Fetch URL, return (response, html) or (None, None) on failure."""
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }
        try:
            resp = requests.get(url, headers=headers, timeout=self.TIMEOUT,
                                verify=False, allow_redirects=True)
            return resp, resp.text
        except requests.exceptions.SSLError:
            # Retry without SSL verification (already False but handle cert errors)
            try:
                resp = requests.get(url, headers=headers, timeout=self.TIMEOUT,
                                    verify=False, allow_redirects=True)
                return resp, resp.text
            except Exception as e:
                logger.error(f"Fetch error (SSL retry): {e}")
                return None, None
        except Exception as e:
            logger.error(f"Fetch error: {e}")
            return None, None

    def _detect(self, html: str, response, signatures: dict) -> list:
        """Match signatures against combined headers + html string."""
        combined = html + "\n" + "\n".join(
            f"{k}: {v}" for k, v in response.headers.items()
        )
        found = []
        for tech, patterns in signatures.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    if tech not in found:
                        found.append(tech)
                    break
        return found

    def _parse_notable_headers(self, headers) -> dict:
        """Extract security-relevant headers."""
        notable = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Feature-Policy",
            "Cache-Control",
            "Server",
            "X-Powered-By",
        ]
        return {h: headers.get(h) for h in notable if headers.get(h)}

    def _check_ssl(self, url: str) -> dict:
        """Inspect SSL/TLS certificate details."""
        ssl_info: dict = {
            "has_ssl": url.startswith("https"),
            "valid": False,
            "expired": False,
            "issuer": None,
            "subject": None,
            "expires_on": None,
            "days_remaining": None,
            "version": None,
            "error": None,
        }

        if not ssl_info["has_ssl"]:
            return ssl_info

        parsed = urlparse(url)
        hostname = parsed.hostname
        port     = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((hostname, port), timeout=self.TIMEOUT),
                server_hostname=hostname
            ) as s:
                cert = s.getpeercert()
                ssl_info["version"] = s.version()

                # Subject
                subject = dict(x[0] for x in cert.get("subject", []))
                ssl_info["subject"] = subject.get("commonName")

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", []))
                ssl_info["issuer"] = issuer.get("organizationName")

                # Expiry
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    ssl_info["expires_on"]    = expiry.isoformat() + "Z"
                    ssl_info["days_remaining"] = (expiry - datetime.datetime.utcnow()).days
                    ssl_info["expired"]        = ssl_info["days_remaining"] < 0
                    ssl_info["valid"]          = not ssl_info["expired"]

        except ssl.SSLCertVerificationError as e:
            ssl_info["error"] = f"Certificate verification failed: {e}"
        except socket.timeout:
            ssl_info["error"] = "Connection timed out"
        except Exception as e:
            ssl_info["error"] = str(e)

        return ssl_info

    def _scan_ports(self, url: str, timeout: float = 0.5) -> list:
        """
        Lightweight port scan using raw sockets.
        Checks a curated list of common ports.
        """
        parsed   = urlparse(url)
        hostname = parsed.hostname
        open_ports = []

        # Only scan a safe subset to avoid being too slow or flagged
        ports_to_check = [21, 22, 23, 25, 53, 80, 110, 143,
                        443, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

        for port in ports_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "service": COMMON_PORTS.get(port, "Unknown"),
                        "state": "open",
                    })
            except Exception:
                pass  # Unreachable host or blocked — expected

        return open_ports

    def _extract_meta(self, soup: BeautifulSoup) -> dict:
        """Pull useful meta info from the HTML head."""
        info: dict = {"title": None, "description": None, "generator": None, "charset": None}

        title_tag = soup.find("title")
        if title_tag:
            info["title"] = title_tag.get_text(strip=True)

        for meta in soup.find_all("meta"):
            name    = (meta.get("name") or "").lower()
            prop    = (meta.get("property") or "").lower()
            content = meta.get("content", "")

            if name == "description" or prop == "og:description":
                info["description"] = content[:300]
            elif name == "generator":
                info["generator"] = content
            elif meta.get("charset"):
                info["charset"] = meta.get("charset")

        return info