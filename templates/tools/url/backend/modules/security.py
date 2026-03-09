"""
backend/modules/security.py
Analyses scan data to produce vulnerability list, recommendations, and overall risk level.
"""


def detect_vulnerabilities(ssl_info, headers_info, ports_info, technologies, url):
    """Return a list of identified vulnerability dicts."""
    vulns = []

    # 1. HTTP instead of HTTPS
    if url.startswith("http://"):
        vulns.append({
            "id": "V001",
            "title": "Site running on HTTP (unencrypted)",
            "description": "All traffic is transmitted in plain text. Attackers on the same network can intercept credentials and session cookies.",
            "severity": "Critical",
            "category": "Transport Security",
        })

    # 2. SSL issues
    if not ssl_info.get("ssl_valid") and url.startswith("https://"):
        vulns.append({
            "id": "V002",
            "title": "Invalid or untrusted SSL certificate",
            "description": ssl_info.get("error", "Certificate could not be verified."),
            "severity": "Critical",
            "category": "Transport Security",
        })

    days_rem = ssl_info.get("days_remaining")
    if days_rem is not None:
        if days_rem <= 0:
            vulns.append({
                "id": "V003",
                "title": "SSL certificate has EXPIRED",
                "description": f"Certificate expired {abs(days_rem)} days ago.",
                "severity": "Critical",
                "category": "Transport Security",
            })
        elif days_rem <= 30:
            vulns.append({
                "id": "V004",
                "title": "SSL certificate expiring soon",
                "description": f"Certificate expires in {days_rem} days.",
                "severity": "High",
                "category": "Transport Security",
            })

    # 3. Missing security headers
    for h in headers_info.get("missing", []):
        sev = h.get("severity", "Low")
        header_id = h['name'].upper().replace('-', '_')
        vulns.append({
            "id": f"V-HDR-{header_id}",
            "title": f"Missing HTTP security header: {h['name']}",
            "description": h.get("description", ""),
            "severity": sev,
            "category": "HTTP Headers",
        })

    # 4. Exposed server/technology headers
    for exp in headers_info.get("exposed_headers", []):
        vulns.append({
            "id": f"V-EXP-{exp['name'].upper().replace('-','_')}",
            "title": f"Server information leaked via '{exp['name']}' header",
            "description": f"Value '{exp['value']}' reveals backend technology.",
            "severity": "Medium",
            "category": "Information Disclosure",
        })

    # 5. Risky open ports
    for p in ports_info.get("risky_open", []):
        vulns.append({
            "id": f"V-PORT-{p['port']}",
            "title": f"Risky port {p['port']} ({p['service']}) is open",
            "description": f"{p['service']} on port {p['port']} should not be publicly accessible.",
            "severity": "High",
            "category": "Network Exposure",
        })

    # 6. CMS security warnings
    cms_list = technologies.get("CMS", [])
    for cms in cms_list:
        if cms in ("WordPress", "Joomla", "Drupal", "Magento"):
            vulns.append({
                "id": f"V-CMS-{cms.upper()}",
                "title": f"{cms} detected – verify it is up to date",
                "description": f"{cms} is a frequent target. Unpatched installations are routinely exploited.",
                "severity": "Medium",
                "category": "CMS Security",
            })

    # 7. Telnet open
    if any(p["port"] == 23 for p in ports_info.get("open", [])):
        vulns.append({
            "id": "V-TELNET",
            "title": "Telnet (port 23) is open",
            "description": "Telnet transmits data in clear text. Replace with SSH immediately.",
            "severity": "Critical",
            "category": "Network Exposure",
        })

    return vulns


def generate_recommendations(vulnerabilities, technologies, url):
    """Map vulnerabilities to actionable recommendations."""
    recs = []
    seen = set()

    rec_map = {
        "V001": {
            "title": "Enable HTTPS / TLS",
            "action": "Obtain a free TLS certificate from Let's Encrypt and redirect all HTTP traffic to HTTPS.",
            "severity": "Critical",
            "effort": "Low",
            "references": ["https://letsencrypt.org/getting-started/"],
        },
        "V002": {
            "title": "Fix or replace the SSL certificate",
            "action": "Verify the certificate chain and renew if expired.",
            "severity": "Critical",
            "effort": "Medium",
            "references": ["https://www.ssllabs.com/ssltest/"],
        },
        "V003": {
            "title": "Renew expired SSL certificate immediately",
            "action": "Use certbot or your hosting provider's control panel to renew.",
            "severity": "Critical",
            "effort": "Low",
            "references": ["https://certbot.eff.org/"],
        },
        "V004": {
            "title": "Renew SSL certificate before it expires",
            "action": "Automate renewal with certbot --renew or a managed certificate service.",
            "severity": "High",
            "effort": "Low",
            "references": ["https://certbot.eff.org/"],
        },
    }

    header_recs = {
        "Strict-Transport-Security": {
            "title": "Add HSTS Header",
            "action": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all responses.",
            "severity": "High", "effort": "Low",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        },
        "Content-Security-Policy": {
            "title": "Implement Content-Security-Policy",
            "action": "Define a strict CSP to restrict resource origins and mitigate XSS.",
            "severity": "High", "effort": "High",
            "references": ["https://content-security-policy.com/"],
        },
        "X-Frame-Options": {
            "title": "Add X-Frame-Options Header",
            "action": "Set `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent clickjacking.",
            "severity": "Medium", "effort": "Low",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
        },
        "X-Content-Type-Options": {
            "title": "Add X-Content-Type-Options Header",
            "action": "Set `X-Content-Type-Options: nosniff` on all responses.",
            "severity": "Medium", "effort": "Low",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
        },
        "Referrer-Policy": {
            "title": "Add Referrer-Policy Header",
            "action": "Set `Referrer-Policy: strict-origin-when-cross-origin`.",
            "severity": "Low", "effort": "Low",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
        },
        "Permissions-Policy": {
            "title": "Add Permissions-Policy Header",
            "action": "Restrict access to browser features like camera, microphone, geolocation.",
            "severity": "Low", "effort": "Low",
            "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
        },
    }

    for vuln in vulnerabilities:
        vid = vuln["id"]
        rec_data = rec_map.get(vid)

        # Check if it's a missing header vulnerability
        if not rec_data and vid.startswith("V-HDR-"):
            for header_name, hrec in header_recs.items():
                if header_name.upper().replace("-", "_") in vid:
                    rec_data = hrec
                    break

        if not rec_data:
            rec_data = {
                "title": f"Remediate: {vuln['title']}",
                "action": vuln.get("description", "Review and address the identified issue."),
                "severity": vuln.get("severity", "Low"),
                "effort": "Medium",
                "references": [],
            }

        if rec_data["title"] not in seen:
            seen.add(rec_data["title"])
            recs.append({**rec_data, "related_vuln": vid})

    # Sort by severity
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recs.sort(key=lambda r: order.get(r.get("severity", "Low"), 4))
    return recs


def calculate_risk_level(vulnerabilities):
    """Aggregate severity into a single risk label."""
    severities = {v.get("severity", "Low") for v in vulnerabilities}
    for level in ("Critical", "High", "Medium", "Low"):
        if level in severities:
            return level
    return "Low"