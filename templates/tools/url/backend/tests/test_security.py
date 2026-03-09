"""
tests/test_security.py
======================
Unit tests for the SecurityAnalyzer module.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.security import SecurityAnalyzer


def _make_tech(**overrides):
    base = {
        "cms": [],
        "frontend_frameworks": [],
        "backend_technologies": [],
        "server": [],
        "cdn": [],
        "ssl": {"has_ssl": True, "valid": True, "days_remaining": 90},
        "open_ports": [],
        "headers": {},
        "raw_headers": {},
    }
    base.update(overrides)
    return base


def test_http_raises_score():
    sec = SecurityAnalyzer()
    tech = _make_tech(ssl={"has_ssl": False})
    result = sec.analyze("http://example.com", tech)
    assert result["risk_score"] >= 25
    assert len(result["protocol_issues"]) == 1


def test_https_no_protocol_issue():
    sec = SecurityAnalyzer()
    tech = _make_tech()
    result = sec.analyze("https://example.com", tech)
    assert result["protocol_issues"] == []


def test_missing_all_headers_high_risk():
    sec = SecurityAnalyzer()
    tech = _make_tech()
    result = sec.analyze("https://example.com", tech)
    # All headers missing → score should be significant
    assert result["risk_score"] > 30


def test_all_headers_present_lowers_score():
    sec = SecurityAnalyzer()
    all_headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
        "X-XSS-Protection": "1; mode=block",
    }
    tech = _make_tech(headers=all_headers)
    result = sec.analyze("https://example.com", tech)
    assert result["missing_headers"] == []


def test_risky_port_detected():
    sec = SecurityAnalyzer()
    tech = _make_tech(open_ports=[{"port": 23, "service": "Telnet", "state": "open"}])
    result = sec.analyze("https://example.com", tech)
    assert len(result["open_port_risks"]) == 1
    assert result["open_port_risks"][0]["severity"] == "High"


def test_server_info_leakage():
    sec = SecurityAnalyzer()
    tech = _make_tech(raw_headers={"Server": "Apache/2.4.51", "X-Powered-By": "PHP/8.1"})
    result = sec.analyze("https://example.com", tech)
    assert result["server_info_exposed"] is True


def test_risk_levels():
    sec = SecurityAnalyzer()
    for url, min_score, expected_level in [
        ("https://example.com", 0, None),   # depends on headers
    ]:
        result = sec.analyze(url, _make_tech())
        assert result["risk_level"] in ["Low", "Medium", "High"]