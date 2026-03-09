"""
tests/test_validators.py
========================
Unit tests for URL validation.
Run with: pytest backend/tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.validators import validate_url


def test_valid_https_url():
    ok, url, err = validate_url("https://example.com")
    assert ok is True
    assert "example.com" in url
    assert err == ""


def test_valid_http_url():
    ok, url, err = validate_url("http://example.com")
    assert ok is True


def test_url_without_scheme():
    """Should auto-prepend https://"""
    ok, url, err = validate_url("example.com")
    assert ok is True
    assert url.startswith("https://")


def test_empty_url():
    ok, url, err = validate_url("")
    assert ok is False
    assert err != ""


def test_localhost_blocked():
    ok, url, err = validate_url("http://localhost")
    assert ok is False
    assert "not allowed" in err.lower()


def test_loopback_blocked():
    ok, url, err = validate_url("http://127.0.0.1")
    assert ok is False


def test_private_ip_blocked():
    ok, url, err = validate_url("http://192.168.1.1")
    assert ok is False


def test_invalid_scheme():
    ok, url, err = validate_url("ftp://example.com")
    assert ok is False