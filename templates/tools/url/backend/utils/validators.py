"""
backend/utils/validators.py
URL validation and sanitisation helpers.
"""

import re
from urllib.parse import urlparse


def validate_url(url):
    """
    Validate and normalise a URL.
    Returns (is_valid, normalised_url, error_message).
    """
    if not url or not isinstance(url, str):
        return False, "", "URL must be a non-empty string."

    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "", "Could not parse the URL."

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        return False, "", "URL scheme must be http or https."

    if not parsed.netloc:
        return False, "", "URL must contain a valid hostname."

    hostname = parsed.hostname or ""

    # Block localhost / private ranges
    blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if hostname in blocked_hosts:
        return False, "", "Scanning localhost or loopback addresses is not allowed."

    # Basic hostname format check
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    if not hostname_re.match(hostname) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        return False, "", f"Invalid hostname: '{hostname}'."

    return True, url, ""