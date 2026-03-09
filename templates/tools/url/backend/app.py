"""
backend/app.py
Flask API server – entry point for the Web Technology Detector backend.

Endpoints:
POST /scan          – Run a full scan on a URL
GET  /history       – List all past scans
GET  /report/<id>   – Download PDF report for a scan
GET  /scan/<id>     – Get full JSON data for a single scan
"""

import sys
import os

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, request, jsonify, send_file, abort

import io

from db import init_db, save_scan, get_all_scans, get_scan_by_id, delete_scan
from backend.modules.discovery import (
    detect_technologies, check_ssl, check_security_headers, scan_ports
)
from backend.modules.security import (
    detect_vulnerabilities, generate_recommendations, calculate_risk_level
)
from backend.utils.validators import validate_url
from backend.utils.pdf_report import build_report
from urllib.parse import urlparse

# ── App setup ────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="../frontend/templates",
            static_folder="../frontend/static")


# Initialise DB on startup
init_db()


# ── Helper ───────────────────────────────────────────────────────────

def _json_error(message: str, code: int = 400):
    return jsonify({"success": False, "error": message}), code


# ── Routes ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the frontend HTML."""
    from flask import send_from_directory
    return send_from_directory("../frontend/templates", "index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    POST /scan
    Body: { "url": "https://example.com" }
    Returns a full scan result JSON.
    """
    data = request.get_json(silent=True)
    if not data:
        return _json_error("Request body must be JSON.")

    raw_url = data.get("url", "").strip()
    is_valid, url, err = validate_url(raw_url)
    if not is_valid:
        return _json_error(f"Invalid URL: {err}")

    hostname = urlparse(url).hostname or ""

    # ── Run scan modules ─────────────────────────────────────────────
    try:
        technologies = detect_technologies(url)
    except Exception as e:
        technologies = {"error": str(e)}

    try:
        ssl_info = check_ssl(url)
    except Exception as e:
        ssl_info = {"error": str(e), "ssl_valid": False}

    try:
        headers_info = check_security_headers(url)
    except Exception as e:
        headers_info = {"error": str(e), "present": [], "missing": [], "exposed_headers": []}

    try:
        ports_info = scan_ports(hostname)
    except Exception as e:
        ports_info = {"error": str(e), "open": [], "risky_open": []}

    # ── Derive security posture ──────────────────────────────────────
    vulnerabilities = detect_vulnerabilities(ssl_info, headers_info, ports_info, technologies, url)
    recommendations = generate_recommendations(vulnerabilities, technologies, url)
    risk_level      = calculate_risk_level(vulnerabilities)

    result = {
        "url":             url,
        "risk_level":      risk_level,
        "technologies":    technologies,
        "ssl_info":        ssl_info,
        "headers_info":    headers_info,
        "ports_info":      ports_info,
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations,
    }

    # ── Persist & return ─────────────────────────────────────────────
    scan_id = save_scan(url, result)
    result["id"] = scan_id

    return jsonify({"success": True, "data": result})


@app.route("/history", methods=["GET"])
def history():
    """
    GET /history
    Returns a list of past scans (lightweight, no JSON blobs).
    """
    scans = get_all_scans()
    return jsonify({"success": True, "data": scans})


@app.route("/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    """
    GET /scan/<id>
    Returns full scan data for the given id.
    """
    scan = get_scan_by_id(scan_id)
    if scan is None:
        return _json_error("Scan not found.", 404)
    return jsonify({"success": True, "data": scan})


@app.route("/report/<int:scan_id>", methods=["GET"])
def download_report(scan_id: int):
    """
    GET /report/<id>
    Streams a PDF report for the given scan.
    """
    scan = get_scan_by_id(scan_id)
    if scan is None:
        return _json_error("Scan not found.", 404)

    try:
        pdf_bytes = build_report(scan)
    except Exception as e:
        return _json_error(f"Failed to generate PDF: {e}", 500)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"scan_report_{scan_id}.pdf",
    )


@app.route("/delete/<int:scan_id>", methods=["DELETE"])
def delete_scan_endpoint(scan_id: int):
    """
    DELETE /delete/<id>
    Deletes a scan record.
    """
    if delete_scan(scan_id):
        return jsonify({"success": True, "message": "Scan deleted."})
    else:
        return _json_error("Scan not found.", 404)


# ── Main ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
    return response