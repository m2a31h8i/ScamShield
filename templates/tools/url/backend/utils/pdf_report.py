"""
backend/utils/pdf_report.py
Generates a PDF scan report using ReportLab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# ── Colour palette ──────────────────────────────
C_BG       = colors.HexColor("#0D1117")
C_GREEN    = colors.HexColor("#00FF88")
C_RED      = colors.HexColor("#FF4444")
C_ORANGE   = colors.HexColor("#FF8800")
C_YELLOW   = colors.HexColor("#FFD700")
C_BLUE     = colors.HexColor("#00AAFF")
C_DGRAY    = colors.HexColor("#161B22")
C_LGRAY    = colors.HexColor("#8B949E")
C_WHITE    = colors.white

SEVERITY_COLORS = {
    "Critical": C_RED,
    "High":     C_ORANGE,
    "Medium":   C_YELLOW,
    "Low":      C_BLUE,
}

RISK_COLORS = {
    "Critical": C_RED,
    "High":     C_ORANGE,
    "Medium":   C_YELLOW,
    "Low":      C_GREEN,
}


def build_report(scan_data: dict) -> bytes:
    """
    Build a PDF report for the given scan data dict.
    Returns raw PDF bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2*cm,
        rightMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    story = []

    # ── Title block ──────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "title", parent=styles["Title"],
        fontSize=22, textColor=C_GREEN, spaceAfter=6,
    )
    sub_style = ParagraphStyle(
        "sub", parent=styles["Normal"],
        fontSize=10, textColor=C_LGRAY, spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "body", parent=styles["Normal"],
        fontSize=9, textColor=colors.black, spaceAfter=4, leading=14,
    )
    h2_style = ParagraphStyle(
        "h2", parent=styles["Heading2"],
        fontSize=13, textColor=C_BLUE, spaceBefore=12, spaceAfter=6,
    )

    story.append(Paragraph("🛡 Web Technology Detector", title_style))
    story.append(Paragraph("Security Scan Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=C_GREEN))
    story.append(Spacer(1, 0.3*cm))

    # Meta info
    meta_data = [
        ["Target URL", scan_data.get("url", "N/A")],
        ["Scan Date",  scan_data.get("scanned_at", "N/A")[:19].replace("T", " ")],
        ["Risk Level", scan_data.get("risk_level", "N/A")],
        ["Report ID",  str(scan_data.get("id", "N/A"))],
    ]
    meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("TEXTCOLOR",   (0,0), (0,-1), C_LGRAY),
        ("TEXTCOLOR",   (1,0), (1,-1), colors.black),
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.4*cm))

    # ── Technologies ────────────────────────────────────────────────
    story.append(Paragraph("Detected Technologies", h2_style))
    techs = scan_data.get("technologies", {})
    if techs:
        tech_rows = [["Category", "Technologies"]]
        for cat, items in techs.items():
            if items:
                tech_rows.append([cat, ", ".join(items)])
        t = Table(tech_rows, colWidths=[5*cm, 12*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,0), C_DGRAY),
            ("TEXTCOLOR",    (0,0),(-1,0), C_GREEN),
            ("FONTNAME",     (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0),(-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("GRID",         (0,0),(-1,-1), 0.4, C_LGRAY),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No technologies detected.", body_style))

    story.append(Spacer(1, 0.4*cm))

    # ── SSL Info ─────────────────────────────────────────────────────
    story.append(Paragraph("SSL / TLS Certificate", h2_style))
    ssl = scan_data.get("ssl_info", {})
    ssl_rows = [
        ["Valid",         "✓ Yes" if ssl.get("ssl_valid") else "✗ No"],
        ["Issuer",        ssl.get("issuer") or "N/A"],
        ["Expiry Date",   ssl.get("expiry_date") or "N/A"],
        ["Days Remaining",str(ssl.get("days_remaining") or "N/A")],
        ["Protocol",      ssl.get("protocol") or "N/A"],
        ["Error",         ssl.get("error") or "None"],
    ]
    ssl_table = Table(ssl_rows, colWidths=[5*cm, 12*cm])
    ssl_table.setStyle(TableStyle([
        ("FONTSIZE",     (0,0),(-1,-1), 9),
        ("FONTNAME",     (0,0),(0,-1), "Helvetica-Bold"),
        ("TEXTCOLOR",    (0,0),(0,-1), C_LGRAY),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("GRID",         (0,0),(-1,-1), 0.4, C_LGRAY),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
    ]))
    story.append(ssl_table)
    story.append(Spacer(1, 0.4*cm))

    # ── Vulnerabilities ──────────────────────────────────────────────
    story.append(Paragraph("Identified Vulnerabilities", h2_style))
    vulns = scan_data.get("vulnerabilities", [])
    if vulns:
        v_rows = [["Severity", "Title", "Category"]]
        for v in vulns:
            v_rows.append([v.get("severity","?"), v.get("title",""), v.get("category","")])
        vt = Table(v_rows, colWidths=[2.5*cm, 10*cm, 4.5*cm])
        vt.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,0), C_DGRAY),
            ("TEXTCOLOR",    (0,0),(-1,0), C_GREEN),
            ("FONTNAME",     (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0),(-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, colors.HexColor("#FFF8F8")]),
            ("GRID",         (0,0),(-1,-1), 0.4, C_LGRAY),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ]))
        story.append(vt)
    else:
        story.append(Paragraph("No vulnerabilities found.", body_style))

    story.append(Spacer(1, 0.4*cm))

    # ── Recommendations ──────────────────────────────────────────────
    story.append(Paragraph("Security Recommendations", h2_style))
    recs = scan_data.get("recommendations", [])
    for i, rec in enumerate(recs, 1):
        sev_color = SEVERITY_COLORS.get(rec.get("severity","Low"), C_BLUE)
        story.append(Paragraph(
            f'<font color="#0066CC"><b>{i}. {rec.get("title","")}</b></font> '
            f'[{rec.get("severity","")} | Effort: {rec.get("effort","")}]',
            body_style,
        ))
        story.append(Paragraph(rec.get("action",""), body_style))
        refs = rec.get("references", [])
        if refs:
            story.append(Paragraph(f'<font color="#888888">Ref: {refs[0]}</font>', body_style))
        story.append(Spacer(1, 0.15*cm))

    # ── Footer ───────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_LGRAY))
    story.append(Paragraph(
        f'Generated by Web Technology Detector · {datetime.utcnow().strftime("%Y-%m-%d %H:%M")} UTC',
        ParagraphStyle("footer", parent=styles["Normal"], fontSize=7, textColor=C_LGRAY, alignment=TA_CENTER),
    ))

    doc.build(story)
    return buffer.getvalue()