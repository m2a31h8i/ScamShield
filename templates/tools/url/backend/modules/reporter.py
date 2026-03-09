"""
modules/reporter.py
===================
Report Generator — creates PDF scan reports using ReportLab.
Falls back to a plain HTML file if ReportLab is not installed.
"""

import os
import json
import logging
import datetime
import tempfile

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates downloadable scan reports."""

    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "../../reports")

    def __init__(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

    def generate_pdf(self, scan_record: dict) -> str:
        """
        Build a PDF report for the given scan record.
        Returns the file path to the generated PDF.
        """
        try:
            return self._build_pdf_reportlab(scan_record)
        except ImportError:
            logger.warning("ReportLab not installed — falling back to HTML report.")
            return self._build_html_report(scan_record)

    # ── ReportLab PDF ─────────────────────────────────────────────────────────

    def _build_pdf_reportlab(self, record: dict) -> str:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        scan_id   = record.get("id", record.get("scan_id", "unknown"))
        url       = record.get("url", "N/A")
        scanned   = record.get("scanned_at", "N/A")
        risk      = record.get("risk_level", "Unknown")
        risk_score = record.get("risk_score", 0)

        pdf_path = os.path.join(self.OUTPUT_DIR, f"scan_report_{scan_id}.pdf")
        doc      = SimpleDocTemplate(pdf_path, pagesize=A4,
                                    leftMargin=2*cm, rightMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title", parent=styles["Title"],
                                    fontSize=22, spaceAfter=6)
        h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                    fontSize=13, spaceAfter=4)
        body_style  = styles["BodyText"]

        RISK_COLOR = {"Low": colors.green, "Medium": colors.orange, "High": colors.red}
        risk_color = RISK_COLOR.get(risk, colors.grey)

        story = []

        # ── Header ────────────────────────────────────────────────────────────
        story.append(Paragraph("🔍 Web Technology Detector", title_style))
        story.append(Paragraph("Security Scan Report", styles["Heading3"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
        story.append(Spacer(1, 0.4*cm))

        # ── Summary table ─────────────────────────────────────────────────────
        summary_data = [
            ["Field", "Value"],
            ["URL",        url],
            ["Scanned At", scanned],
            ["Risk Level", risk],
            ["Risk Score", f"{risk_score}/100"],
        ]
        t = Table(summary_data, colWidths=[4*cm, 13*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("TEXTCOLOR",  (1, 3), (1, 3), risk_color),
            ("FONTNAME",   (1, 3), (1, 3), "Helvetica-Bold"),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.6*cm))

        # ── Technologies detected ─────────────────────────────────────────────
        tech = record.get("technologies", {})
        story.append(Paragraph("Detected Technologies", h2_style))

        categories = [
            ("CMS",                tech.get("cms", [])),
            ("Frontend Frameworks",tech.get("frontend_frameworks", [])),
            ("Backend",            tech.get("backend_technologies", [])),
            ("Server",             tech.get("server", [])),
            ("CDN",                tech.get("cdn", [])),
            ("Analytics",          tech.get("analytics", [])),
        ]

        tech_data = [["Category", "Technologies"]]
        for cat, items in categories:
            tech_data.append([cat, ", ".join(items) if items else "None detected"])

        t2 = Table(tech_data, colWidths=[5*cm, 12*cm])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef2ff")]),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        story.append(t2)
        story.append(Spacer(1, 0.6*cm))

        # ── Security recommendations ──────────────────────────────────────────
        recs = record.get("security", {}).get("recommendations", [])
        if recs:
            story.append(Paragraph("Security Recommendations", h2_style))
            rec_data = [["Severity", "Issue", "Fix"]]
            for r in recs:
                rec_data.append([r.get("severity"), r.get("issue", ""), r.get("fix", "")])

            t3 = Table(rec_data, colWidths=[2.5*cm, 6*cm, 8.5*cm])
            t3.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff8f0")]),
                ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("WORDWRAP",   (0, 0), (-1, -1), True),
            ]))
            story.append(t3)

        # ── Footer ────────────────────────────────────────────────────────────
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey))
        story.append(Paragraph(
            f"Generated by Web Technology Detector — {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            ParagraphStyle("footer", parent=styles["Normal"], fontSize=8,
                        textColor=colors.grey, alignment=TA_CENTER)
        ))

        doc.build(story)
        return pdf_path

    # ── HTML fallback ─────────────────────────────────────────────────────────

    def _build_html_report(self, record: dict) -> str:
        html_path = os.path.join(self.OUTPUT_DIR,
                                f"scan_report_{record.get('id', 'x')}.html")
        with open(html_path, "w") as f:
            f.write(f"<html><body><pre>{json.dumps(record, indent=2)}</pre></body></html>")
        return html_path