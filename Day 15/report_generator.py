# ─────────────────────────────────────────────────────────────────────────────
# AEGIS – PDF Report Generator
# Generates professional security assessment reports in PDF format
# ─────────────────────────────────────────────────────────────────────────────

import os
import io
from datetime import datetime
from typing import List, Dict, Any

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

from threat_engine import ThreatFinding, RiskLevel, get_risk_color


def _get_risk_level_label(score: float) -> str:
    if score >= 80:   return "CRITICAL"
    elif score >= 60: return "HIGH"
    elif score >= 40: return "MEDIUM"
    else:             return "LOW"


def generate_pdf_report(
    architecture_text: str,
    analysis_result: Dict[str, Any],
    executive_summary: str = "",
) -> bytes:
    """
    Generate a professional PDF security assessment report.
    Returns bytes of the PDF file.
    """
    if not FPDF_AVAILABLE:
        raise ImportError("fpdf2 is required for PDF generation. Run: pip install fpdf2")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── Cover Page ─────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(10, 15, 30)
    pdf.rect(0, 0, 210, 297, "F")

    # Title block
    pdf.set_y(60)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(0, 212, 255)
    pdf.cell(0, 12, "AEGIS", ln=True, align="C")

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(200, 220, 255)
    pdf.cell(0, 8, "AI Architecture Threat Modeling &", ln=True, align="C")
    pdf.cell(0, 8, "Security Review Engine", ln=True, align="C")

    pdf.ln(10)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(150, 180, 220)
    pdf.cell(0, 6, "SECURITY ASSESSMENT REPORT", ln=True, align="C")

    # Risk score box
    score = analysis_result.get("overall_score", 0)
    label = _get_risk_level_label(score)
    pdf.ln(20)
    pdf.set_font("Helvetica", "B", 36)
    if label == "CRITICAL":    pdf.set_text_color(255, 45, 85)
    elif label == "HIGH":      pdf.set_text_color(255, 107, 53)
    elif label == "MEDIUM":    pdf.set_text_color(255, 214, 10)
    else:                      pdf.set_text_color(48, 209, 88)
    pdf.cell(0, 16, f"{score:.0f}/100", ln=True, align="C")

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, f"Overall Risk: {label}", ln=True, align="C")

    # Metadata
    pdf.ln(30)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(120, 150, 190)
    pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True, align="C")
    pdf.cell(0, 6, "Frameworks: OWASP LLM Top 10 | NIST AI RMF | ENISA | MITRE ATLAS", ln=True, align="C")

    # ── Page 2: Executive Summary ──────────────────────────────────────────────
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)
    pdf.rect(0, 0, 210, 297, "F")

    _section_header(pdf, "EXECUTIVE SUMMARY")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(50, 50, 50)
    summary_text = executive_summary or "Executive summary not generated."
    pdf.multi_cell(0, 5, summary_text)

    # Risk Summary Table
    pdf.ln(8)
    _section_header(pdf, "RISK DISTRIBUTION")
    risk_summary = analysis_result.get("risk_summary", {})
    _draw_risk_table(pdf, risk_summary)

    # ── Page 3: Threat Findings ────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "THREAT FINDINGS")

    threats: List[ThreatFinding] = analysis_result.get("threat_findings", [])
    for i, threat in enumerate(threats, 1):
        _draw_threat_card(pdf, threat, i)

    # ── Page N: Full Analysis ──────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "DETAILED ANALYSIS")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(40, 40, 40)
    analysis_text = analysis_result.get("analysis_text", "")
    # Clean up markdown-ish formatting for PDF
    clean = (
        analysis_text
        .replace("**", "")
        .replace("##", "")
        .replace("###", "")
        .replace("####", "")
    )
    pdf.multi_cell(0, 4.5, clean[:8000])

    # ── Architecture Input ─────────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "ARCHITECTURE INPUT")
    pdf.set_font("Courier", "", 8)
    pdf.set_text_color(30, 30, 30)
    pdf.set_fill_color(245, 248, 255)
    pdf.multi_cell(0, 4, architecture_text[:2000], fill=True)

    # ── Footer ─────────────────────────────────────────────────────────────────
    pdf.set_y(-25)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 6, "AEGIS — AI Architecture Threat Modeling & Security Review Engine", ln=True, align="C")
    pdf.cell(0, 6, "Confidential Security Assessment — Do Not Distribute", align="C")

    return bytes(pdf.output())


def _section_header(pdf: "FPDF", title: str):
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_fill_color(10, 15, 40)
    pdf.set_text_color(0, 212, 255)
    pdf.cell(0, 8, f"  {title}", ln=True, fill=True)
    pdf.ln(4)
    pdf.set_text_color(30, 30, 30)


def _draw_risk_table(pdf: "FPDF", risk_summary: Dict[str, int]):
    headers = ["Risk Level", "Count"]
    col_w   = [120, 60]
    row_colors = {
        "Critical":      (255, 45,  85),
        "High":          (255, 107, 53),
        "Medium":        (255, 214, 10),
        "Low":           (48,  209, 88),
        "Informational": (99,  99,  102),
    }
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(230, 235, 255)
    for h, w in zip(headers, col_w):
        pdf.cell(w, 7, h, border=1, fill=True, align="C")
    pdf.ln()

    pdf.set_font("Helvetica", "", 10)
    for level, count in risk_summary.items():
        r, g, b = row_colors.get(level, (180, 180, 180))
        pdf.set_text_color(r, g, b)
        pdf.cell(col_w[0], 6, level, border=1)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(col_w[1], 6, str(count), border=1, align="C")
        pdf.ln()
    pdf.ln(4)


def _draw_threat_card(pdf: "FPDF", threat: ThreatFinding, index: int):
    risk_colors = {
        "Critical": (255, 45,  85),
        "High":     (255, 107, 53),
        "Medium":   (255, 200, 10),
        "Low":      (48,  209, 88),
    }
    r, g, b = risk_colors.get(threat.risk_level.value, (150, 150, 150))

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(r, g, b)
    pdf.cell(0, 6, f"[{threat.id}] {threat.title}  —  {threat.risk_level.value}  (CVSS {threat.cvss_score})", ln=True)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(0, 5, f"NIST Control: {threat.nist_control}")

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(30, 30, 80)
    pdf.cell(0, 5, "Key Mitigations:", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(40, 40, 40)
    for m in threat.mitigations[:3]:
        pdf.multi_cell(0, 4.5, f"  • {m}")
    pdf.ln(3)
