"""
SCAMLENS AI — Native PDF Security Report Generator
Generates multi-page, vector PDF reports from real SQLite scan history and model metadata
with zero external third-party PDF dependencies.
"""

from __future__ import annotations
from datetime import datetime
from typing import List, Dict, Any, Optional


def _pdf_escape(text: str) -> str:
    """Escape a string for safe inclusion in a PDF literal string (...) using WinAnsi/Latin-1."""
    if not text:
        return ""
    replacements = {
        "\u2014": "-",
        "\u2013": "-",
        "\u2026": "...",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2022": "*",
        "\u20b9": "Rs.",
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    safe = text.encode("latin-1", errors="replace").decode("latin-1")
    safe = safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    safe = safe.replace("\r", " ").replace("\n", " ")
    return safe


class SimplePDFCanvas:
    """Minimal multi-page PDF 1.4 builder with vector rectangles, lines, and standard Type1 Helvetica fonts."""

    PAGE_WIDTH = 595.28   # A4 width in pt
    PAGE_HEIGHT = 841.89  # A4 height in pt

    def __init__(self) -> None:
        self.pages: List[List[str]] = []
        self._current: List[str] = []

    def new_page(self) -> None:
        self._current = []
        self.pages.append(self._current)

    def rect_fill(self, x: float, y_top: float, w: float, h: float, r: float, g: float, b: float) -> None:
        y_pdf = self.PAGE_HEIGHT - y_top - h
        self._current.append(f"q {r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y_pdf:.2f} {w:.2f} {h:.2f} re f Q")

    def rect_stroke(self, x: float, y_top: float, w: float, h: float, r: float, g: float, b: float, line_w: float = 0.75) -> None:
        y_pdf = self.PAGE_HEIGHT - y_top - h
        self._current.append(f"q {line_w:.2f} w {r:.3f} {g:.3f} {b:.3f} RG {x:.2f} {y_pdf:.2f} {w:.2f} {h:.2f} re S Q")

    def line(self, x1: float, y1_top: float, x2: float, y2_top: float, r: float, g: float, b: float, line_w: float = 0.6) -> None:
        y1 = self.PAGE_HEIGHT - y1_top
        y2 = self.PAGE_HEIGHT - y2_top
        self._current.append(f"q {line_w:.2f} w {r:.3f} {g:.3f} {b:.3f} RG {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S Q")

    def text(self, x: float, y_top: float, content: str, size: float = 10.0, bold: bool = False, color: tuple[float, float, float] = (0.08, 0.11, 0.18)) -> None:
        font = "/F2" if bold else "/F1"
        y_pdf = self.PAGE_HEIGHT - y_top
        r, g, b = color
        escaped = _pdf_escape(content)
        self._current.append(f"BT {font} {size:.2f} Tf {r:.3f} {g:.3f} {b:.3f} rg 1 0 0 1 {x:.2f} {y_pdf:.2f} Tm ({escaped}) Tj ET")

    def build_bytes(self) -> bytes:
        if not self.pages:
            self.new_page()

        objects: Dict[int, bytes] = {}
        # 1: Catalog, 2: Pages, 3: Font Regular (Helvetica), 4: Font Bold (Helvetica-Bold)
        objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        objects[4] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"

        page_ids: List[int] = []
        next_id = 5
        for page_ops in self.pages:
            stream_data = "\n".join(page_ops).encode("latin-1")
            content_id = next_id
            page_id = next_id + 1
            next_id += 2

            objects[content_id] = (
                f"<< /Length {len(stream_data)} >>\nstream\n".encode("latin-1")
                + stream_data
                + b"\nendstream"
            )
            objects[page_id] = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.PAGE_WIDTH:.2f} {self.PAGE_HEIGHT:.2f}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("latin-1")
            page_ids.append(page_id)

        kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects[2] = f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_ids)} >>".encode("latin-1")
        objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: Dict[int, int] = {}
        max_id = next_id - 1

        for obj_id in range(1, max_id + 1):
            offsets[obj_id] = len(out)
            out.extend(f"{obj_id} 0 obj\n".encode("latin-1"))
            out.extend(objects[obj_id])
            out.extend(b"\nendobj\n")

        xref_offset = len(out)
        out.extend(f"xref\n0 {max_id + 1}\n".encode("latin-1"))
        out.extend(b"0000000000 65535 f \n")
        for obj_id in range(1, max_id + 1):
            out.extend(f"{offsets[obj_id]:010d} 00000 n \n".encode("latin-1"))

        out.extend(
            f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1")
        )
        return bytes(out)


def generate_security_report_pdf(
    records: List[Dict[str, Any]],
    scope_label: str,
    date_range_label: str,
    model_name: str = "Random Forest Classifier (Class-Balanced)",
) -> bytes:
    """
    Build a multi-page SCAMLENS AI Security Analysis PDF report from actual filtered scan records.
    """
    pdf = SimplePDFCanvas()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total = len(records)
    scam_count = sum(1 for r in records if "scam" in str(r.get("prediction_label", "")).lower())
    legit_count = total - scam_count
    scam_rate = round((scam_count / total) * 100, 1) if total > 0 else 0.0

    risk_counts = {
        "Low": sum(1 for r in records if r.get("risk_level") == "Low"),
        "Suspicious": sum(1 for r in records if r.get("risk_level") == "Suspicious"),
        "High": sum(1 for r in records if r.get("risk_level") == "High"),
        "Very High": sum(1 for r in records if r.get("risk_level") == "Very High"),
    }

    # Pagination calculation: Page 1 holds summary + risk chart + up to 14 rows; subsequent pages hold 24 rows
    first_page_cap = 14
    other_page_cap = 24
    if total <= first_page_cap:
        total_pages = 1
    else:
        rem = total - first_page_cap
        total_pages = 1 + ((rem + other_page_cap - 1) // other_page_cap)

    def draw_header(page_num: int) -> None:
        # Dark Navy Header Banner
        pdf.rect_fill(0, 0, 595.28, 76, 0.035, 0.067, 0.125)
        pdf.rect_fill(0, 74, 595.28, 2.5, 0.08, 0.72, 0.85)
        pdf.text(36, 30, "SCAMLENS AI  |  SECURITY INTELLIGENCE REPORT", size=14, bold=True, color=(0.96, 0.98, 1.0))
        pdf.text(36, 48, "Intelligent Scam & Phishing Detection System  -  See the risk before you click.", size=9, bold=False, color=(0.55, 0.75, 0.92))
        pdf.text(36, 63, f"Generated: {generated_at}   |   Model: {model_name}", size=8, bold=False, color=(0.68, 0.76, 0.86))
        pdf.text(500, 30, f"Page {page_num} of {total_pages}", size=9, bold=True, color=(0.35, 0.85, 0.96))

    def draw_footer(page_num: int) -> None:
        pdf.line(36, 804, 559, 804, 0.82, 0.85, 0.90, 0.6)
        pdf.text(36, 818, "SCAMLENS AI Audit Report  |  100% Offline Random Forest Inference  |  URLs Evaluated Statically", size=7.5, color=(0.42, 0.47, 0.55))
        pdf.text(505, 818, f"Page {page_num} / {total_pages}", size=7.5, bold=True, color=(0.32, 0.37, 0.45))

    # --- PAGE 1 ---
    pdf.new_page()
    draw_header(1)

    # Filter & Scope bar
    pdf.rect_fill(36, 90, 523, 28, 0.94, 0.96, 0.99)
    pdf.rect_stroke(36, 90, 523, 28, 0.82, 0.86, 0.92, 0.6)
    pdf.text(46, 108, f"Report Scope: {scope_label}     |     Date Window: {date_range_label}     |     Records Included: {total}", size=9, bold=True, color=(0.12, 0.18, 0.28))

    # KPI Summary Cards (4 columns)
    cards = [
        ("TOTAL SCANS", str(total), "Persisted in SQLite", (0.08, 0.45, 0.75)),
        ("SCAM / PHISHING", f"{scam_count} ({scam_rate}%)", "Flagged threats", (0.82, 0.18, 0.22)),
        ("LEGITIMATE", str(legit_count), "Clean classifications", (0.08, 0.58, 0.38)),
        ("HIGH / VERY HIGH", str(risk_counts["High"] + risk_counts["Very High"]), "Elevated risk tier", (0.85, 0.48, 0.06)),
    ]
    card_w = 124.0
    for idx, (label, val, sub, accent) in enumerate(cards):
        cx = 36 + idx * (card_w + 9.0)
        pdf.rect_fill(cx, 128, card_w, 58, 0.98, 0.99, 1.0)
        pdf.rect_stroke(cx, 128, card_w, 58, 0.84, 0.87, 0.92, 0.7)
        pdf.rect_fill(cx, 128, 3.5, 58, accent[0], accent[1], accent[2])
        pdf.text(cx + 10, 143, label, size=7.5, bold=True, color=(0.40, 0.46, 0.55))
        pdf.text(cx + 10, 163, val, size=14, bold=True, color=(0.08, 0.12, 0.20))
        pdf.text(cx + 10, 177, sub, size=7.5, color=(0.45, 0.50, 0.58))

    # Risk Distribution Horizontal Bar Chart
    pdf.rect_fill(36, 198, 523, 102, 0.985, 0.99, 1.0)
    pdf.rect_stroke(36, 198, 523, 102, 0.84, 0.87, 0.92, 0.7)
    pdf.text(48, 214, "RISK LEVEL DISTRIBUTION (ACTUAL SCAN DATA)", size=9, bold=True, color=(0.12, 0.16, 0.24))

    bar_colors = {
        "Low": (0.12, 0.65, 0.42),
        "Suspicious": (0.90, 0.58, 0.10),
        "High": (0.88, 0.32, 0.16),
        "Very High": (0.78, 0.14, 0.18),
    }
    max_risk = max(max(risk_counts.values()), 1)
    by = 228.0
    for r_label in ["Low", "Suspicious", "High", "Very High"]:
        cnt = risk_counts[r_label]
        pct = round((cnt / total) * 100, 1) if total > 0 else 0.0
        pdf.text(48, by + 8, r_label, size=8.5, bold=True, color=(0.20, 0.25, 0.34))
        # Track background
        pdf.rect_fill(120, by, 340, 10, 0.91, 0.93, 0.96)
        # Filled bar
        fill_w = max((cnt / max_risk) * 340.0, 2.0) if cnt > 0 else 0.0
        if fill_w > 0:
            c = bar_colors[r_label]
            pdf.rect_fill(120, by, fill_w, 10, c[0], c[1], c[2])
        pdf.text(470, by + 8, f"{cnt} ({pct}%)", size=8, bold=True, color=(0.20, 0.25, 0.34))
        by += 17.5

    def draw_table_header(y_top: float) -> float:
        pdf.rect_fill(36, y_top, 523, 20, 0.09, 0.14, 0.23)
        pdf.text(42, y_top + 13, "ID", size=8, bold=True, color=(0.95, 0.97, 1.0))
        pdf.text(74, y_top + 13, "TIMESTAMP", size=8, bold=True, color=(0.95, 0.97, 1.0))
        pdf.text(168, y_top + 13, "TYPE", size=8, bold=True, color=(0.95, 0.97, 1.0))
        pdf.text(204, y_top + 13, "PREDICTION", size=8, bold=True, color=(0.95, 0.97, 1.0))
        pdf.text(282, y_top + 13, "RISK", size=8, bold=True, color=(0.95, 0.97, 1.0))
        pdf.text(342, y_top + 13, "SCORE", size=8, bold=True, color=(0.95, 0.97, 1.0))
        pdf.text(382, y_top + 13, "INPUT PREVIEW", size=8, bold=True, color=(0.95, 0.97, 1.0))
        return y_top + 20.0

    pdf.text(36, 318, "DETAILED SCAN AUDIT TRAIL", size=10, bold=True, color=(0.10, 0.14, 0.22))
    y_cursor = draw_table_header(326.0)

    if not records:
        pdf.rect_stroke(36, y_cursor, 523, 45, 0.84, 0.87, 0.92, 0.7)
        pdf.text(175, y_cursor + 26, "No scan records matched the selected filter criteria.", size=9.5, color=(0.45, 0.50, 0.58))
        draw_footer(1)
        return pdf.build_bytes()

    row_h = 28.0
    current_page = 1
    rows_on_page = 0

    for idx, rec in enumerate(records):
        cap = first_page_cap if current_page == 1 else other_page_cap
        if rows_on_page >= cap:
            draw_footer(current_page)
            current_page += 1
            pdf.new_page()
            draw_header(current_page)
            pdf.text(36, 96, f"DETAILED SCAN AUDIT TRAIL (CONTINUED)", size=10, bold=True, color=(0.10, 0.14, 0.22))
            y_cursor = draw_table_header(104.0)
            rows_on_page = 0

        if rows_on_page % 2 == 1:
            pdf.rect_fill(36, y_cursor, 523, row_h, 0.965, 0.975, 0.99)
        pdf.line(36, y_cursor + row_h, 559, y_cursor + row_h, 0.88, 0.90, 0.94, 0.5)

        rid = str(rec.get("id", ""))[:6]
        ts = str(rec.get("timestamp", ""))[:19]
        itype = "URL" if str(rec.get("input_type", "")).lower() == "url" else "MSG"
        pred = str(rec.get("prediction_label") or rec.get("prediction") or "")
        rlevel = str(rec.get("risk_level", ""))
        rscore = f"{float(rec.get('risk_score', 0.0)):.1f}%"
        content = str(rec.get("content", "")).replace("\n", " ").strip()
        preview_line1 = content[:36]
        preview_line2 = content[36:72] + ("..." if len(content) > 72 else "")

        pred_color = (0.78, 0.14, 0.18) if "scam" in pred.lower() else (0.08, 0.55, 0.36)

        pdf.text(42, y_cursor + 12, f"#{rid}", size=7.5, bold=True, color=(0.25, 0.30, 0.38))
        pdf.text(74, y_cursor + 12, ts, size=7.5, color=(0.25, 0.30, 0.38))
        pdf.text(168, y_cursor + 12, itype, size=7.5, bold=True, color=(0.15, 0.42, 0.68))
        pdf.text(204, y_cursor + 12, pred[:15], size=7.5, bold=True, color=pred_color)
        pdf.text(282, y_cursor + 12, rlevel[:10], size=7.5, bold=True, color=(0.22, 0.26, 0.34))
        pdf.text(342, y_cursor + 12, rscore, size=7.5, color=(0.20, 0.25, 0.32))
        pdf.text(382, y_cursor + 11, preview_line1, size=7.2, color=(0.15, 0.20, 0.28))
        if preview_line2:
            pdf.text(382, y_cursor + 21, preview_line2, size=6.8, color=(0.40, 0.45, 0.54))

        y_cursor += row_h
        rows_on_page += 1

    draw_footer(current_page)
    return pdf.build_bytes()


def generate_incident_report_pdf(record: Dict[str, Any]) -> bytes:
    """
    Build a 1-page formal security incident dossier for a single scan record.
    """
    pdf = SimplePDFCanvas()
    pdf.new_page()

    # Colors
    c_navy = (0.05, 0.08, 0.16)
    c_cyan = (0.05, 0.65, 0.85)
    c_red = (0.85, 0.20, 0.20)
    c_green = (0.10, 0.65, 0.40)
    c_amber = (0.85, 0.55, 0.10)
    c_gray_bg = (0.96, 0.97, 0.98)
    c_border = (0.85, 0.88, 0.92)
    c_text_dark = (0.10, 0.15, 0.22)
    c_text_muted = (0.45, 0.50, 0.58)

    scan_id = str(record.get('id', record.get('scan_id', 'N/A')))
    timestamp = str(record.get('timestamp', 'N/A'))
    input_type = str(record.get('input_type', 'message')).upper()
    pred_label = str(record.get('prediction_label', record.get('prediction', 'Unknown')))
    risk_level = str(record.get('risk_level', 'Unknown'))
    risk_score = float(record.get('risk_score', 0.0))
    scam_prob = float(record.get('scam_probability', record.get('risk_probability', 0.0)))
    if scam_prob > 1.0:
        scam_prob = scam_prob / 100.0
    content = str(record.get('content', record.get('input_preview', '')))
    explanation = str(record.get('explanation_summary', record.get('guidance', 'No explanation stored.')))
    review_status = str(record.get('review_status', 'unreviewed')).upper()
    review_notes = str(record.get('review_notes') or 'No analyst review notes recorded.')

    is_threat = 'scam' in pred_label.lower() or 'phish' in pred_label.lower() or risk_level in ('High', 'Very High')

    # 1. Header Banner
    pdf.rect_fill(0, 0, pdf.PAGE_WIDTH, 65, *c_navy)
    pdf.rect_fill(0, 63, pdf.PAGE_WIDTH, 2, *c_cyan)
    pdf.text(36, 26, 'SCAMLENS AI - INCIDENT FORENSIC DOSSIER', size=15, bold=True, color=(1.0, 1.0, 1.0))
    pdf.text(36, 46, 'ZERO-EXECUTION STATIC CYBERSECURITY AUDIT REPORT', size=8.5, bold=False, color=(0.7, 0.8, 0.9))
    pdf.text(pdf.PAGE_WIDTH - 160, 46, f'CASE REF: SL-{scan_id.zfill(6)}', size=9, bold=True, color=c_cyan)

    # 2. Executive Incident Summary Box
    y = 82
    pdf.rect_fill(36, y, pdf.PAGE_WIDTH - 72, 70, *c_gray_bg)
    pdf.rect_stroke(36, y, pdf.PAGE_WIDTH - 72, 70, *c_border, line_w=0.8)

    pdf.text(48, y + 18, f'TARGET ARTIFACT: {input_type}', size=8, bold=True, color=c_text_muted)
    pdf.text(48, y + 36, f'TIMESTAMP (UTC): {timestamp}', size=8, bold=False, color=c_text_dark)
    pdf.text(48, y + 54, f'TRIAGE STATUS: {review_status}', size=8, bold=True, color=c_cyan if review_status != 'UNREVIEWED' else c_amber)

    # Right side: Verdict Badge
    pdf.rect_fill(pdf.PAGE_WIDTH - 210, y + 12, 160, 46, *(c_red if is_threat else c_green))
    pdf.text(pdf.PAGE_WIDTH - 198, y + 30, f'VERDICT: {pred_label.upper()}', size=10, bold=True, color=(1.0, 1.0, 1.0))
    pdf.text(pdf.PAGE_WIDTH - 198, y + 46, f'SEVERITY: {risk_level} ({risk_score:.1f}%)', size=8.5, bold=False, color=(1.0, 1.0, 1.0))

    # 3. Target Content Box
    y = 168
    pdf.text(36, y, 'ANALYZED CONTENT SNIPPET', size=10, bold=True, color=c_navy)
    pdf.line(36, y + 4, pdf.PAGE_WIDTH - 36, y + 4, *c_border)
    y += 14

    pdf.rect_fill(36, y, pdf.PAGE_WIDTH - 72, 65, 0.98, 0.98, 0.99)
    pdf.rect_stroke(36, y, pdf.PAGE_WIDTH - 72, 65, *c_border, line_w=0.6)

    c_lines = [content[i:i+80] for i in range(0, min(len(content), 240), 80)]
    for idx, cl in enumerate(c_lines[:3]):
        pdf.text(46, y + 18 + (idx * 16), cl, size=8.5, bold=False, color=c_text_dark)
    if not c_lines:
        pdf.text(46, y + 25, '[Empty content]', size=8.5, bold=False, color=c_text_muted)

    # 4. Machine Learning & Telemetry
    y += 85
    pdf.text(36, y, 'MACHINE LEARNING & FORENSIC METRICS', size=10, bold=True, color=c_navy)
    pdf.line(36, y + 4, pdf.PAGE_WIDTH - 36, y + 4, *c_border)
    y += 14

    col_w = (pdf.PAGE_WIDTH - 72 - 20) / 3
    metrics = [
        ('Random Forest Probability', f'{scam_prob * 100:.2f}% Phishing', 'Ensemble leaf vote'),
        ('Calibrated Threat Score', f'{risk_score:.1f} / 100.0', f'{risk_level} Risk Category'),
        ('Feature Space Dimension', '10,043 Features', 'TF-IDF word & char + 43 lexical'),
    ]
    for idx, (m_label, m_val, m_sub) in enumerate(metrics):
        bx = 36 + (idx * (col_w + 10))
        pdf.rect_fill(bx, y, col_w, 48, *c_gray_bg)
        pdf.rect_stroke(bx, y, col_w, 48, *c_border, line_w=0.6)
        pdf.text(bx + 8, y + 14, m_label, size=7.5, bold=True, color=c_text_muted)
        pdf.text(bx + 8, y + 28, m_val, size=9.5, bold=True, color=c_navy)
        pdf.text(bx + 8, y + 40, m_sub, size=6.8, bold=False, color=c_text_muted)

    # 5. Explanatory Indicators
    y += 66
    pdf.text(36, y, 'EXPLAINABLE INDICATORS & HEURISTIC FINDINGS', size=10, bold=True, color=c_navy)
    pdf.line(36, y + 4, pdf.PAGE_WIDTH - 36, y + 4, *c_border)
    y += 14

    pdf.rect_fill(36, y, pdf.PAGE_WIDTH - 72, 75, 1.0, 1.0, 1.0)
    pdf.rect_stroke(36, y, pdf.PAGE_WIDTH - 72, 75, *c_border, line_w=0.6)

    ind_lines = [explanation[i:i+85] for i in range(0, min(len(explanation), 340), 85)]
    for idx, il in enumerate(ind_lines[:4]):
        pdf.text(46, y + 16 + (idx * 15), f'*  {il}', size=8, bold=False, color=c_text_dark)
    if not ind_lines:
        pdf.text(46, y + 25, 'No specific risk indicators flagged. Message classified via baseline feature distribution.', size=8, color=c_text_muted)

    # 6. Analyst Review Notes & Feedback
    y += 92
    pdf.text(36, y, 'INCIDENT REVIEW & ANALYST TRIAGE', size=10, bold=True, color=c_navy)
    pdf.line(36, y + 4, pdf.PAGE_WIDTH - 36, y + 4, *c_border)
    y += 14

    pdf.rect_fill(36, y, pdf.PAGE_WIDTH - 72, 50, *c_gray_bg)
    pdf.rect_stroke(36, y, pdf.PAGE_WIDTH - 72, 50, *c_border, line_w=0.6)
    pdf.text(46, y + 16, f'Current Review Status: {review_status}', size=8.5, bold=True, color=c_navy)
    note_preview = review_notes[:170]
    pdf.text(46, y + 32, f'Analyst Notes: {note_preview}', size=7.8, bold=False, color=c_text_dark)

    # 7. Actionable Guidance / Remediation
    y += 66
    pdf.text(36, y, 'RECOMMENDED INCIDENT CONTAINMENT ACTIONS', size=10, bold=True, color=c_navy)
    pdf.line(36, y + 4, pdf.PAGE_WIDTH - 36, y + 4, *c_border)
    y += 14

    if is_threat:
        recs = [
            '1. DO NOT CLICK any embedded links or call phone numbers mentioned in the message.',
            '2. DO NOT provide banking credentials, OTPs, PINs, or PAN/Aadhaar identity documents.',
            '3. Block the sender address or phone number across your communication channels.',
            '4. Report this incident to your internal security operations team or National Cyber Crime portal.'
        ]
    else:
        recs = [
            '1. This artifact did not exhibit primary phishing indicators on holdout evaluation.',
            '2. Always verify the sender identity through an independent, official communication channel.',
            '3. Never disclose one-time passwords (OTPs) even if a communication appears legitimate.'
        ]
    for idx, rec in enumerate(recs):
        pdf.text(46, y + 12 + (idx * 14), rec, size=7.8, bold=False, color=c_text_dark)

    # Footer
    pdf.line(36, pdf.PAGE_HEIGHT - 38, pdf.PAGE_WIDTH - 36, pdf.PAGE_HEIGHT - 38, *c_border)
    pdf.text(36, pdf.PAGE_HEIGHT - 24, 'SCAMLENS AI Security Operations * Confidential Forensic Dossier * Offline ML Inference', size=7.5, color=c_text_muted)
    pdf.text(pdf.PAGE_WIDTH - 120, pdf.PAGE_HEIGHT - 24, f'Generated: {datetime.now().strftime("%Y-%m-%d")}', size=7.5, color=c_text_muted)

    return pdf.build_bytes()
