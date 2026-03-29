"""
PDF Report Generation — clean A4 layout, no emoji, proper ReportLab conventions
"""

import sys
from pathlib import Path
from typing import List
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable, ListFlowable, ListItem,
)

from models import MCPServer, Vulnerability, Severity
from utils.logger import get_logger

logger = get_logger("pdf_reporter")

# ── Palette ─────────────────────────────────────────────────────────────────────
C = {
    "white":       colors.HexColor("#ffffff"),
    "bg":          colors.HexColor("#f8fafc"),
    "border":      colors.HexColor("#e2e8f0"),
    "ink":         colors.HexColor("#0f172a"),
    "muted":       colors.HexColor("#64748b"),
    "accent":      colors.HexColor("#6366f1"),
    "accent_dark": colors.HexColor("#4338ca"),
    # Severity foreground / background pairs
    "critical":    colors.HexColor("#991b1b"),
    "critical_bg": colors.HexColor("#fef2f2"),
    "high":        colors.HexColor("#9a3412"),
    "high_bg":     colors.HexColor("#fff7ed"),
    "medium":      colors.HexColor("#92400e"),
    "medium_bg":   colors.HexColor("#fefce8"),
    "low":         colors.HexColor("#1e40af"),
    "low_bg":      colors.HexColor("#eff6ff"),
    "info":        colors.HexColor("#065f46"),
    "info_bg":     colors.HexColor("#ecfdf5"),
}

# Maps Severity enum → (fg_color, bg_color, strip_color)
_SEV: dict = {
    Severity.CRITICAL: (C["critical"],  C["critical_bg"],  colors.HexColor("#ef4444")),
    Severity.HIGH:     (C["high"],      C["high_bg"],      colors.HexColor("#f97316")),
    Severity.MEDIUM:   (C["medium"],    C["medium_bg"],    colors.HexColor("#eab308")),
    Severity.LOW:      (C["low"],       C["low_bg"],       colors.HexColor("#3b82f6")),
    Severity.INFO:     (C["info"],      C["info_bg"],      colors.HexColor("#10b981")),
}

SEV_NAMES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_SLA   = {
    "CRITICAL": "24 hours",
    "HIGH":     "1 week",
    "MEDIUM":   "1 month",
    "LOW":      "3 months",
    "INFO":     "At convenience",
}

PAGE_W, PAGE_H = A4
MARGIN    = 2.0 * cm
CONTENT_W = PAGE_W - 2 * MARGIN
VERSION   = "0.3.0"

# Cover: top band height (painted by _on_cover canvas callback)
COVER_BAND_H = 9.0 * cm


class PDFReportGenerator:

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._add_styles()

    # ── Paragraph styles ─────────────────────────────────────────────────────────

    def _add_styles(self):
        ss = self.styles

        ss.add(ParagraphStyle("CoverEyebrow",
            parent=ss["Normal"],
            fontName="Helvetica", fontSize=10, leading=14,
            textColor=colors.HexColor("#a5b4fc"),   # light accent on dark bg
            spaceAfter=6))

        ss.add(ParagraphStyle("CoverTitle",
            parent=ss["Normal"],
            fontName="Helvetica-Bold", fontSize=30, leading=36,
            textColor=C["white"], spaceAfter=4))

        ss.add(ParagraphStyle("CoverMeta",
            parent=ss["Normal"],
            fontName="Helvetica", fontSize=10, leading=16,
            textColor=C["white"], spaceAfter=2))

        ss.add(ParagraphStyle("H1",
            parent=ss["Normal"],
            fontName="Helvetica-Bold", fontSize=16, leading=20,
            textColor=C["white"], spaceAfter=0))

        ss.add(ParagraphStyle("H2",
            parent=ss["Normal"],
            fontName="Helvetica-Bold", fontSize=12, leading=16,
            textColor=C["ink"], spaceBefore=14, spaceAfter=8))

        ss.add(ParagraphStyle("Body",
            parent=ss["Normal"],
            fontName="Helvetica", fontSize=10, leading=15,
            textColor=C["ink"], spaceAfter=8, alignment=TA_JUSTIFY))

        ss.add(ParagraphStyle("BodyMuted",
            parent=ss["Normal"],
            fontName="Helvetica", fontSize=9, leading=13,
            textColor=C["muted"], spaceAfter=4))

        ss.add(ParagraphStyle("Label",
            parent=ss["Normal"],
            fontName="Helvetica-Bold", fontSize=8, leading=11,
            textColor=C["muted"], spaceAfter=2))

        ss.add(ParagraphStyle("VulnTitle",
            parent=ss["Normal"],
            fontName="Helvetica-Bold", fontSize=11, leading=14,
            textColor=C["ink"], spaceAfter=4))

        ss.add(ParagraphStyle("MonoBlock",
            parent=ss["Normal"],
            fontName="Courier", fontSize=8, leading=12,
            textColor=colors.HexColor("#334155"),
            spaceAfter=2, leftIndent=4))

        ss.add(ParagraphStyle("Footer",
            parent=ss["Normal"],
            fontName="Helvetica", fontSize=8, leading=11,
            textColor=C["muted"], alignment=TA_CENTER))

        ss.add(ParagraphStyle("TableHdr",
            parent=ss["Normal"],
            fontName="Helvetica-Bold", fontSize=9, leading=12,
            textColor=C["white"]))

        ss.add(ParagraphStyle("TableCell",
            parent=ss["Normal"],
            fontName="Helvetica", fontSize=9, leading=13,
            textColor=C["ink"]))

        ss.add(ParagraphStyle("TableCellMuted",
            parent=ss["Normal"],
            fontName="Helvetica", fontSize=9, leading=13,
            textColor=C["muted"]))

    # ── Canvas callbacks ─────────────────────────────────────────────────────────

    def _on_cover(self, canvas, doc):
        canvas.saveState()
        # Dark band fills the top portion of the cover
        canvas.setFillColor(C["ink"])
        canvas.rect(0, PAGE_H - COVER_BAND_H, PAGE_W, COVER_BAND_H, fill=1, stroke=0)
        # Accent left stripe
        canvas.setFillColor(C["accent"])
        canvas.rect(0, 0, 0.5 * cm, PAGE_H, fill=1, stroke=0)
        # Footer note
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C["muted"])
        canvas.drawCentredString(PAGE_W / 2, 0.7 * cm,
                                 f"MCP Security Scanner v{VERSION}  |  Confidential")
        canvas.restoreState()

    def _on_page(self, canvas, doc):
        canvas.saveState()
        # Top bar
        canvas.setFillColor(C["ink"])
        canvas.rect(0, PAGE_H - 1.0 * cm, PAGE_W, 1.0 * cm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(C["white"])
        canvas.drawString(MARGIN, PAGE_H - 0.65 * cm, "MCP Security Scanner")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.65 * cm,
                               f"Confidential  |  {datetime.now():%Y-%m-%d}")
        # Bottom rule + page number
        canvas.setStrokeColor(C["border"])
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 1.1 * cm, PAGE_W - MARGIN, 1.1 * cm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C["muted"])
        canvas.drawCentredString(PAGE_W / 2, 0.65 * cm, f"Page {doc.page}")
        canvas.restoreState()

    # ── Public API ───────────────────────────────────────────────────────────────

    def generate(self, server_info: MCPServer, vulnerabilities: List[Vulnerability],
                 output_path: str) -> str:
        logger.info(f"Generating PDF report to {output_path}")
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=1.6 * cm,    # body pages: comfortable gap below 1cm top bar
            bottomMargin=1.6 * cm,
        )

        story = []
        story += self._cover(server_info, vulnerabilities)
        story.append(PageBreak())

        # Body pages use a smaller top margin — handled by changing doc frame,
        # but SimpleDocTemplate doesn't support per-page margins easily.
        # We use a leading Spacer on every body section instead.
        story += self._executive_summary(server_info, vulnerabilities)
        story.append(PageBreak())
        story += self._findings(vulnerabilities)
        if vulnerabilities:
            story.append(PageBreak())
            story += self._remediation_plan(vulnerabilities)
        story += self._disclaimer()

        # Build with cover callback first, body callback for subsequent pages.
        # SimpleDocTemplate calls onFirstPage for page 1, onLaterPages for rest.
        # But topMargin is constant — we compensate on body pages with a Spacer.
        doc.build(story,
                  onFirstPage=self._on_cover,
                  onLaterPages=self._on_page)
        logger.info(f"PDF saved to {output_path}")
        return output_path

    # ── Cover page ───────────────────────────────────────────────────────────────

    def _cover(self, server: MCPServer, vulns: List[Vulnerability]) -> list:
        sev   = _counts(vulns)
        risk  = _risk(sev)
        risk_label, risk_fg = _risk_label(risk)

        # topMargin = 1.4cm, so the first flowable sits 1.4cm from the top edge.
        # The canvas has painted a dark band over the top 9cm.
        # A small Spacer places the eyebrow ~2cm from the top (inside the band).
        elements = []
        elements.append(Spacer(1, 0.6 * cm))   # → eyebrow lands at ~2cm from top

        # ── Title block (white text on dark band) ──
        elements.append(Paragraph("SECURITY ASSESSMENT REPORT", self.styles["CoverEyebrow"]))
        elements.append(Paragraph("MCP Server", self.styles["CoverTitle"]))
        elements.append(Spacer(1, 0.5 * cm))

        # ── Meta lines (white text, still within dark band) ──
        for label, value in [
            ("Target",     server.url or "—"),
            ("Server",     server.name or "Unknown"),
            ("Date",       datetime.now().strftime("%B %d, %Y")),
            ("Findings",   str(len(vulns))),
            ("Risk Score", f"{risk}/100  —  {risk_label}"),
        ]:
            elements.append(Paragraph(
                f'<font color="#94a3b8"><b>{label}:</b></font>  {value}',
                self.styles["CoverMeta"]
            ))

        # ── Severity strip (light-colored cells, below or at bottom of dark band) ──
        elements.append(Spacer(1, 0.6 * cm))
        elements.append(self._severity_strip(sev))
        return elements

    def _severity_strip(self, sev: dict) -> Table:
        """5-column severity summary table with colored backgrounds."""
        counts_row = []
        labels_row = []
        for name in SEV_NAMES:
            sv = getattr(Severity, name)
            fg, bg, _ = _SEV[sv]
            counts_row.append(
                Paragraph(f'<b>{sev[name]}</b>',
                          ParagraphStyle(f"_cnt_{name}", fontName="Helvetica-Bold",
                                         fontSize=24, leading=28,
                                         textColor=fg, alignment=TA_CENTER))
            )
            labels_row.append(
                Paragraph(name,
                          ParagraphStyle(f"_lbl_{name}", fontName="Helvetica-Bold",
                                         fontSize=7, leading=10,
                                         textColor=fg, alignment=TA_CENTER))
            )

        col = CONTENT_W / 5
        t = Table([counts_row, labels_row], colWidths=[col] * 5,
                  rowHeights=[1.4 * cm, 0.55 * cm])

        style = [
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("BOX",           (0, 0), (-1, -1), 1, C["border"]),
            ("LINEAFTER",     (0, 0), (-3, -1), 0.5, C["border"]),
            ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ]
        for col_idx, name in enumerate(SEV_NAMES):
            sv = getattr(Severity, name)
            _, bg, _ = _SEV[sv]
            style.append(("BACKGROUND", (col_idx, 0), (col_idx, -1), bg))

        t.setStyle(TableStyle(style))
        return t

    # ── Section header helper ────────────────────────────────────────────────────

    def _section_header(self, title: str, subtitle: str = "") -> Table:
        """Dark-background section title row with optional subtitle."""
        inner = [Paragraph(title, self.styles["H1"])]
        if subtitle:
            inner.append(Paragraph(subtitle, ParagraphStyle(
                "_sh_sub", fontName="Helvetica", fontSize=9, leading=12,
                textColor=colors.HexColor("#94a3b8"))))

        t = Table([[inner]], colWidths=[CONTENT_W])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C["ink"]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        return t

    # ── Executive summary ────────────────────────────────────────────────────────

    def _executive_summary(self, server: MCPServer, vulns: List[Vulnerability]) -> list:
        sev  = _counts(vulns)
        risk = _risk(sev)
        risk_label, risk_fg = _risk_label(risk)
        cats = {}
        for v in vulns:
            cats.setdefault(v.category, 0)
            cats[v.category] += 1

        elements = [Spacer(1, 0.6 * cm)]
        elements.append(self._section_header(
            "Executive Summary",
            f"Security assessment of {server.url or server.host}"
        ))
        elements.append(Spacer(1, 0.4 * cm))

        # Risk score callout
        risk_row = Table(
            [[
                Paragraph(str(risk),
                          ParagraphStyle("_rs_num", fontName="Helvetica-Bold",
                                         fontSize=40, leading=46,
                                         textColor=risk_fg, alignment=TA_CENTER)),
                Paragraph(
                    f"<b>Risk Score</b><br/>{risk_label}<br/>"
                    f"<font color='#64748b' size='9'>{len(vulns)} findings across "
                    f"{len(cats)} categories</font>",
                    ParagraphStyle("_rs_txt", fontName="Helvetica", fontSize=13,
                                   leading=20, textColor=C["ink"])),
            ]],
            colWidths=[2.8 * cm, CONTENT_W - 2.8 * cm]
        )
        risk_row.setStyle(TableStyle([
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("BACKGROUND",    (0, 0), (-1, -1), C["bg"]),
            ("BOX",           (0, 0), (-1, -1), 1, C["border"]),
        ]))
        elements.append(risk_row)
        elements.append(Spacer(1, 0.5 * cm))

        # Intro paragraph
        elements.append(Paragraph(
            f"This report presents findings from an automated security assessment of the "
            f"MCP server at <b>{server.url or server.host}</b>. "
            f"The scanner performed {len(SEV_NAMES)} severity-level checks across authentication, "
            f"injection, AI-specific threats, encryption, and configuration categories. "
            f"All findings should be verified manually before remediation.",
            self.styles["Body"]
        ))

        # Severity breakdown table
        sev_rows_data = [row for s in SEV_NAMES if (row := [s, str(sev[s]), SEV_SLA[s]]) and sev[s] > 0]
        if sev_rows_data:
            elements.append(Paragraph("Findings by Severity", self.styles["H2"]))
            hdr = [
                Paragraph("SEVERITY",  self.styles["TableHdr"]),
                Paragraph("COUNT",     self.styles["TableHdr"]),
                Paragraph("RECOMMENDED SLA", self.styles["TableHdr"]),
            ]
            rows = [hdr]
            for s, cnt, sla in sev_rows_data:
                sv = getattr(Severity, s)
                fg, _, _ = _SEV[sv]
                rows.append([
                    Paragraph(s,   ParagraphStyle(f"_se_{s}", fontName="Helvetica-Bold",
                                                  fontSize=9, textColor=fg)),
                    Paragraph(cnt, self.styles["TableCell"]),
                    Paragraph(sla, self.styles["TableCellMuted"]),
                ])
            widths = [3.2 * cm, 2.0 * cm, CONTENT_W - 5.2 * cm]
            st = Table(rows, colWidths=widths)
            ts = [
                ("BACKGROUND",    (0, 0), (-1, 0),  C["ink"]),
                ("FONTSIZE",      (0, 0), (-1, -1),  9),
                ("PADDING",       (0, 0), (-1, -1),  8),
                ("GRID",          (0, 0), (-1, -1),  0.5, C["border"]),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1),  [C["white"], C["bg"]]),
                ("VALIGN",        (0, 0), (-1, -1),  "MIDDLE"),
            ]
            # Colour the severity bg cells
            row_idx = 1
            for s, cnt, _ in sev_rows_data:
                sv = getattr(Severity, s)
                _, bg, _ = _SEV[sv]
                ts.append(("BACKGROUND", (0, row_idx), (0, row_idx), bg))
                row_idx += 1
            st.setStyle(TableStyle(ts))
            elements.append(st)

        # Category breakdown
        if cats:
            elements.append(Spacer(1, 0.3 * cm))
            elements.append(Paragraph("Findings by Category", self.styles["H2"]))
            hdr = [
                Paragraph("CATEGORY", self.styles["TableHdr"]),
                Paragraph("COUNT",    self.styles["TableHdr"]),
            ]
            rows = [hdr] + [
                [Paragraph(c, self.styles["TableCell"]),
                 Paragraph(str(n), self.styles["TableCell"])]
                for c, n in sorted(cats.items(), key=lambda x: -x[1])
            ]
            ct = Table(rows, colWidths=[CONTENT_W - 2.5 * cm, 2.5 * cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),  C["ink"]),
                ("FONTSIZE",      (0, 0), (-1, -1),  9),
                ("PADDING",       (0, 0), (-1, -1),  8),
                ("GRID",          (0, 0), (-1, -1),  0.5, C["border"]),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1),  [C["white"], C["bg"]]),
                ("ALIGN",         (1, 0), (1, -1),   "CENTER"),
                ("VALIGN",        (0, 0), (-1, -1),  "MIDDLE"),
            ]))
            elements.append(ct)

        return elements

    # ── Detailed findings ────────────────────────────────────────────────────────

    def _findings(self, vulns: List[Vulnerability]) -> list:
        elements = [Spacer(1, 0.6 * cm)]
        elements.append(self._section_header(
            "Detailed Findings",
            f"{len(vulns)} issue{'s' if len(vulns) != 1 else ''} — sorted by severity"
        ))

        if not vulns:
            elements.append(Spacer(1, 0.4 * cm))
            elements.append(Paragraph("No vulnerabilities found.", self.styles["Body"]))
            return elements

        order = list(_SEV.keys())
        for i, v in enumerate(sorted(vulns, key=lambda x: order.index(x.severity)), 1):
            elements.append(Spacer(1, 0.35 * cm))
            elements.append(KeepTogether(self._finding_card(i, v)))

        return elements

    def _finding_card(self, num: int, v: Vulnerability) -> list:
        fg, bg, strip = _SEV[v.severity]

        # ── Header row: colored left strip | severity badge | number + title ──
        badge_cell = Paragraph(
            v.severity.value,
            ParagraphStyle(f"_fc_badge_{v.id}", fontName="Helvetica-Bold",
                           fontSize=7, leading=9, textColor=fg, alignment=TA_CENTER)
        )
        title_cell = Paragraph(
            f"<b>{num}.  {v.title}</b>",
            self.styles["VulnTitle"]
        )
        hdr = Table(
            [[badge_cell, title_cell]],
            colWidths=[1.6 * cm, CONTENT_W - 1.6 * cm]
        )
        hdr.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), bg),
            ("BACKGROUND",    (1, 0), (1, 0), C["bg"]),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (0, 0),  6),
            ("LEFTPADDING",   (1, 0), (1, 0), 10),
            ("BOX",           (0, 0), (-1, -1), 0.5, C["border"]),
            ("LINEAFTER",     (0, 0), (0, 0),  1.5, fg),
        ]))

        # ── Meta line ──
        meta_parts = [f"ID: <b>{v.id}</b>"]
        if v.cwe_id:        meta_parts.append(f"CWE: {v.cwe_id}")
        if v.cvss_score:    meta_parts.append(f"CVSS: {v.cvss_score}/10")
        if v.affected_component: meta_parts.append(f"Component: {v.affected_component}")

        elems = [
            hdr,
            Paragraph("  |  ".join(meta_parts), self.styles["BodyMuted"]),
            Paragraph(v.description, self.styles["Body"]),
        ]

        # ── Evidence ──
        if v.evidence:
            elems.append(Paragraph("Evidence", self.styles["Label"]))
            evidence_rows = [[Paragraph(f"- {e}", self.styles["MonoBlock"])]
                             for e in v.evidence[:8]]
            ev_t = Table(evidence_rows, colWidths=[CONTENT_W])
            ev_t.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("BOX",           (0, 0), (-1, -1), 0.5, C["border"]),
            ]))
            elems.append(ev_t)
            elems.append(Spacer(1, 0.15 * cm))

        # ── Remediation ──
        if v.remediation:
            elems.append(Paragraph("Remediation", self.styles["Label"]))
            for line in v.remediation.splitlines():
                line = line.strip()
                if line:
                    elems.append(Paragraph(line, self.styles["Body"]))

        elems.append(Spacer(1, 0.1 * cm))
        return elems

    # ── Remediation plan ─────────────────────────────────────────────────────────

    def _remediation_plan(self, vulns: List[Vulnerability]) -> list:
        elements = [Spacer(1, 0.6 * cm)]
        elements.append(self._section_header(
            "Remediation Plan",
            "Findings sorted by priority — fix critical issues first"
        ))
        elements.append(Spacer(1, 0.4 * cm))
        elements.append(Paragraph(
            "Address findings in severity order. Each row maps to its recommended "
            "SLA from point of discovery. CRITICAL issues pose immediate risk and "
            "should be resolved within 24 hours.",
            self.styles["Body"]
        ))

        order = list(_SEV.keys())
        sorted_vulns = sorted(vulns, key=lambda x: order.index(x.severity))

        hdr = [
            Paragraph("#",        self.styles["TableHdr"]),
            Paragraph("ID",       self.styles["TableHdr"]),
            Paragraph("Title",    self.styles["TableHdr"]),
            Paragraph("Severity", self.styles["TableHdr"]),
            Paragraph("SLA",      self.styles["TableHdr"]),
        ]
        rows = [hdr]
        for i, v in enumerate(sorted_vulns, 1):
            fg, bg, _ = _SEV[v.severity]
            title = v.title if len(v.title) <= 48 else v.title[:47] + "…"
            rows.append([
                Paragraph(str(i),         self.styles["TableCellMuted"]),
                Paragraph(v.id,           self.styles["TableCell"]),
                Paragraph(title,          self.styles["TableCell"]),
                Paragraph(v.severity.value,
                          ParagraphStyle(f"_rp_sev_{v.id}", fontName="Helvetica-Bold",
                                         fontSize=9, textColor=fg)),
                Paragraph(SEV_SLA[v.severity.value], self.styles["TableCellMuted"]),
            ])

        widths = [0.65*cm, 2.8*cm, CONTENT_W - 10.85*cm, 2.5*cm, 3.0*cm]
        t = Table(rows, colWidths=widths, repeatRows=1)
        ts = [
            ("BACKGROUND",    (0, 0), (-1, 0),  C["ink"]),
            ("FONTSIZE",      (0, 0), (-1, -1),  8),
            ("PADDING",       (0, 0), (-1, -1),  7),
            ("GRID",          (0, 0), (-1, -1),  0.5, C["border"]),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1),  [C["white"], C["bg"]]),
            ("VALIGN",        (0, 0), (-1, -1),  "MIDDLE"),
        ]
        for i, v in enumerate(sorted_vulns, 1):
            _, bg, _ = _SEV[v.severity]
            ts.append(("BACKGROUND", (3, i), (3, i), bg))
        t.setStyle(TableStyle(ts))
        elements.append(t)
        return elements

    # ── Disclaimer ───────────────────────────────────────────────────────────────

    def _disclaimer(self) -> list:
        return [
            Spacer(1, 0.8 * cm),
            HRFlowable(width=CONTENT_W, thickness=0.5, color=C["border"]),
            Spacer(1, 0.2 * cm),
            Paragraph(
                f"Generated by MCP Security Scanner v{VERSION} on "
                f"{datetime.now():%Y-%m-%d %H:%M}. "
                "Findings are produced by automated scanning only. "
                "Manual verification is strongly recommended before undertaking remediation. "
                "This report is confidential and intended for authorized personnel only.",
                self.styles["Footer"]
            ),
        ]


# ── Module-level helpers ─────────────────────────────────────────────────────────

def _counts(vulns: List[Vulnerability]) -> dict:
    c = {s: 0 for s in SEV_NAMES}
    for v in vulns:
        c[v.severity.value] = c.get(v.severity.value, 0) + 1
    return c


def _risk(sev: dict) -> int:
    w = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 1}
    return min(100, sum(w[s] * n for s, n in sev.items()))


def _risk_label(risk: int):
    if risk >= 70:
        return "HIGH RISK",    C["critical"]
    if risk >= 30:
        return "MEDIUM RISK",  C["medium"]
    return     "LOW RISK",     C["info"]


# Backward-compatibility alias
EnhancedPDFReportGenerator = PDFReportGenerator
