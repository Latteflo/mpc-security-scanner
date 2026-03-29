"""
PDF Report Generation
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
    PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfbase import pdfmetrics

from models import MCPServer, Vulnerability, Severity
from utils.logger import get_logger

logger = get_logger("pdf_reporter")

# ── Palette ────────────────────────────────────────────────────────────────────
C = {
    "bg":        colors.HexColor("#f8fafc"),
    "white":     colors.white,
    "ink":       colors.HexColor("#1a1d2e"),
    "muted":     colors.HexColor("#64748b"),
    "border":    colors.HexColor("#e2e8f0"),
    "accent":    colors.HexColor("#7c83f7"),
    "critical":  colors.HexColor("#be123c"),
    "critical_bg": colors.HexColor("#fff1f2"),
    "high":      colors.HexColor("#c2410c"),
    "high_bg":   colors.HexColor("#fff7ed"),
    "medium":    colors.HexColor("#d97706"),
    "medium_bg": colors.HexColor("#fefce8"),
    "low":       colors.HexColor("#1d4ed8"),
    "low_bg":    colors.HexColor("#eff6ff"),
    "info":      colors.HexColor("#059669"),
    "info_bg":   colors.HexColor("#f0fdf4"),
    "ok":        colors.HexColor("#059669"),
    "ok_bg":     colors.HexColor("#f0fdf4"),
}

SEV_COLOR = {
    Severity.CRITICAL: (C["critical"], C["critical_bg"]),
    Severity.HIGH:     (C["high"],     C["high_bg"]),
    Severity.MEDIUM:   (C["medium"],   C["medium_bg"]),
    Severity.LOW:      (C["low"],      C["low_bg"]),
    Severity.INFO:     (C["info"],     C["info_bg"]),
}

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm
CONTENT_W = PAGE_W - 2 * MARGIN

VERSION = "0.3.0"


class PDFReportGenerator:

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._add_styles()

    # ── Styles ──────────────────────────────────────────────────────────────────

    def _add_styles(self):
        add = self.styles.add

        add(ParagraphStyle("CoverTitle",
            fontName="Helvetica-Bold", fontSize=28, leading=34,
            textColor=C["ink"], alignment=TA_LEFT, spaceAfter=6))

        add(ParagraphStyle("CoverSub",
            fontName="Helvetica", fontSize=13, leading=18,
            textColor=C["muted"], alignment=TA_LEFT, spaceAfter=4))

        add(ParagraphStyle("SectionTitle",
            fontName="Helvetica-Bold", fontSize=14, leading=18,
            textColor=C["ink"], spaceBefore=18, spaceAfter=10))

        add(ParagraphStyle("Body",
            fontName="Helvetica", fontSize=10, leading=15,
            textColor=C["ink"], spaceAfter=8, alignment=TA_JUSTIFY))

        add(ParagraphStyle("BodyMuted",
            fontName="Helvetica", fontSize=9, leading=13,
            textColor=C["muted"], spaceAfter=6))

        add(ParagraphStyle("Label",
            fontName="Helvetica-Bold", fontSize=8, leading=11,
            textColor=C["muted"], spaceAfter=2,
            wordWrap="CJK"))

        add(ParagraphStyle("VulnTitle",
            fontName="Helvetica-Bold", fontSize=11, leading=14,
            textColor=C["ink"], spaceAfter=6))

        add(ParagraphStyle("CodeBlock",
            fontName="Courier", fontSize=8, leading=12,
            textColor=colors.HexColor("#334155"),
            backColor=colors.HexColor("#f8fafc"),
            spaceAfter=6, leftIndent=6))

        add(ParagraphStyle("Footer",
            fontName="Helvetica", fontSize=8, leading=11,
            textColor=C["muted"], alignment=TA_CENTER))

    # ── Header / footer canvas callbacks ───────────────────────────────────────

    def _on_page(self, canvas, doc):
        canvas.saveState()
        # Top bar
        canvas.setFillColor(C["ink"])
        canvas.rect(0, PAGE_H - 1.1 * cm, PAGE_W, 1.1 * cm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(colors.white)
        canvas.drawString(MARGIN, PAGE_H - 0.7 * cm, "MCP Security Scanner")
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.7 * cm,
                               f"Confidential  |  {datetime.now():%Y-%m-%d}")
        # Bottom
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C["muted"])
        canvas.drawCentredString(PAGE_W / 2, 0.6 * cm, f"Page {doc.page}")
        canvas.restoreState()

    def _on_cover(self, canvas, doc):
        # Cover page — accent sidebar
        canvas.saveState()
        canvas.setFillColor(C["accent"])
        canvas.rect(0, 0, 0.8 * cm, PAGE_H, fill=1, stroke=0)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(C["muted"])
        canvas.drawCentredString(PAGE_W / 2, 0.6 * cm, f"MCP Security Scanner v{VERSION}")
        canvas.restoreState()

    # ── Public API ──────────────────────────────────────────────────────────────

    def generate(self, server_info: MCPServer, vulnerabilities: List[Vulnerability],
                 output_path: str) -> str:
        logger.info(f"Generating PDF report to {output_path}")
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=2.2 * cm, bottomMargin=1.4 * cm,
        )

        story = []
        story += self._cover(server_info, vulnerabilities)
        story.append(PageBreak())
        story += self._executive_summary(server_info, vulnerabilities)
        story.append(PageBreak())
        story += self._findings(vulnerabilities)
        if vulnerabilities:
            story.append(PageBreak())
            story += self._remediation_plan(vulnerabilities)
        story += self._disclaimer()

        doc.build(story, onFirstPage=self._on_cover, onLaterPages=self._on_page)
        logger.info(f"PDF saved to {output_path}")
        return output_path

    # ── Cover page ──────────────────────────────────────────────────────────────

    def _cover(self, server: MCPServer, vulns: List[Vulnerability]) -> List:
        sev = self._counts(vulns)
        risk = self._risk(sev)
        risk_color, risk_label = (
            (C["critical"], "HIGH RISK") if risk >= 70
            else (C["medium"], "MEDIUM RISK") if risk >= 30
            else (C["ok"], "LOW RISK")
        )

        elements = [Spacer(1, 3 * cm)]

        elements.append(Paragraph("SECURITY ASSESSMENT", self.styles["CoverSub"]))
        elements.append(Paragraph("MCP Server Report", self.styles["CoverTitle"]))
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(HRFlowable(width=CONTENT_W, thickness=2, color=C["accent"], spaceAfter=20))

        # Meta table
        meta = [
            ["Target",      server.url or "—"],
            ["Server",      server.name or "Unknown"],
            ["Date",        datetime.now().strftime("%B %d, %Y")],
            ["Findings",    str(len(vulns))],
            ["Risk Score",  f"{risk}/100  {risk_label}"],
        ]
        t = Table(meta, colWidths=[3 * cm, CONTENT_W - 3 * cm])
        t.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",  (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE",  (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (0, 0), (0, -1), C["muted"]),
            ("TEXTCOLOR", (1, 0), (1, -1), C["ink"]),
            ("TEXTCOLOR", (1, 4), (1, 4),  risk_color),
            ("FONTNAME",  (1, 4), (1, 4),  "Helvetica-Bold"),
            ("TOPPADDING",  (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LINEBELOW", (0, 0), (-1, -2), 0.5, C["border"]),
            ("VALIGN",    (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 1 * cm))

        # Severity summary strip
        strip_data = [[
            self._sev_cell(sev["CRITICAL"], "CRITICAL", Severity.CRITICAL),
            self._sev_cell(sev["HIGH"],     "HIGH",     Severity.HIGH),
            self._sev_cell(sev["MEDIUM"],   "MEDIUM",   Severity.MEDIUM),
            self._sev_cell(sev["LOW"],      "LOW",      Severity.LOW),
            self._sev_cell(sev["INFO"],     "INFO",     Severity.INFO),
        ]]
        col = CONTENT_W / 5
        strip = Table(strip_data, colWidths=[col] * 5)
        strip.setStyle(TableStyle([
            ("ALIGN",   (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",  (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 12),
            ("BOX",     (0, 0), (-1, -1), 1, C["border"]),
            ("LINEBEFORE", (1, 0), (-1, -1), 0.5, C["border"]),
        ]))
        elements.append(strip)
        return elements

    def _sev_cell(self, count: int, label: str, sev: Severity):
        fg, bg = SEV_COLOR[sev]
        return Paragraph(
            f'<font color="#{self._hex(fg)}"><b>{count}</b></font><br/>'
            f'<font color="#{self._hex(C["muted"])}" size="8">{label}</font>',
            ParagraphStyle("_sc", fontName="Helvetica-Bold", fontSize=22,
                           alignment=TA_CENTER, leading=26,
                           backColor=bg, borderPadding=4)
        )

    # ── Executive summary ───────────────────────────────────────────────────────

    def _executive_summary(self, server: MCPServer, vulns: List[Vulnerability]) -> List:
        sev = self._counts(vulns)
        risk = self._risk(sev)

        elements = [Paragraph("Executive Summary", self.styles["SectionTitle"])]

        elements.append(Paragraph(
            f"This report presents the findings from a security assessment of the "
            f"MCP server at <b>{server.url}</b>. "
            f"The scan identified <b>{len(vulns)} issue{'s' if len(vulns) != 1 else ''}</b> "
            f"across {len({v.category for v in vulns})} categories, "
            f"with an overall risk score of <b>{risk}/100</b>.",
            self.styles["Body"]
        ))

        # Summary table
        rows = [["Severity", "Count", "SLA"]]
        sla = {"CRITICAL": "Fix within 24 hours",
               "HIGH":     "Fix within 1 week",
               "MEDIUM":   "Fix within 1 month",
               "LOW":      "Fix within 3 months",
               "INFO":     "Review at convenience"}
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev[s] > 0:
                rows.append([s, str(sev[s]), sla[s]])

        if len(rows) > 1:
            elements.append(Spacer(1, 0.3 * cm))
            widths = [3 * cm, 2 * cm, CONTENT_W - 5 * cm]
            t = Table(rows, colWidths=widths)
            style = [
                ("BACKGROUND", (0, 0), (-1, 0), C["ink"]),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 9),
                ("ALIGN",      (1, 0), (1, -1), "CENTER"),
                ("PADDING",    (0, 0), (-1, -1), 8),
                ("GRID",       (0, 0), (-1, -1), 0.5, C["border"]),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C["bg"]]),
            ]
            # Colour severity column
            for i, s in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], 1):
                if sev[s] > 0:
                    fg, bg = SEV_COLOR[getattr(Severity, s)]
                    style += [
                        ("BACKGROUND", (0, i), (0, i), bg),
                        ("TEXTCOLOR",  (0, i), (0, i), fg),
                        ("FONTNAME",   (0, i), (0, i), "Helvetica-Bold"),
                    ]
            t.setStyle(TableStyle(style))
            elements.append(t)

        # Category breakdown
        cats = {}
        for v in vulns:
            cats.setdefault(v.category, 0)
            cats[v.category] += 1
        if cats:
            elements.append(Spacer(1, 0.5 * cm))
            elements.append(Paragraph("Findings by Category", self.styles["SectionTitle"]))
            cat_rows = [["Category", "Count"]] + [
                [c, str(n)] for c, n in sorted(cats.items(), key=lambda x: -x[1])
            ]
            ct = Table(cat_rows, colWidths=[CONTENT_W - 3 * cm, 3 * cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), C["ink"]),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 9),
                ("ALIGN",      (1, 0), (1, -1), "CENTER"),
                ("PADDING",    (0, 0), (-1, -1), 7),
                ("GRID",       (0, 0), (-1, -1), 0.5, C["border"]),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C["bg"]]),
            ]))
            elements.append(ct)

        return elements

    # ── Detailed findings ───────────────────────────────────────────────────────

    def _findings(self, vulns: List[Vulnerability]) -> List:
        elements = [Paragraph("Detailed Findings", self.styles["SectionTitle"])]

        if not vulns:
            elements.append(Paragraph("No vulnerabilities found.", self.styles["Body"]))
            return elements

        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_vulns = sorted(vulns, key=lambda v: order.index(v.severity))

        for i, v in enumerate(sorted_vulns, 1):
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(KeepTogether(self._finding_card(i, v)))

        return elements

    def _finding_card(self, num: int, v: Vulnerability) -> List:
        fg, bg = SEV_COLOR[v.severity]

        # Title row with severity badge
        badge = Table(
            [[Paragraph(v.severity.value,
                        ParagraphStyle("_b", fontName="Helvetica-Bold", fontSize=8,
                                       textColor=fg, alignment=TA_CENTER))]],
            colWidths=[1.8 * cm]
        )
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("BOX",        (0, 0), (-1, -1), 1, fg),
            ("PADDING",    (0, 0), (-1, -1), 4),
        ]))

        title_row = Table(
            [[badge, Paragraph(f"<b>{num}. {v.title}</b>", self.styles["VulnTitle"])]],
            colWidths=[2 * cm, CONTENT_W - 2 * cm]
        )
        title_row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING",   (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))

        # Meta line
        meta_parts = [f"ID: {v.id}"]
        if v.cwe_id:   meta_parts.append(f"CWE: {v.cwe_id}")
        if v.cvss_score: meta_parts.append(f"CVSS: {v.cvss_score}/10")
        if v.affected_component: meta_parts.append(f"Component: {v.affected_component}")
        meta_line = "   |   ".join(meta_parts)

        elems = [
            title_row,
            Paragraph(meta_line, self.styles["BodyMuted"]),
            Paragraph(v.description, self.styles["Body"]),
        ]

        if v.evidence:
            elems.append(Paragraph("<b>Evidence</b>", self.styles["Label"]))
            for e in v.evidence[:6]:
                elems.append(Paragraph(f"- {e}", self.styles["CodeBlock"]))

        if v.remediation:
            elems.append(Spacer(1, 0.1 * cm))
            elems.append(Paragraph("<b>Remediation</b>", self.styles["Label"]))
            for line in v.remediation.splitlines():
                line = line.strip()
                if line:
                    elems.append(Paragraph(line, self.styles["Body"]))

        elems.append(HRFlowable(width=CONTENT_W, thickness=0.5, color=C["border"], spaceAfter=4))
        return elems

    # ── Remediation plan ────────────────────────────────────────────────────────

    def _remediation_plan(self, vulns: List[Vulnerability]) -> List:
        elements = [Paragraph("Remediation Plan", self.styles["SectionTitle"])]
        elements.append(Paragraph(
            "Prioritise fixes in severity order. The table below maps each finding "
            "to its recommended SLA.",
            self.styles["Body"]
        ))

        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sla_map = {
            Severity.CRITICAL: "24 hours",
            Severity.HIGH:     "1 week",
            Severity.MEDIUM:   "1 month",
            Severity.LOW:      "3 months",
            Severity.INFO:     "At convenience",
        }
        rows = [["#", "ID", "Title", "Severity", "SLA"]]
        for i, v in enumerate(sorted(vulns, key=lambda x: order.index(x.severity)), 1):
            rows.append([str(i), v.id, v.title[:55] + ("…" if len(v.title) > 55 else ""),
                         v.severity.value, sla_map[v.severity]])

        widths = [0.7*cm, 2.8*cm, CONTENT_W - 9.5*cm, 2.5*cm, 3.5*cm]
        t = Table(rows, colWidths=widths, repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), C["ink"]),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("PADDING",    (0, 0), (-1, -1), 6),
            ("GRID",       (0, 0), (-1, -1), 0.5, C["border"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C["bg"]]),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ]
        for i, v in enumerate(sorted(vulns, key=lambda x: order.index(x.severity)), 1):
            fg, bg = SEV_COLOR[v.severity]
            style += [
                ("TEXTCOLOR",  (3, i), (3, i), fg),
                ("FONTNAME",   (3, i), (3, i), "Helvetica-Bold"),
                ("BACKGROUND", (3, i), (3, i), bg),
            ]
        t.setStyle(TableStyle(style))
        elements.append(t)
        return elements

    # ── Disclaimer ──────────────────────────────────────────────────────────────

    def _disclaimer(self) -> List:
        return [
            Spacer(1, 0.5 * cm),
            HRFlowable(width=CONTENT_W, thickness=0.5, color=C["border"]),
            Spacer(1, 0.2 * cm),
            Paragraph(
                f"Generated by MCP Security Scanner v{VERSION} on "
                f"{datetime.now():%Y-%m-%d %H:%M}. "
                "Findings reflect automated scanning only — manual verification "
                "is recommended before remediation.",
                self.styles["Footer"]
            ),
        ]

    # ── Helpers ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _counts(vulns):
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            c[v.severity.value] = c.get(v.severity.value, 0) + 1
        return c

    @staticmethod
    def _risk(sev):
        w = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 1}
        return min(100, sum(w[s] * n for s, n in sev.items()))

    @staticmethod
    def _hex(color) -> str:
        r = int(color.red   * 255)
        g = int(color.green * 255)
        b = int(color.blue  * 255)
        return f"{r:02x}{g:02x}{b:02x}"


# Backward-compatibility alias
EnhancedPDFReportGenerator = PDFReportGenerator
