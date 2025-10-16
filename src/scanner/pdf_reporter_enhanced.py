"""
Enhanced PDF Report Generation with Professional Styling
"""

import sys
from pathlib import Path
from typing import List
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether, Frame, PageTemplate
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas

from models import MCPServer, Vulnerability, Severity
from utils.logger import get_logger

logger = get_logger("pdf_enhanced")


class EnhancedPDFReportGenerator:
    """Generates beautiful professional PDF reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.colors = {
            'primary': colors.HexColor('#2c3e50'),
            'secondary': colors.HexColor('#3498db'),
            'success': colors.HexColor('#27ae60'),
            'danger': colors.HexColor('#e74c3c'),
            'warning': colors.HexColor('#f39c12'),
            'info': colors.HexColor('#3498db'),
            'light': colors.HexColor('#ecf0f1'),
            'dark': colors.HexColor('#34495e'),
        }
    
    def _setup_custom_styles(self):
        """Setup enhanced custom styles"""
        
        # Cover page title
        self.styles.add(ParagraphStyle(
            name='CoverTitle',
            parent=self.styles['Heading1'],
            fontSize=36,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            leading=42
        ))
        
        # Cover subtitle
        self.styles.add(ParagraphStyle(
            name='CoverSubtitle',
            parent=self.styles['Normal'],
            fontSize=18,
            textColor=colors.HexColor('#7f8c8d'),
            spaceAfter=20,
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))
        
        # Section header with underline
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=18,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=15,
            spaceBefore=25,
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5
        ))
        
        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='Executive',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            alignment=TA_JUSTIFY,
            leading=16
        ))
        
        # Vulnerability title with icon
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=10,
            fontName='Helvetica-Bold',
            leftIndent=20
        ))
        
        # Body text
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=10,
            alignment=TA_JUSTIFY,
            leading=14
        ))
    
    def _create_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#95a5a6'))
        canvas.drawString(inch, letter[1] - 0.5*inch, "MCP Security Scanner Report")
        canvas.drawRightString(letter[0] - inch, letter[1] - 0.5*inch, 
                              datetime.now().strftime('%Y-%m-%d'))
        
        # Header line
        canvas.setStrokeColor(colors.HexColor('#3498db'))
        canvas.setLineWidth(2)
        canvas.line(inch, letter[1] - 0.6*inch, letter[0] - inch, letter[1] - 0.6*inch)
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.drawCentredString(letter[0]/2, 0.5*inch, 
                                f"Page {doc.page}")
        canvas.drawRightString(letter[0] - inch, 0.5*inch, 
                              "Confidential - For Internal Use Only")
        
        canvas.restoreState()
    
    def generate(self, server: MCPServer, vulnerabilities: List[Vulnerability], 
                output_path: str) -> str:
        """Generate enhanced PDF report"""
        
        logger.info(f"Generating enhanced PDF report to {output_path}")
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create PDF with custom page template
        doc = SimpleDocTemplate(
            str(output_file),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=90,
            bottomMargin=72
        )
        
        # Build content
        story = []
        
        # Cover page
        story.extend(self._create_cover_page(server))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(server, vulnerabilities))
        story.append(PageBreak())
        
        # Detailed findings
        story.extend(self._create_findings(vulnerabilities))
        
        # Recommendations
        story.append(PageBreak())
        story.extend(self._create_recommendations(vulnerabilities))
        
        # Footer
        story.extend(self._create_footer())
        
        # Build with header/footer
        doc.build(story, onFirstPage=self._create_header_footer, 
                 onLaterPages=self._create_header_footer)
        
        logger.info(f"Enhanced PDF report saved to {output_file}")
        return str(output_file)
    
    def _create_cover_page(self, server: MCPServer) -> List:
        """Create professional cover page"""
        elements = []
        
        # Add vertical space
        elements.append(Spacer(1, 2*inch))
        
        # Shield/Lock icon (text-based)
        icon = Paragraph("🔒", self.styles['CoverTitle'])
        elements.append(icon)
        elements.append(Spacer(1, 0.3*inch))
        
        # Title
        title = Paragraph(
            "<b>SECURITY ASSESSMENT REPORT</b>",
            self.styles['CoverTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        
        # Subtitle
        subtitle = Paragraph(
            f"Model Context Protocol Server<br/>{server.url}",
            self.styles['CoverSubtitle']
        )
        elements.append(subtitle)
        elements.append(Spacer(1, 1*inch))
        
        # Info box
        info_data = [
            ['Report Date:', datetime.now().strftime('%B %d, %Y')],
            ['Target Server:', server.url],
            ['Server Name:', server.name or 'Unknown'],
            ['Assessment Type:', 'Comprehensive Security Scan'],
            ['Status:', 'CONFIDENTIAL'],
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.colors['light']),
            ('TEXTCOLOR', (0, 0), (0, -1), self.colors['dark']),
            ('TEXTCOLOR', (1, 0), (1, -1), self.colors['primary']),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('PADDING', (0, 0), (-1, -1), 12),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 1, self.colors['secondary']),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
        ]))
        
        elements.append(info_table)
        
        return elements
    
    def _create_executive_summary(self, server: MCPServer, 
                                  vulnerabilities: List[Vulnerability]) -> List:
        """Create executive summary with charts"""
        elements = []
        
        # Section header
        header = Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.3*inch))
        
        # Summary text
        summary_text = f"""
        This report presents the findings from a comprehensive security assessment 
        of the Model Context Protocol (MCP) server deployed at <b>{server.url}</b>. 
        The assessment identified <b>{len(vulnerabilities)} security issues</b> 
        that require attention to ensure the confidentiality, integrity, and 
        availability of the system.
        """
        
        summary = Paragraph(summary_text, self.styles['Executive'])
        elements.append(summary)
        elements.append(Spacer(1, 0.3*inch))
        
        # Risk score calculation
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity.value] += 1
        
        risk_score = min(sum([
            severity_counts['CRITICAL'] * 10,
            severity_counts['HIGH'] * 5,
            severity_counts['MEDIUM'] * 2,
            severity_counts['LOW'] * 1
        ]), 100)
        
        # Risk level determination
        if risk_score >= 70:
            risk_level = "HIGH RISK"
            risk_color = self.colors['danger']
        elif risk_score >= 40:
            risk_level = "MEDIUM RISK"
            risk_color = self.colors['warning']
        else:
            risk_level = "LOW RISK"
            risk_color = self.colors['success']
        
        # Risk score box
        risk_data = [[f'OVERALL RISK SCORE: {risk_score}/100<br/>{risk_level}']]
        risk_table = Table(risk_data, colWidths=[6.5*inch])
        risk_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 18),
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('PADDING', (0, 0), (-1, -1), 20),
            ('BOX', (0, 0), (-1, -1), 3, self.colors['dark']),
            ('ROUNDRECT', (0, 0), (-1, -1), 10),
        ]))
        
        elements.append(risk_table)
        elements.append(Spacer(1, 0.4*inch))
        
        # Vulnerability breakdown table
        vuln_data = [
            ['SEVERITY', 'COUNT', 'RISK LEVEL', 'PRIORITY'],
            ['Critical', str(severity_counts['CRITICAL']), '🔴 Immediate', 'P0 - Fix Now'],
            ['High', str(severity_counts['HIGH']), '🟠 Urgent', 'P1 - This Week'],
            ['Medium', str(severity_counts['MEDIUM']), '🟡 Important', 'P2 - This Month'],
            ['Low', str(severity_counts['LOW']), '🔵 Minor', 'P3 - Backlog'],
            ['Info', str(severity_counts['INFO']), '🟢 FYI', 'P4 - Optional'],
        ]
        
        vuln_table = Table(vuln_data, colWidths=[1.5*inch, 1*inch, 2*inch, 2*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.colors['light']]),
        ]))
        
        elements.append(vuln_table)
        
        return elements
    
    def _create_findings(self, vulnerabilities: List[Vulnerability]) -> List:
        """Create detailed findings section"""
        elements = []
        
        header = Paragraph("DETAILED FINDINGS", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Sort by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, 
                         Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_vulns = sorted(vulnerabilities, 
                             key=lambda v: severity_order[v.severity])
        
        for i, vuln in enumerate(sorted_vulns, 1):
            elements.extend(self._create_vulnerability_card(i, vuln))
            if i < len(sorted_vulns):
                elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_vulnerability_card(self, num: int, vuln: Vulnerability) -> List:
        """Create styled vulnerability card"""
        elements = []
        
        # Severity colors
        severity_colors = {
            Severity.CRITICAL: self.colors['danger'],
            Severity.HIGH: colors.HexColor('#e67e22'),
            Severity.MEDIUM: self.colors['warning'],
            Severity.LOW: self.colors['info'],
            Severity.INFO: self.colors['success']
        }
        
        severity_color = severity_colors.get(vuln.severity, colors.grey)
        
        # Vulnerability header with number and severity badge
        title_text = f"<b>{num}. {vuln.title}</b>"
        title = Paragraph(title_text, self.styles['VulnTitle'])
        
        # Metadata table with color coding
        meta_data = [
            ['ID:', vuln.id, 'Severity:', vuln.severity.value],
            ['Category:', vuln.category, 'CWE:', vuln.cwe_id or 'N/A'],
        ]
        
        if vuln.cvss_score:
            meta_data.append(['CVSS Score:', f"{vuln.cvss_score}/10.0", '', ''])
        
        meta_table = Table(meta_data, colWidths=[1*inch, 2*inch, 1*inch, 2*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), self.colors['dark']),
            ('TEXTCOLOR', (2, 0), (2, -1), self.colors['dark']),
            ('TEXTCOLOR', (3, 0), (3, 0), severity_color),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        # Description
        desc = Paragraph(
            f"<b>Description:</b><br/>{vuln.description}", 
            self.styles['BodyText']
        )
        
        # Evidence
        evidence_items = "<br/>".join([f"• {e}" for e in vuln.evidence[:5]])
        evidence = Paragraph(
            f"<b>Evidence:</b><br/>{evidence_items}", 
            self.styles['BodyText']
        )
        
        # Remediation
        remediation = Paragraph(
            f"<b>Remediation:</b><br/>{vuln.remediation.replace(chr(10), '<br/>')}", 
            self.styles['BodyText']
        )
        
        # Combine into bordered card
        card_elements = [
            title,
            Spacer(1, 0.1*inch),
            meta_table,
            Spacer(1, 0.15*inch),
            desc,
            Spacer(1, 0.1*inch),
            evidence,
            Spacer(1, 0.1*inch),
            remediation
        ]
        
        # Keep card together on same page
        elements.append(KeepTogether(card_elements))
        
        return elements
    
    def _create_recommendations(self, vulnerabilities: List[Vulnerability]) -> List:
        """Create recommendations section"""
        elements = []
        
        header = Paragraph("RECOMMENDATIONS", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Priority actions
        reco_text = """
        <b>Immediate Actions (Priority 0):</b><br/>
        • Address all CRITICAL vulnerabilities within 24 hours<br/>
        • Implement temporary mitigations if permanent fixes require time<br/>
        • Notify security team and stakeholders<br/>
        <br/>
        <b>Short-term Actions (1-2 weeks):</b><br/>
        • Resolve all HIGH severity issues<br/>
        • Begin addressing MEDIUM severity vulnerabilities<br/>
        • Implement monitoring and alerting<br/>
        <br/>
        <b>Long-term Actions (1-3 months):</b><br/>
        • Address remaining MEDIUM and LOW severity issues<br/>
        • Implement security best practices<br/>
        • Schedule regular security assessments<br/>
        • Provide security training to development team<br/>
        """
        
        reco = Paragraph(reco_text, self.styles['BodyText'])
        elements.append(reco)
        
        return elements
    
    def _create_footer(self) -> List:
        """Create report footer"""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Spacer(1, 1*inch))
        
        footer_text = """
        <b>Disclaimer:</b><br/>
        This report is provided for informational purposes only. The findings represent 
        potential security issues identified through automated and manual testing. 
        Manual verification is recommended before taking remediation actions.<br/>
        <br/>
        <b>Report Generated by:</b> MCP Security Scanner v0.2.0<br/>
        <b>Generated:</b> """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """<br/>
        <br/>
        <i>This document contains confidential information. Unauthorized distribution is prohibited.</i>
        """
        
        footer = Paragraph(footer_text, self.styles['BodyText'])
        elements.append(footer)
        
        return elements
