"""
PDF Report Generation Module
Creates professional PDF security reports
"""

import sys
from pathlib import Path
from typing import List
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import MCPServer, Vulnerability, ScanReport, Severity
from utils.logger import get_logger

logger = get_logger("pdf_reporter")


class PDFReportGenerator:
    """Generates PDF security reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='Subtitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#666666'),
            spaceAfter=20,
            alignment=TA_CENTER
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        ))
        
        # Vulnerability title
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
    
    def generate(
        self,
        server_info: MCPServer,
        vulnerabilities: List[Vulnerability],
        output_path: str
    ) -> str:
        """
        Generate PDF report
        
        Args:
            server_info: Scanned server information
            vulnerabilities: List of vulnerabilities
            output_path: Path to save PDF
            
        Returns:
            Path to generated PDF
        """
        logger.info(f"Generating PDF report to {output_path}")
        
        # Create PDF document
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        doc = SimpleDocTemplate(
            str(output_file),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Build content
        story = []
        
        # Add title page
        story.extend(self._create_title_page(server_info))
        story.append(PageBreak())
        
        # Add executive summary
        story.extend(self._create_executive_summary(server_info, vulnerabilities))
        story.append(PageBreak())
        
        # Add vulnerability details
        story.extend(self._create_vulnerability_section(vulnerabilities))
        
        # Add footer
        story.extend(self._create_footer())
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"PDF report saved to {output_file}")
        return str(output_file)
    
    def _create_title_page(self, server: MCPServer) -> List:
        """Create title page"""
        elements = []
        
        # Add spacing from top
        elements.append(Spacer(1, 2*inch))
        
        # Title
        title = Paragraph(
            "🔒 MCP Security Scan Report",
            self.styles['CustomTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.3*inch))
        
        # Subtitle
        subtitle = Paragraph(
            f"Security Assessment for {server.url}",
            self.styles['Subtitle']
        )
        elements.append(subtitle)
        elements.append(Spacer(1, 1*inch))
        
        # Server info table
        server_data = [
            ['Target Server:', server.url],
            ['Server Name:', server.name or 'Unknown'],
            ['Port:', str(server.port)],
            ['Protocol:', server.protocol.upper()],
            ['Scan Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        server_table = Table(server_data, colWidths=[2*inch, 4*inch])
        server_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#2c3e50')),
        ]))
        
        elements.append(server_table)
        
        return elements
    
    def _create_executive_summary(
        self,
        server: MCPServer,
        vulnerabilities: List[Vulnerability]
    ) -> List:
        """Create executive summary"""
        elements = []
        
        # Section header
        header = Paragraph("Executive Summary", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Severity counts
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for vuln in vulnerabilities:
            severity_counts[vuln.severity.value] += 1
        
        # Calculate risk score
        risk_score = min(sum([
            severity_counts['CRITICAL'] * 10,
            severity_counts['HIGH'] * 5,
            severity_counts['MEDIUM'] * 2,
            severity_counts['LOW'] * 1
        ]), 100)
        
        # Summary text
        summary_text = f"""
        This report presents the findings from a comprehensive security assessment of the MCP server 
        at <b>{server.url}</b>. The scan identified <b>{len(vulnerabilities)} security issues</b> 
        that require attention.
        """
        
        summary = Paragraph(summary_text, self.styles['Normal'])
        elements.append(summary)
        elements.append(Spacer(1, 0.3*inch))
        
        # Risk score box
        risk_color = colors.red if risk_score > 70 else colors.orange if risk_score > 40 else colors.green
        risk_data = [[f'Overall Risk Score: {risk_score}/100']]
        risk_table = Table(risk_data, colWidths=[6*inch])
        risk_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 16),
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('PADDING', (0, 0), (-1, -1), 20),
            ('BOX', (0, 0), (-1, -1), 2, colors.black),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Severity breakdown table
        severity_data = [
            ['Severity', 'Count', 'Risk'],
            ['Critical', str(severity_counts['CRITICAL']), '🔴 Immediate Action Required'],
            ['High', str(severity_counts['HIGH']), '🟠 Important'],
            ['Medium', str(severity_counts['MEDIUM']), '🟡 Should Address'],
            ['Low', str(severity_counts['LOW']), '🔵 Minor'],
            ['Info', str(severity_counts['INFO']), '🟢 Informational'],
        ]
        
        severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(severity_table)
        
        return elements
    
    def _create_vulnerability_section(self, vulnerabilities: List[Vulnerability]) -> List:
        """Create detailed vulnerability section"""
        elements = []
        
        # Section header
        header = Paragraph("Detailed Findings", self.styles['SectionHeader'])
        elements.append(header)
        elements.append(Spacer(1, 0.2*inch))
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order[v.severity])
        
        for i, vuln in enumerate(sorted_vulns, 1):
            vuln_elements = self._create_vulnerability_card(i, vuln)
            elements.extend(vuln_elements)
            
            if i < len(sorted_vulns):
                elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_vulnerability_card(self, num: int, vuln: Vulnerability) -> List:
        """Create a vulnerability card"""
        elements = []
        
        # Severity color mapping
        severity_colors = {
            Severity.CRITICAL: colors.HexColor('#d32f2f'),
            Severity.HIGH: colors.HexColor('#f57c00'),
            Severity.MEDIUM: colors.HexColor('#fbc02d'),
            Severity.LOW: colors.HexColor('#1976d2'),
            Severity.INFO: colors.HexColor('#388e3c')
        }
        
        severity_color = severity_colors.get(vuln.severity, colors.grey)
        
        # Vulnerability header with severity badge
        title_text = f"<b>{num}. {vuln.title}</b>"
        title = Paragraph(title_text, self.styles['VulnTitle'])
        
        # Create card container
        card_content = []
        
        # Metadata table
        meta_data = [
            ['ID:', vuln.id],
            ['Severity:', vuln.severity.value],
            ['Category:', vuln.category],
        ]
        
        if vuln.cvss_score:
            meta_data.append(['CVSS Score:', f"{vuln.cvss_score}/10.0"])
        if vuln.cwe_id:
            meta_data.append(['CWE:', vuln.cwe_id])
        
        meta_table = Table(meta_data, colWidths=[1.5*inch, 4.5*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), severity_color),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        
        # Description
        desc = Paragraph(f"<b>Description:</b><br/>{vuln.description}", self.styles['Normal'])
        
        # Evidence
        evidence_text = "<b>Evidence:</b><br/>" + "<br/>".join([f"• {e}" for e in vuln.evidence])
        evidence = Paragraph(evidence_text, self.styles['Normal'])
        
        # Remediation
        remediation_text = f"<b>Remediation:</b><br/>{vuln.remediation.replace(chr(10), '<br/>')}"
        remediation = Paragraph(remediation_text, self.styles['Normal'])
        
        # Combine into a bordered box
        elements.append(KeepTogether([
            title,
            Spacer(1, 0.1*inch),
            meta_table,
            Spacer(1, 0.1*inch),
            desc,
            Spacer(1, 0.1*inch),
            evidence,
            Spacer(1, 0.1*inch),
            remediation
        ]))
        
        return elements
    
    def _create_footer(self) -> List:
        """Create report footer"""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Spacer(1, 1*inch))
        
        footer_text = """
        <b>Disclaimer:</b><br/>
        This report is provided for informational purposes only. The findings represent 
        potential security issues identified through automated scanning. Manual verification 
        and testing are recommended before taking remediation actions.<br/><br/>
        
        <b>Report Generated by:</b> MCP Security Scanner v0.1.0<br/>
        <b>Generated:</b> """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """<br/><br/>
        
        For more information, visit: https://github.com/Latteflo/mpc-security-scanner
        """
        
        footer = Paragraph(footer_text, self.styles['Normal'])
        elements.append(footer)
        
        return elements
