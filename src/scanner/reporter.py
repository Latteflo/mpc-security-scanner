"""
Report Generation Module
Creates reports in various formats
"""

import json
import sys
from pathlib import Path
from typing import List
from datetime import datetime

from rich.console import Console

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import MCPServer, Vulnerability, ScanReport, Severity
from utils.logger import get_logger

console = Console()
logger = get_logger("reporter")


class ReportGenerator:
    """Generates security scan reports"""
    
    async def generate(
        self,
        server_info: MCPServer,
        vulnerabilities: List[Vulnerability],
        output_path: str,
        format: str = "json"  # json, html, pdf, terminal
    ) -> str:
        """
        Generate a report
        
        Args:
            server_info: Scanned server information
            vulnerabilities: List of found vulnerabilities
            output_path: Path to save report
            format: Report format (json, html, terminal)
            
        Returns:
            Path to generated report
        """
        logger.info(f"Generating {format} report...")
        
        # Create scan report object
        report = ScanReport(
            scan_id=f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            target=server_info.to_dict(),
            vulnerabilities=[v.to_dict() for v in vulnerabilities],
            total_checks=5,
            failed_checks=len(vulnerabilities),
            passed_checks=5 - len(vulnerabilities)
        )
        
        report.completed_at = datetime.now()
        duration = (report.completed_at - report.started_at).total_seconds()
        report.duration_seconds = duration
        
        # Generate based on format
        if format == "json":
            return await self._generate_json(report, output_path)
        elif format == "html":
            return await self._generate_html(report, output_path, server_info, vulnerabilities)
        else:  # terminal
            self._display_terminal(report, server_info, vulnerabilities)
            return "terminal"
    
    async def _generate_json(self, report: ScanReport, output_path: str) -> str:
        """Generate JSON report"""
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        report.save_json(output_file)
        
        logger.info(f"JSON report saved to {output_file}")
        return str(output_file)
    
    async def _generate_html(self, report: ScanReport, output_path: str, 
                            server_info: MCPServer, vulnerabilities: List[Vulnerability]) -> str:
        """Generate HTML report"""
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = self._create_html_report(report, server_info, vulnerabilities)
        
        with open(output_file, "w") as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {output_file}")
        return str(output_file)
    
    def _display_terminal(self, report: ScanReport, server_info: MCPServer, 
                         vulnerabilities: List[Vulnerability]):
        """Display report in terminal"""
        
        console.print("\n[bold]📊 Scan Report Summary[/bold]\n")
        
        # Server info
        console.print(f"[cyan]Target:[/cyan] {server_info.url}")
        console.print(f"[cyan]Scan ID:[/cyan] {report.scan_id}")
        console.print(f"[cyan]Duration:[/cyan] {report.duration_seconds:.2f}s\n")
        
        # Statistics
        console.print(f"[cyan]Total Checks:[/cyan] {report.total_checks}")
        console.print(f"[green]Passed:[/green] {report.passed_checks}")
        console.print(f"[red]Failed:[/red] {report.failed_checks}\n")
        
        # Risk score
        risk_score = report.risk_score
        risk_color = "red" if risk_score > 70 else "yellow" if risk_score > 40 else "green"
        console.print(f"[{risk_color}]Risk Score:[/{risk_color}] {risk_score}/100\n")
    
    def _create_html_report(self, report: ScanReport, server_info: MCPServer,
                           vulnerabilities: List[Vulnerability]) -> str:
        """Create HTML report content"""
        
        severity_counts = report.severity_counts
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MCP Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat {{ background: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 32px; font-weight: bold; margin: 5px 0; }}
        .vulnerability {{ margin: 20px 0; padding: 20px; border-left: 5px solid; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .critical {{ border-color: #d32f2f; background: #ffebee; }}
        .high {{ border-color: #f57c00; background: #fff3e0; }}
        .medium {{ border-color: #fbc02d; background: #fffde7; }}
        .low {{ border-color: #1976d2; background: #e3f2fd; }}
        .info {{ border-color: #388e3c; background: #e8f5e9; }}
        .severity-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 12px; }}
        .critical-badge {{ background: #d32f2f; }}
        .high-badge {{ background: #f57c00; }}
        .medium-badge {{ background: #fbc02d; color: #333; }}
        .low-badge {{ background: #1976d2; }}
        .info-badge {{ background: #388e3c; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        .risk-score {{ font-size: 48px; font-weight: bold; text-align: center; padding: 20px; }}
        .risk-high {{ color: #d32f2f; }}
        .risk-medium {{ color: #f57c00; }}
        .risk-low {{ color: #388e3c; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 MCP Security Scan Report</h1>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Target:</strong> {server_info.url}</p>
            <p><strong>Server Name:</strong> {server_info.name or 'Unknown'}</p>
            <p><strong>Scan ID:</strong> {report.scan_id}</p>
            <p><strong>Date:</strong> {report.completed_at}</p>
            <p><strong>Duration:</strong> {report.duration_seconds:.2f}s</p>
            
            <div class="risk-score {'risk-high' if report.risk_score > 70 else 'risk-medium' if report.risk_score > 40 else 'risk-low'}">
                Risk Score: {report.risk_score}/100
            </div>
        </div>
        
        <h2>Statistics</h2>
        <div class="stats">
            <div class="stat">
                <div>Total Checks</div>
                <div class="stat-value">{report.total_checks}</div>
            </div>
            <div class="stat">
                <div>Vulnerabilities</div>
                <div class="stat-value" style="color: #d32f2f;">{len(vulnerabilities)}</div>
            </div>
            <div class="stat">
                <div>Critical</div>
                <div class="stat-value" style="color: #d32f2f;">{severity_counts['CRITICAL']}</div>
            </div>
            <div class="stat">
                <div>High</div>
                <div class="stat-value" style="color: #f57c00;">{severity_counts['HIGH']}</div>
            </div>
            <div class="stat">
                <div>Medium</div>
                <div class="stat-value" style="color: #fbc02d;">{severity_counts['MEDIUM']}</div>
            </div>
            <div class="stat">
                <div>Low</div>
                <div class="stat-value" style="color: #1976d2;">{severity_counts['LOW']}</div>
            </div>
        </div>
        
        <h2>Vulnerabilities</h2>
"""
        
        for vuln in vulnerabilities:
            severity_class = vuln.severity.value.lower()
            badge_class = f"{severity_class}-badge"
            html += f"""
        <div class="vulnerability {severity_class}">
            <h3>
                <span class="severity-badge {badge_class}">{vuln.severity.value}</span>
                {vuln.title}
            </h3>
            <p><strong>ID:</strong> {vuln.id} | <strong>Category:</strong> {vuln.category}</p>
            <p>{vuln.description}</p>
            <p><strong>Remediation:</strong></p>
            <pre>{vuln.remediation}</pre>
            <p><strong>Evidence:</strong></p>
            <ul>
"""
            for evidence in vuln.evidence:
                html += f"                <li>{evidence}</li>\n"
            
            html += """            </ul>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        return html

# PDF generation support
async def _generate_pdf(self, report: ScanReport, output_path: str,
                       server_info: MCPServer, vulnerabilities: List[Vulnerability]) -> str:
    """Generate PDF report"""
    from .pdf_reporter import PDFReportGenerator
    
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    pdf_generator = PDFReportGenerator()
    pdf_path = pdf_generator.generate(
        server_info=server_info,
        vulnerabilities=vulnerabilities,
        output_path=str(output_file)
    )
    
    logger.info(f"PDF report saved to {pdf_path}")
    return pdf_path
