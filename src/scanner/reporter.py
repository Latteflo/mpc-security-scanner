"""
Report Generation Module
Creates reports in various formats
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List


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
        format: str = "json"
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
            target=server_info,
            vulnerabilities=vulnerabilities,
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
            return await self._generate_html(report, output_path)
        else:  # terminal
            self._display_terminal(report)
            return "terminal"
    
    async def _generate_json(self, report: ScanReport, output_path: str) -> str:
        """Generate JSON report"""
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        report.save_json(output_file)
        
        logger.info(f"JSON report saved to {output_file}")
        return str(output_file)
    
    async def _generate_html(self, report: ScanReport, output_path: str) -> str:
        """Generate HTML report"""
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = self._create_html_report(report)
        
        with open(output_file, "w") as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {output_file}")
        return str(output_file)
    
    def _display_terminal(self, report: ScanReport):
        """Display report in terminal"""
        
        console.print("\n[bold]📊 Scan Report Summary[/bold]\n")
        
        # Server info
        console.print(f"[cyan]Target:[/cyan] {report.target.url}")
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
    
    def _create_html_report(self, report: ScanReport) -> str:
        """Create HTML report content"""
        
        severity_counts = report.severity_counts
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MCP Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .vulnerability {{ margin: 20px 0; padding: 15px; border-left: 4px solid; }}
        .critical {{ border-color: #d32f2f; background: #ffebee; }}
        .high {{ border-color: #f57c00; background: #fff3e0; }}
        .medium {{ border-color: #fbc02d; background: #fffde7; }}
        .low {{ border-color: #1976d2; background: #e3f2fd; }}
        .info {{ border-color: #388e3c; background: #e8f5e9; }}
    </style>
</head>
<body>
    <h1>🔒 MCP Security Scan Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Target:</strong> {report.target.url}</p>
        <p><strong>Scan ID:</strong> {report.scan_id}</p>
        <p><strong>Date:</strong> {report.completed_at}</p>
        <p><strong>Duration:</strong> {report.duration_seconds:.2f}s</p>
        <p><strong>Risk Score:</strong> {report.risk_score}/100</p>
        <p><strong>Vulnerabilities Found:</strong> {len(report.vulnerabilities)}</p>
        <ul>
            <li>Critical: {severity_counts['CRITICAL']}</li>
            <li>High: {severity_counts['HIGH']}</li>
            <li>Medium: {severity_counts['MEDIUM']}</li>
            <li>Low: {severity_counts['LOW']}</li>
            <li>Info: {severity_counts['INFO']}</li>
        </ul>
    </div>
    
    <h2>Vulnerabilities</h2>
"""
        
        for vuln in report.vulnerabilities:
            severity_class = vuln.severity.value.lower()
            html += f"""
    <div class="vulnerability {severity_class}">
        <h3>{vuln.title}</h3>
        <p><strong>Severity:</strong> {vuln.severity.value}</p>
        <p><strong>Category:</strong> {vuln.category}</p>
        <p>{vuln.description}</p>
        <p><strong>Remediation:</strong></p>
        <pre>{vuln.remediation}</pre>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        return html
