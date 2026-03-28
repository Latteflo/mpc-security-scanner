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

# The number of distinct security checks the analyzer runs.
# This must match the number of _check_* methods called in SecurityAnalyzer.scan().
# Update this constant whenever a check is added or removed from the analyzer.
#
# Current checks (13):
#   Auth, Encryption, Tools Exposure, Config (port), Config (version disclosure),
#   CORS, Rate Limiting, SQL Injection, Command Injection, Path Traversal,
#   Tool Poisoning (AI-001), Over-permissive Schema (AI-002), Indirect Injection (AI-003)
TOTAL_CHECKS = 13


class ReportGenerator:
    """Generates security scan reports"""

    async def generate(
        self,
        server_info: MCPServer,
        vulnerabilities: List[Vulnerability],
        output_path: str,
        format: str = "json",  # json, html, pdf, terminal
    ) -> str:
        """
        Generate a report.

        Args:
            server_info: Scanned server information
            vulnerabilities: List of found vulnerabilities
            output_path: Path to save report
            format: Report format (json, html, pdf, terminal)

        Returns:
            Path to generated report
        """
        logger.info(f"Generating {format} report...")

        # `failed_checks` is the count of individual vulnerability findings, not
        # the count of check methods that found something. A single check method
        # (e.g. _check_configuration) can contribute multiple findings (port +
        # version). We cap passed_checks at 0 to avoid negative numbers when
        # findings exceed TOTAL_CHECKS.
        report = ScanReport(
            scan_id=f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            target=server_info.to_dict(),
            vulnerabilities=[v.to_dict() for v in vulnerabilities],
            total_checks=TOTAL_CHECKS,
            failed_checks=len(vulnerabilities),
            passed_checks=max(0, TOTAL_CHECKS - len(vulnerabilities)),
        )

        report.completed_at = datetime.now()
        duration = (report.completed_at - report.started_at).total_seconds()
        report.duration_seconds = duration

        if format == "json":
            return await self._generate_json(report, output_path)
        elif format == "html":
            return await self._generate_html(report, output_path, server_info, vulnerabilities)
        elif format == "pdf":
            return await self._generate_pdf(report, output_path, server_info, vulnerabilities)
        elif format == "sarif":
            return await self._generate_sarif(report, output_path, server_info, vulnerabilities)
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

    async def _generate_html(
        self,
        report: ScanReport,
        output_path: str,
        server_info: MCPServer,
        vulnerabilities: List[Vulnerability],
    ) -> str:
        """Generate HTML report"""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        html_content = self._create_html_report(report, server_info, vulnerabilities)
        with open(output_file, "w") as f:
            f.write(html_content)
        logger.info(f"HTML report saved to {output_file}")
        return str(output_file)

    async def _generate_pdf(
        self,
        report: ScanReport,
        output_path: str,
        server_info: MCPServer,
        vulnerabilities: List[Vulnerability],
    ) -> str:
        """Generate PDF report via PDFReportGenerator."""
        # PDFReportGenerator handles its own file creation and path setup.
        # We delegate entirely rather than duplicating the logic here.
        from .pdf_reporter import PDFReportGenerator

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        pdf_generator = PDFReportGenerator()
        pdf_path = pdf_generator.generate(
            server_info=server_info,
            vulnerabilities=vulnerabilities,
            output_path=str(output_file),
        )
        logger.info(f"PDF report saved to {pdf_path}")
        return pdf_path

    async def _generate_sarif(
        self,
        report: ScanReport,
        output_path: str,
        server_info: MCPServer,
        vulnerabilities: List[Vulnerability],
    ) -> str:
        """
        Generate a SARIF 2.1.0 report.

        SARIF (Static Analysis Results Interchange Format) is the standard
        consumed by GitHub's Security tab, VS Code's Problems pane, and most
        CI/CD security dashboards. Producing SARIF means scan findings appear
        inline on pull requests without any extra tooling.

        Structure:
          - Each unique vulnerability ID becomes a `rule` in the tool driver.
          - Each finding instance becomes a `result` referencing its rule.
          - Severity maps to SARIF `level`: CRITICAL/HIGH → error,
            MEDIUM → warning, LOW/INFO → note.
          - The target URL is the artifact location (no physical file path,
            since we're scanning a network service, not source code).
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # SARIF level mapping
        def sarif_level(severity_value: str) -> str:
            return {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note",
                "INFO": "note",
            }.get(severity_value, "warning")

        # Build the rules list from the unique vulnerability IDs seen in this scan.
        # We deduplicate because the same check ID can appear multiple times if
        # the scanner finds the same issue on different tools/endpoints.
        seen_rule_ids: set = set()
        rules = []
        for vuln in vulnerabilities:
            if vuln.id in seen_rule_ids:
                continue
            seen_rule_ids.add(vuln.id)
            rules.append({
                "id": vuln.id,
                "name": vuln.title.replace(" ", ""),  # camelCase per SARIF convention
                "shortDescription": {"text": vuln.title},
                "fullDescription": {"text": vuln.description},
                "defaultConfiguration": {"level": sarif_level(vuln.severity.value)},
                "properties": {
                    "category": vuln.category,
                    "cwe": vuln.cwe_id or "",
                    "cvssScore": vuln.cvss_score or 0.0,
                },
            })

        # Build the results list — one entry per finding instance
        results = []
        for vuln in vulnerabilities:
            result = {
                "ruleId": vuln.id,
                "level": sarif_level(vuln.severity.value),
                "message": {
                    "text": (
                        f"{vuln.description}\n\n"
                        f"Remediation: {vuln.remediation}\n\n"
                        f"Evidence: {'; '.join(vuln.evidence)}"
                    )
                },
                # Network services don't have source file locations, so we use
                # the server URL as the artifact URI. This is a common pattern
                # for DAST (dynamic analysis) SARIF reports.
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": server_info.url,
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": vuln.severity.value,
                    "category": vuln.category,
                    "affectedComponent": vuln.affected_component or "",
                },
            }
            results.append(result)

        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MCP Security Scanner",
                            "version": "0.2.1",
                            "informationUri": "https://github.com/Latteflo/mcp-security-scanner",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    # Invocation metadata — useful for audit trails in GitHub
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "commandLine": f"mcp-security-scanner scan --target {server_info.url}",
                            "startTimeUtc": report.started_at.isoformat(),
                            "endTimeUtc": report.completed_at.isoformat()
                            if report.completed_at
                            else None,
                        }
                    ],
                }
            ],
        }

        with open(output_file, "w") as f:
            json.dump(sarif_doc, f, indent=2, default=str)

        logger.info(f"SARIF report saved to {output_file}")
        return str(output_file)

    def _display_terminal(
        self,
        report: ScanReport,
        server_info: MCPServer,
        vulnerabilities: List[Vulnerability],
    ):
        """Display report in terminal"""
        console.print("\n[bold]📊 Scan Report Summary[/bold]\n")
        console.print(f"[cyan]Target:[/cyan] {server_info.url}")
        console.print(f"[cyan]Scan ID:[/cyan] {report.scan_id}")
        console.print(f"[cyan]Duration:[/cyan] {report.duration_seconds:.2f}s\n")
        console.print(f"[cyan]Total Checks:[/cyan] {report.total_checks}")
        console.print(f"[green]Passed:[/green] {report.passed_checks}")
        console.print(f"[red]Failed:[/red] {report.failed_checks}\n")
        risk_score = report.risk_score
        risk_color = "red" if risk_score > 70 else "yellow" if risk_score > 40 else "green"
        console.print(f"[{risk_color}]Risk Score:[/{risk_color}] {risk_score}/100\n")

    def _create_html_report(
        self,
        report: ScanReport,
        server_info: MCPServer,
        vulnerabilities: List[Vulnerability],
    ) -> str:
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
