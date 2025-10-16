"""
Compliance-focused Report Generator
Generates compliance reports for auditing purposes
"""

import sys
from pathlib import Path
from typing import List, Dict
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import MCPServer, Vulnerability
from compliance.mapper import ComplianceMapper
from compliance.frameworks import ComplianceFramework
from utils.logger import get_logger

logger = get_logger("compliance_reporter")


class ComplianceReportGenerator:
    """Generates compliance-focused reports"""
    
    def __init__(self):
        self.mapper = ComplianceMapper()
    
    def generate_terminal_report(
        self,
        server: MCPServer,
        vulnerabilities: List[Vulnerability]
    ):
        """Generate terminal-based compliance report"""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        
        console = Console()
        
        # Header
        console.print("\n")
        console.print("=" * 80)
        console.print("  🔒 COMPLIANCE ASSESSMENT REPORT", style="bold cyan")
        console.print("=" * 80)
        console.print()
        
        # Server Info
        info_table = Table(show_header=False, box=box.SIMPLE)
        info_table.add_column("Field", style="bold cyan")
        info_table.add_column("Value")
        info_table.add_row("Target Server", server.url)
        info_table.add_row("Server Name", server.name or "Unknown")
        info_table.add_row("Assessment Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        info_table.add_row("Total Vulnerabilities", str(len(vulnerabilities)))
        
        console.print(Panel(info_table, title="Assessment Overview", border_style="cyan"))
        console.print()
        
        # Get compliance summary
        vuln_dicts = [v.to_dict() for v in vulnerabilities]
        summary = self.mapper.get_compliance_summary(vuln_dicts)
        
        # Framework Summary Table
        console.print("[bold]Compliance Framework Summary[/bold]\n")
        
        framework_table = Table(show_header=True, box=box.ROUNDED)
        framework_table.add_column("Framework", style="bold")
        framework_table.add_column("Status", justify="center")
        framework_table.add_column("Affected Controls", justify="center")
        framework_table.add_column("Critical", justify="center", style="red")
        framework_table.add_column("High", justify="center", style="orange1")
        
        for framework, data in summary.items():
            framework_name = self.mapper._get_framework_name(framework)
            status = "❌ Non-Compliant" if data['compliance_status'] == 'NON_COMPLIANT' else "✅ Compliant"
            
            framework_table.add_row(
                framework_name,
                status,
                str(data['affected_control_count']),
                str(data['critical_vulns']),
                str(data['high_vulns'])
            )
        
        console.print(framework_table)
        console.print()
        
        # Detailed Framework Analysis
        console.print("[bold]Detailed Framework Analysis[/bold]\n")
        
        for framework in [ComplianceFramework.ISO27001, ComplianceFramework.NIST_CSF, 
                          ComplianceFramework.NIST_800_53, ComplianceFramework.MITRE_ATTCK]:
            if framework in summary:
                self._print_framework_details(console, framework, vuln_dicts)
        
        # Remediation Priority
        console.print("\n[bold]Remediation Priorities[/bold]\n")
        self._print_remediation_priorities(console, vulnerabilities)
        
        console.print("\n" + "=" * 80)
        console.print()
    
    def _print_framework_details(
        self,
        console,
        framework: ComplianceFramework,
        vulnerabilities: List[Dict]
    ):
        """Print detailed framework analysis"""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        
        gap_analysis = self.mapper.get_framework_gap_analysis(vulnerabilities, framework)
        
        framework_name = gap_analysis['framework_name']
        
        console.print(f"\n[bold cyan]📋 {framework_name}[/bold cyan]")
        console.print(f"Status: [red]NON-COMPLIANT[/red] | Affected Controls: {gap_analysis['total_affected_controls']}")
        
        # Controls table
        if gap_analysis['affected_controls']:
            control_table = Table(show_header=True, box=box.SIMPLE)
            control_table.add_column("Control ID", style="bold red")
            control_table.add_column("Control Name")
            control_table.add_column("Category", style="dim")
            
            for control in gap_analysis['affected_controls'][:10]:  # Show top 10
                control_table.add_row(
                    control['id'],
                    control['name'][:50] + "..." if len(control['name']) > 50 else control['name'],
                    control['category'][:30] + "..." if len(control['category']) > 30 else control['category']
                )
            
            console.print(control_table)
            
            if len(gap_analysis['affected_controls']) > 10:
                console.print(f"[dim]... and {len(gap_analysis['affected_controls']) - 10} more controls[/dim]")
    
    def _print_remediation_priorities(self, console, vulnerabilities: List[Vulnerability]):
        """Print remediation priorities"""
        from rich.table import Table
        from rich import box
        
        # Group by severity
        critical = [v for v in vulnerabilities if v.severity.value == "CRITICAL"]
        high = [v for v in vulnerabilities if v.severity.value == "HIGH"]
        
        priority_table = Table(show_header=True, box=box.ROUNDED)
        priority_table.add_column("Priority", style="bold")
        priority_table.add_column("Vulnerability", style="bold")
        priority_table.add_column("Frameworks Affected", justify="center")
        
        priority = 1
        for vuln in critical[:5]:  # Top 5 critical
            frameworks = self.mapper.get_frameworks(vuln.id)
            priority_table.add_row(
                f"P{priority}",
                vuln.title[:50] + "..." if len(vuln.title) > 50 else vuln.title,
                str(len(frameworks))
            )
            priority += 1
        
        for vuln in high[:3]:  # Top 3 high
            frameworks = self.mapper.get_frameworks(vuln.id)
            priority_table.add_row(
                f"P{priority}",
                vuln.title[:50] + "..." if len(vuln.title) > 50 else vuln.title,
                str(len(frameworks))
            )
            priority += 1
        
        console.print(priority_table)
    
    def generate_json_report(
        self,
        server: MCPServer,
        vulnerabilities: List[Vulnerability],
        output_path: str
    ) -> str:
        """Generate JSON compliance report"""
        import json
        
        vuln_dicts = [v.to_dict() for v in vulnerabilities]
        summary = self.mapper.get_compliance_summary(vuln_dicts)
        
        # Build comprehensive report
        report = {
            'report_type': 'compliance_assessment',
            'generated_at': datetime.now().isoformat(),
            'server': server.to_dict(),
            'vulnerabilities': vuln_dicts,
            'compliance_summary': {
                framework.value: data 
                for framework, data in summary.items()
            },
            'framework_gap_analysis': {}
        }
        
        # Add detailed gap analysis for each framework
        for framework in summary.keys():
            gap_analysis = self.mapper.get_framework_gap_analysis(vuln_dicts, framework)
            report['framework_gap_analysis'][framework.value] = gap_analysis
        
        # Save report
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"JSON compliance report saved to {output_file}")
        return str(output_file)
    
    def generate_markdown_report(
        self,
        server: MCPServer,
        vulnerabilities: List[Vulnerability],
        output_path: str
    ) -> str:
        """Generate Markdown compliance report"""
        
        vuln_dicts = [v.to_dict() for v in vulnerabilities]
        summary = self.mapper.get_compliance_summary(vuln_dicts)
        
        md = []
        md.append("# 🔒 Compliance Assessment Report\n")
        md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        md.append(f"**Target:** {server.url}\n")
        md.append(f"**Server Name:** {server.name or 'Unknown'}\n")
        md.append(f"**Total Vulnerabilities:** {len(vulnerabilities)}\n")
        md.append("\n---\n")
        
        # Executive Summary
        md.append("## Executive Summary\n")
        md.append(f"This compliance assessment identified **{len(vulnerabilities)} security issues** ")
        md.append(f"affecting **{len(summary)} compliance frameworks**.\n\n")
        
        # Framework Summary Table
        md.append("## Framework Compliance Status\n\n")
        md.append("| Framework | Status | Affected Controls | Critical | High |\n")
        md.append("|-----------|--------|-------------------|----------|------|\n")
        
        for framework, data in summary.items():
            framework_name = self.mapper._get_framework_name(framework)
            status = "❌ Non-Compliant" if data['compliance_status'] == 'NON_COMPLIANT' else "✅ Compliant"
            md.append(f"| {framework_name} | {status} | {data['affected_control_count']} | ")
            md.append(f"{data['critical_vulns']} | {data['high_vulns']} |\n")
        
        md.append("\n---\n")
        
        # Detailed Analysis per Framework
        for framework in summary.keys():
            gap_analysis = self.mapper.get_framework_gap_analysis(vuln_dicts, framework)
            
            md.append(f"\n## {gap_analysis['framework_name']}\n\n")
            md.append(f"**Status:** {gap_analysis['compliance_status']}\n")
            md.append(f"**Risk Level:** {gap_analysis['risk_level']}\n")
            md.append(f"**Affected Controls:** {gap_analysis['total_affected_controls']}\n\n")
            
            md.append("### Affected Controls\n\n")
            md.append("| Control ID | Control Name | Category |\n")
            md.append("|------------|--------------|----------|\n")
            
            for control in gap_analysis['affected_controls']:
                md.append(f"| {control['id']} | {control['name']} | {control['category']} |\n")
            
            md.append("\n")
        
        # Remediation Recommendations
        md.append("## Remediation Recommendations\n\n")
        md.append("### Critical Priority\n\n")
        
        critical_vulns = [v for v in vulnerabilities if v.severity.value == "CRITICAL"]
        for i, vuln in enumerate(critical_vulns, 1):
            md.append(f"{i}. **{vuln.title}** ({vuln.id})\n")
            md.append(f"   - {vuln.description[:100]}...\n")
            frameworks = self.mapper.get_frameworks(vuln.id)
            md.append(f"   - Affects {len(frameworks)} frameworks\n\n")
        
        # Save report
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write(''.join(md))
        
        logger.info(f"Markdown compliance report saved to {output_file}")
        return str(output_file)
