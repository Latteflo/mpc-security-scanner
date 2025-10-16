import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from scanner import MCPDiscovery, SecurityAnalyzer, ReportGenerator
from utils import setup_logger

console = Console()


@click.group()
@click.version_option(version="0.2.0")
def cli():
    """
    🔒 MCP Security Scanner & Auditor
    
    A comprehensive security auditing tool for Model Context Protocol servers
    with compliance framework support.
    """
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="Target MCP server URL")
@click.option("--output", "-o", default="reports/scan_results.json", help="Output file")
@click.option("--format", "-f", type=click.Choice(["json", "html", "terminal", "pdf"]), default="terminal")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def scan(target: str, output: str, format: str, verbose: bool):
    """Scan an MCP server for security vulnerabilities."""
    
    async def run_scan():
        # Setup logger
        log_level = "DEBUG" if verbose else "INFO"
        logger = setup_logger(level=log_level)
        
        console.print(f"\n[bold cyan]🔍 Starting MCP Security Scan[/bold cyan]")
        console.print(f"[dim]Target: {target}[/dim]\n")
        
        try:
            # Phase 1: Discovery
            with console.status("[bold green]Discovering MCP server..."):
                discovery = MCPDiscovery()
                server_info = await discovery.probe_server(target)
                
                if not server_info:
                    console.print("[bold red]❌ Could not connect to MCP server[/bold red]")
                    console.print("[dim]Make sure the server is running and accessible[/dim]")
                    return
                
                console.print(f"[green]✓[/green] Server discovered")
                if server_info.name:
                    console.print(f"  Name: {server_info.name}")
                if server_info.version:
                    console.print(f"  Version: {server_info.version}")
                console.print(f"  Tools: {len(server_info.tools)}")
                console.print(f"  Resources: {len(server_info.resources)}")
                console.print()
            
            # Phase 2: Analysis
            with console.status("[bold green]Analyzing security posture..."):
                analyzer = SecurityAnalyzer()
                vulnerabilities = await analyzer.scan(server_info)
                
                console.print(f"[green]✓[/green] Analysis complete")
                console.print(f"  Found {len(vulnerabilities)} potential issues\n")
            
            # Phase 3: Reporting
            console.print("[bold]📊 Scan Results:[/bold]\n")
            
            # Create summary table
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Severity", style="dim")
            table.add_column("Count", justify="right")
            
            severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
            
            for vuln in vulnerabilities:
                severity_counts[vuln.severity.value] += 1
            
            for severity, count in severity_counts.items():
                if count > 0:
                    color = {
                        "CRITICAL": "red",
                        "HIGH": "orange1",
                        "MEDIUM": "yellow",
                        "LOW": "blue",
                        "INFO": "green"
                    }[severity]
                    table.add_row(f"[{color}]{severity}[/{color}]", str(count))
            
            console.print(table)
            
            # Display top vulnerabilities
            if vulnerabilities:
                console.print("\n[bold]🚨 Key Findings:[/bold]\n")
                for i, vuln in enumerate(vulnerabilities[:5], 1):
                    color = vuln.severity_color
                    console.print(f"  {i}. [{color}]{vuln.title}[/{color}]")
                    console.print(f"     [dim]{vuln.description[:100]}...[/dim]\n")
            
            # Generate report
            if format != "terminal":
                reporter = ReportGenerator()
                report_path = await reporter.generate(
                    server_info=server_info,
                    vulnerabilities=vulnerabilities,
                    output_path=output,
                    format=format
                )
                console.print(f"\n[green]✓[/green] Report saved to: {report_path}")
            
            console.print("\n[bold green]✅ Scan completed successfully![/bold green]\n")
            
        except Exception as e:
            console.print(f"\n[bold red]❌ Error during scan:[/bold red] {str(e)}")
            if verbose:
                console.print_exception()
            sys.exit(1)
    
    asyncio.run(run_scan())


@cli.command()
@click.option("--target", "-t", required=True, help="Target MCP server URL")
@click.option("--output", "-o", default="reports/compliance_report.json", help="Output file")
@click.option("--format", "-f", type=click.Choice(["json", "terminal", "markdown"]), default="terminal")
@click.option("--framework", "-fw", multiple=True, 
              type=click.Choice(["ISO27001", "NIST_CSF", "NIST_800_53", "MITRE_ATTCK", "PCI_DSS", "SOC2"]),
              help="Specific frameworks to assess (can be used multiple times)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def compliance(target: str, output: str, format: str, framework: tuple, verbose: bool):
    """Run compliance assessment against security frameworks.
    
    Examples:
        # Full compliance assessment (all frameworks)
        python src/main.py compliance --target http://localhost:3000
        
        # Specific frameworks only
        python src/main.py compliance --target http://localhost:3000 -fw ISO27001 -fw NIST_CSF
        
        # Generate JSON report
        python src/main.py compliance --target http://localhost:3000 --format json
    """
    
    async def run_compliance():
        from compliance import ComplianceReportGenerator
        
        log_level = "DEBUG" if verbose else "INFO"
        logger = setup_logger(level=log_level)
        
        console.print(f"\n[bold cyan]🔒 Starting Compliance Assessment[/bold cyan]")
        console.print(f"[dim]Target: {target}[/dim]")
        
        if framework:
            console.print(f"[dim]Frameworks: {', '.join(framework)}[/dim]")
        else:
            console.print(f"[dim]Frameworks: ALL (ISO27001, NIST CSF, NIST 800-53, MITRE ATT&CK, PCI DSS, SOC2)[/dim]")
        
        console.print()
        
        try:
            # Phase 1: Discovery
            with console.status("[bold green]Discovering MCP server..."):
                discovery = MCPDiscovery()
                server_info = await discovery.probe_server(target)
                
                if not server_info:
                    console.print("[bold red]❌ Could not connect to MCP server[/bold red]")
                    console.print("[dim]Make sure the server is running and accessible[/dim]")
                    return
                
                console.print(f"[green]✓[/green] Server discovered: {server_info.name or server_info.url}")
            
            # Phase 2: Security Analysis
            with console.status("[bold green]Performing security analysis..."):
                analyzer = SecurityAnalyzer()
                vulnerabilities = await analyzer.scan(server_info)
                
                console.print(f"[green]✓[/green] Found {len(vulnerabilities)} vulnerabilities")
            
            # Phase 3: Compliance Reporting
            reporter = ComplianceReportGenerator()
            
            if format == "terminal":
                console.print()
                reporter.generate_terminal_report(server_info, vulnerabilities)
            elif format == "json":
                report_path = reporter.generate_json_report(server_info, vulnerabilities, output)
                console.print(f"\n[green]✓[/green] JSON compliance report saved to: [bold]{report_path}[/bold]")
            elif format == "markdown":
                report_path = reporter.generate_markdown_report(server_info, vulnerabilities, output)
                console.print(f"\n[green]✓[/green] Markdown compliance report saved to: [bold]{report_path}[/bold]")
            
            console.print("\n[bold green]✅ Compliance assessment completed![/bold green]\n")
            
        except Exception as e:
            console.print(f"\n[bold red]❌ Error during compliance assessment:[/bold red] {str(e)}")
            if verbose:
                import traceback
                console.print(traceback.format_exc())
            sys.exit(1)
    
    asyncio.run(run_compliance())


@cli.command()
@click.option("--framework", "-f", 
              type=click.Choice(["ISO27001", "NIST_CSF", "NIST_800_53", "MITRE_ATTCK", "PCI_DSS", "SOC2", "ALL"]),
              default="ALL",
              help="Framework to display controls for")
def frameworks(framework: str):
    """List supported compliance frameworks and their controls.
    
    Examples:
        # Show all frameworks
        python src/main.py frameworks
        
        # Show ISO 27001 controls
        python src/main.py frameworks --framework ISO27001
        
        # Show NIST CSF controls
        python src/main.py frameworks --framework NIST_CSF
    """
    
    try:
        from compliance import (
            ISO27001_CONTROLS,
            NIST_CSF_CONTROLS,
            NIST_800_53_CONTROLS,
            MITRE_ATTCK_TECHNIQUES,
            PCI_DSS_CONTROLS,
            SOC2_CONTROLS,
        )
    except ImportError:
        console.print("[bold red]❌ Compliance module not found![/bold red]")
        console.print("Make sure compliance module is properly installed.")
        sys.exit(1)
    
    console.print("\n[bold cyan]📋 Compliance Frameworks[/bold cyan]\n")
    
    frameworks_data = {
        "ISO27001": ("ISO/IEC 27001:2013", ISO27001_CONTROLS, "Information Security Management System"),
        "NIST_CSF": ("NIST Cybersecurity Framework", NIST_CSF_CONTROLS, "Risk-based cybersecurity approach"),
        "NIST_800_53": ("NIST SP 800-53 Rev. 5", NIST_800_53_CONTROLS, "Security and privacy controls"),
        "MITRE_ATTCK": ("MITRE ATT&CK", MITRE_ATTCK_TECHNIQUES, "Adversarial tactics and techniques"),
        "PCI_DSS": ("PCI DSS 3.2.1", PCI_DSS_CONTROLS, "Payment Card Industry security"),
        "SOC2": ("SOC 2 Type II", SOC2_CONTROLS, "Service Organization Controls"),
    }
    
    if framework == "ALL":
        # Summary table of all frameworks
        summary_table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        summary_table.add_column("Framework", style="cyan", width=15)
        summary_table.add_column("Full Name", width=35)
        summary_table.add_column("Controls", justify="center", width=10)
        summary_table.add_column("Description", style="dim", width=30)
        
        for fw_key, (fw_name, controls, description) in frameworks_data.items():
            summary_table.add_row(
                fw_key,
                fw_name,
                str(len(controls)),
                description
            )
        
        console.print(summary_table)
        console.print("\n[dim]💡 Use --framework <NAME> to see detailed controls for a specific framework[/dim]")
        console.print("[dim]   Example: python src/main.py frameworks --framework ISO27001[/dim]\n")
    
    else:
        # Detailed view of specific framework
        if framework not in frameworks_data:
            console.print(f"[bold red]❌ Unknown framework: {framework}[/bold red]")
            return
        
        fw_name, controls, description = frameworks_data[framework]
        
        console.print(f"[bold]{fw_name}[/bold]")
        console.print(f"[dim]{description}[/dim]")
        console.print(f"\nTotal Controls: [bold cyan]{len(controls)}[/bold cyan]\n")
        
        # Detailed controls table
        control_table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        control_table.add_column("Control ID", style="bold cyan", width=12)
        control_table.add_column("Name", width=40)
        control_table.add_column("Category", style="dim", width=35)
        
        for control_id, control in sorted(controls.items()):
            name = control.name
            if len(name) > 40:
                name = name[:37] + "..."
            
            category = control.category
            if len(category) > 35:
                category = category[:32] + "..."
            
            control_table.add_row(
                control.id,
                name,
                category
            )
        
        console.print(control_table)
        console.print()


@cli.command()
@click.option("--range", "-r", required=True, help="IP range to scan (CIDR notation)")
@click.option("--ports", "-p", default="3000,8080", help="Ports to scan (comma-separated)")
def discover(range: str, ports: str):
    """Discover MCP servers on a network (EXPERIMENTAL).
    
    Examples:
        python src/main.py discover --range 192.168.1.0/24
        python src/main.py discover --range 10.0.0.0/24 --ports 3000,8080,5000
    """
    
    async def run_discovery():
        console.print(f"\n[bold cyan]🔍 Discovering MCP Servers[/bold cyan]")
        console.print(f"[dim]Range: {range}[/dim]")
        console.print(f"[dim]Ports: {ports}[/dim]\n")
        
        port_list = [int(p.strip()) for p in ports.split(",")]
        
        discovery = MCPDiscovery()
        servers = await discovery.network_scan(range, port_list)
        
        if not servers:
            console.print("[yellow]⚠ Network scanning feature is experimental[/yellow]")
            console.print("[dim]No servers found or feature not fully implemented[/dim]\n")
            return
        
        console.print(f"\n[green]✓ Found {len(servers)} MCP server(s)[/green]\n")
        
        for i, server in enumerate(servers, 1):
            console.print(f"{i}. {server.url}")
    
    asyncio.run(run_discovery())


@cli.command()
def checks():
    """List all available security checks.
    
    Shows the security checks performed during scanning and
    their associated compliance frameworks.
    """
    
    console.print("\n[bold cyan]📋 Available Security Checks[/bold cyan]\n")
    
    checks_list = [
        ("Authentication", "Checks for missing or weak authentication", "CRITICAL"),
        ("Authorization", "Validates tool access permissions and RBAC", "CRITICAL/HIGH"),
        ("Encryption", "Verifies TLS/SSL configuration", "HIGH"),
        ("CORS", "Detects Cross-Origin Resource Sharing issues", "HIGH/CRITICAL"),
        ("Rate Limiting", "Tests for DoS protection", "HIGH"),
        ("SQL Injection", "Tests for SQL injection vulnerabilities", "CRITICAL"),
        ("Command Injection", "Tests for command execution vulnerabilities", "CRITICAL"),
        ("Path Traversal", "Tests for directory traversal issues", "CRITICAL/HIGH"),
        ("Configuration", "Scans for insecure settings", "LOW/INFO"),
        ("Information Disclosure", "Detects version and info leaks", "INFO"),
    ]
    
    table = Table(show_header=True, header_style="bold magenta", show_lines=True)
    table.add_column("Check", style="cyan", width=20)
    table.add_column("Description", width=45)
    table.add_column("Severity", justify="center", width=15)
    
    for check, desc, severity in checks_list:
        table.add_row(check, desc, severity)
    
    console.print(table)
    
    console.print("\n[bold]Compliance Framework Mapping:[/bold]")
    console.print("• [cyan]ISO 27001:[/cyan] 12+ controls")
    console.print("• [cyan]NIST CSF:[/cyan] 5+ functions")
    console.print("• [cyan]NIST 800-53:[/cyan] 9+ controls")
    console.print("• [cyan]MITRE ATT&CK:[/cyan] 8+ techniques")
    console.print("• [cyan]PCI DSS:[/cyan] 3+ requirements")
    console.print("• [cyan]SOC 2:[/cyan] 3+ criteria\n")


def main():
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠ Scan interrupted by user[/yellow]\n")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]❌ Unexpected error:[/bold red] {str(e)}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
