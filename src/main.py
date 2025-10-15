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
@click.version_option(version="0.1.0")
def cli():
    """
    🔒 MCP Security Scanner & Auditor
    
    A comprehensive security auditing tool for Model Context Protocol servers.
    """
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="Target MCP server URL")
@click.option("--output", "-o", default="reports/scan_results.json", help="Output file")
@click.option("--format", "-f", type=click.Choice(["json", "html", "terminal"]), default="terminal")
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
@click.option("--range", "-r", required=True, help="IP range to scan")
@click.option("--ports", "-p", default="3000,8080", help="Ports to scan")
def discover(range: str, ports: str):
    """Discover MCP servers on a network."""
    
    async def run_discovery():
        console.print(f"\n[bold cyan]🔍 Discovering MCP Servers[/bold cyan]")
        console.print(f"[dim]Range: {range}[/dim]\n")
        
        port_list = [int(p.strip()) for p in ports.split(",")]
        
        discovery = MCPDiscovery()
        servers = await discovery.network_scan(range, port_list)
        
        if not servers:
            console.print("[yellow]Network scanning feature coming soon![/yellow]")
            return
        
        console.print(f"\n[green]Found {len(servers)} MCP server(s)[/green]\n")
    
    asyncio.run(run_discovery())


@cli.command()
def checks():
    """List all available security checks."""
    
    console.print("\n[bold cyan]📋 Available Security Checks[/bold cyan]\n")
    
    checks_list = [
        ("Authentication", "Checks for missing or weak authentication"),
        ("Authorization", "Validates tool access permissions"),
        ("Encryption", "Verifies TLS/SSL configuration"),
        ("Configuration", "Scans for insecure settings"),
        ("Exposure", "Detects information disclosure"),
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Check", style="cyan")
    table.add_column("Description")
    
    for check, desc in checks_list:
        table.add_row(check, desc)
    
    console.print(table)
    console.print()


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()