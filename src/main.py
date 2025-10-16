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
@click.version_option(version="0.2.1")
def cli():
    """
    🔒 MCP Security Scanner & Auditor
    
    A comprehensive security auditing tool for Model Context Protocol servers.
    """
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="Target MCP server URL")
@click.option("--output", "-o", default="reports/scan_results.json", help="Output file")
@click.option("--format", "-f", type=click.Choice(["json", "html", "pdf", "terminal"]), default="terminal")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--allow-private", is_flag=True, help="Allow scanning private IP addresses (use with caution)")
@click.option("--insecure", is_flag=True, help="Disable SSL certificate verification (not recommended)")
def scan(target: str, output: str, format: str, verbose: bool, allow_private: bool, insecure: bool):
    """Scan an MCP server for security vulnerabilities."""
    
    async def run_scan():
        # SSRF Protection - Validate target URL
        from urllib.parse import urlparse
        import ipaddress
        
        # Validate target URL
        try:
            parsed = urlparse(target)
            
            # Block metadata endpoints (cloud providers)
            blocked_hosts = [
                '169.254.169.254',
                'metadata.google.internal',
                'metadata.azure.com',
                'metadata',
            ]
            
            hostname_lower = parsed.hostname.lower() if parsed.hostname else ''
            for blocked in blocked_hosts:
                if blocked in hostname_lower:
                    console.print("[bold red]❌ Cannot scan cloud metadata endpoints[/bold red]")
                    console.print("[dim]This could expose cloud credentials[/dim]")
                    return
            
            # Check if it's a private IP
            try:
                ip = ipaddress.ip_address(parsed.hostname)
                
                if ip.is_private and not allow_private:
                    console.print(f"[bold yellow]⚠️  Private IP address detected: {parsed.hostname}[/bold yellow]")
                    console.print("[bold red]❌ Scanning private IPs requires authorization[/bold red]")
                    console.print("[dim]Use --allow-private flag if you own this network[/dim]")
                    return
                
                if ip.is_loopback and not allow_private:
                    console.print("[bold yellow]⚠️  Localhost address detected[/bold yellow]")
                    console.print("[dim]Use --allow-private to scan local servers[/dim]")
                    return
                    
            except ValueError:
                # Not an IP address, it's a domain - that's fine
                pass
                
        except Exception as e:
            console.print(f"[bold red]❌ Invalid URL:[/bold red] {str(e)}")
            return
        
        # Show warning if scanning private networks
        if allow_private:
            console.print("[bold yellow]⚠️  Private IP scanning enabled[/bold yellow]")
            console.print("[dim]Ensure you have authorization to scan this network[/dim]\n")
        
        # SSL Verification Warning
        if insecure:
            console.print("[bold yellow]⚠️  SSL verification disabled![/bold yellow]")
            console.print("[bold red]⚠️  Connection is vulnerable to MITM attacks[/bold red]")
            console.print("[dim]Only use this for testing environments\n[/dim]")
        
        
        # Setup logger
        log_level = "DEBUG" if verbose else "INFO"
        logger = setup_logger(level=log_level)
        
        console.print(f"\n[bold cyan]🔍 Starting MCP Security Scan[/bold cyan]")
        console.print(f"[dim]Target: {target}[/dim]\n")
        
        try:
            # Phase 1: Discovery
            with console.status("[bold green]Discovering MCP server..."):
                discovery = MCPDiscovery(verify_ssl=not insecure)
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
                analyzer = SecurityAnalyzer(verify_ssl=not insecure)
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
        
        discovery = MCPDiscovery(verify_ssl=not insecure)
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



@cli.command()
@click.option("--cidr", "-c", required=True, help="CIDR range to scan")
@click.option("--ports", "-p", default="3000,8000,8080", help="Comma-separated ports")
def network_scan(cidr: str, ports: str):
    """Scan network range for MCP servers"""
    async def run_scan():
        from scanner import scan_network_for_mcp
        
        console.print(f"\n[bold cyan]🔍 Network Scan: {cidr}[/bold cyan]\n")
        port_list = [int(p.strip()) for p in ports.split(",")]
        
        try:
            servers = await scan_network_for_mcp(cidr, port_list)
            console.print(f"\n[green]✓ Found {len(servers)} MCP servers[/green]\n")
            
            for server in servers:
                console.print(f"  • {server.url}")
                if server.name:
                    console.print(f"    Name: {server.name}")
                console.print(f"    Tools: {len(server.tools)}")
                console.print()
        except Exception as e:
            console.print(f"\n[bold red]❌ Error:[/bold red] {str(e)}")
            sys.exit(1)
    
    asyncio.run(run_scan())


@cli.command()
def plugins():
    """List available plugins"""
    from scanner import PluginManager
    from rich.table import Table
    
    console.print("\n[bold cyan]🔌 Available Plugins[/bold cyan]\n")
    
    manager = PluginManager()
    manager.load_plugins()
    
    if not manager.plugins:
        console.print("[yellow]No plugins found in plugins/ directory[/yellow]\n")
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Plugin", style="cyan")
    table.add_column("Version")
    table.add_column("Status")
    
    for p in manager.list_plugins():
        status = "[green]✓[/green]" if p['enabled'] else "[dim]✗[/dim]"
        table.add_row(p['name'], p['version'], status)
    
    console.print(table)
    console.print()


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()


@cli.command()
def interactive():
    """Interactive wizard mode for easy scanning"""
    import subprocess
    import sys
    
    # Run the wizard script
    subprocess.run([sys.executable, "src/interactive.py"])
