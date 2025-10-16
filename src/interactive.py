#!/usr/bin/env python3
"""
Interactive Wizard Mode for MCP Security Scanner
User-friendly interface for non-technical users
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from scanner import PDFReportGenerator, MCPDiscovery, SecurityAnalyzer, ReportGenerator, scan_network_for_mcp
from models import MCPServer

console = Console()


class ScanWizard:
    """Interactive scanning wizard"""
    
    def __init__(self):
        self.target = None
        self.scan_type = None
        self.output_format = None
        self.output_path = None
    
    def show_welcome(self):
        """Display welcome screen"""
        console.clear()
        
        welcome_text = """
[bold cyan]🔒 MCP Security Scanner - Interactive Wizard[/bold cyan]

Welcome! This wizard will guide you through scanning your MCP servers
for security vulnerabilities.

[dim]Tip: You can press Ctrl+C at any time to exit[/dim]
        """
        
        console.print(Panel(welcome_text, border_style="cyan"))
        console.print()
    
    def choose_scan_type(self):
        """Let user choose scan type"""
        console.print("[bold]What would you like to scan?[/bold]\n")
        
        options = [
            "1. Single MCP server (URL)",
            "2. Network range (CIDR)",
            "3. Exit"
        ]
        
        for option in options:
            console.print(f"  {option}")
        
        console.print()
        choice = Prompt.ask(
            "Enter your choice",
            choices=["1", "2", "3"],
            default="1"
        )
        
        if choice == "3":
            console.print("\n[yellow]👋 Goodbye![/yellow]")
            sys.exit(0)
        
        self.scan_type = "single" if choice == "1" else "network"
        return self.scan_type
    
    def get_target(self):
        """Get scan target from user"""
        console.print()
        
        if self.scan_type == "single":
            console.print("[bold]Enter the MCP server URL:[/bold]")
            console.print("[dim]Example: http://localhost:3000[/dim]\n")
            
            self.target = Prompt.ask("URL")
            
            # Validate URL
            if not self.target.startswith(('http://', 'https://')):
                console.print("[yellow]⚠ Adding http:// prefix[/yellow]")
                self.target = f"http://{self.target}"
        
        else:  # network
            console.print("[bold]Enter the network range (CIDR):[/bold]")
            console.print("[dim]Example: 192.168.1.0/24[/dim]\n")
            
            self.target = Prompt.ask("CIDR range")
            
            console.print("\n[bold]Which ports should we scan?[/bold]")
            console.print("[dim]Example: 3000,8000,8080 (or press Enter for defaults)[/dim]\n")
            
            ports = Prompt.ask("Ports", default="3000,8000,8080")
            self.ports = [int(p.strip()) for p in ports.split(",")]
        
        return self.target
    
    def choose_output_format(self):
        """Let user choose output format"""
        console.print("\n[bold]Select output format:[/bold]\n")
        
        formats = {
            "1": ("terminal", "📺 Terminal only (view results now)"),
            "2": ("html", "🌐 HTML report (open in browser)"),
            "3": ("pdf", "📄 PDF report (professional document)"),
            "4": ("json", "📋 JSON report (for automation)"),
            "5": ("all", "📦 All formats")
        }
        
        for key, (_, desc) in formats.items():
            console.print(f"  {key}. {desc}")
        
        console.print()
        choice = Prompt.ask(
            "Enter your choice",
            choices=list(formats.keys()),
            default="2"
        )
        
        self.output_format, _ = formats[choice]
        
        if self.output_format != "terminal":
            console.print("\n[bold]Where should we save the report?[/bold]")
            console.print("[dim]Press Enter for default location[/dim]\n")
            
            default_name = f"reports/scan_{Path(self.target.replace('/', '_')).stem}"
            self.output_path = Prompt.ask("File path", default=default_name)
        
        return self.output_format
    
    async def run_single_scan(self):
        """Run a single server scan"""
        console.print("\n" + "="*60)
        console.print(f"[bold cyan]🔍 Scanning: {self.target}[/bold cyan]")
        console.print("="*60 + "\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
        ) as progress:
            
            # Step 1: Discovery
            task1 = progress.add_task("Discovering MCP server...", total=None)
            discovery = MCPDiscovery()
            server = await discovery.probe_server(self.target)
            progress.update(task1, completed=True)
            
            if not server:
                console.print(f"\n[bold red]❌ No MCP server found at {self.target}[/bold red]")
                console.print("[dim]Make sure the server is running and accessible[/dim]\n")
                return None, []
            
            console.print(f"\n[green]✓ Found MCP server[/green]")
            if server.name:
                console.print(f"  Name: [cyan]{server.name}[/cyan]")
            console.print(f"  Tools: {len(server.tools)}")
            console.print(f"  Resources: {len(server.resources)}\n")
            
            # Step 2: Security Analysis
            task2 = progress.add_task("Running security checks...", total=None)
            analyzer = SecurityAnalyzer()
            vulnerabilities = await analyzer.scan(server)
            progress.update(task2, completed=True)
        
        return server, vulnerabilities
    
    async def run_network_scan(self):
        """Run a network range scan"""
        console.print("\n" + "="*60)
        console.print(f"[bold cyan]🌐 Scanning network: {self.target}[/bold cyan]")
        console.print("="*60 + "\n")
        
        servers = await scan_network_for_mcp(self.target, self.ports)
        
        if not servers:
            console.print(f"\n[yellow]⚠ No MCP servers found in {self.target}[/yellow]\n")
            return [], []
        
        console.print(f"\n[green]✓ Found {len(servers)} MCP server(s)[/green]\n")
        
        # Scan each server
        all_vulnerabilities = []
        for i, server in enumerate(servers, 1):
            console.print(f"\n[bold]Scanning server {i}/{len(servers)}: {server.url}[/bold]")
            
            analyzer = SecurityAnalyzer()
            vulns = await analyzer.scan(server)
            all_vulnerabilities.extend(vulns)
            
            console.print(f"  Found {len(vulns)} issues")
        
        return servers, all_vulnerabilities
    
    def display_results(self, server, vulnerabilities):
        """Display scan results in terminal"""
        console.print("\n" + "="*60)
        console.print("[bold]📊 SCAN RESULTS[/bold]")
        console.print("="*60 + "\n")
        
        if not vulnerabilities:
            console.print("[green]✅ No vulnerabilities found! Server looks secure.[/green]\n")
            return
        
        # Severity summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulnerabilities:
            severity_counts[v.severity.value] += 1
        
        # Create summary table
        table = Table(title="Vulnerability Summary", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Status")
        
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green"
        }
        
        for severity, count in severity_counts.items():
            if count > 0:
                color = severity_colors[severity]
                icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🔵" if severity == "LOW" else "🟢"
                table.add_row(
                    f"[{color}]{severity}[/{color}]",
                    str(count),
                    f"{icon} {'Immediate action' if severity == 'CRITICAL' else 'Important' if severity == 'HIGH' else 'Should fix' if severity == 'MEDIUM' else 'Minor'}"
                )
        
        console.print(table)
        console.print()
        
        # List top vulnerabilities
        console.print("[bold]🚨 Top Issues:[/bold]\n")
        
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[v.severity.value]
        )
        
        for i, vuln in enumerate(sorted_vulns[:5], 1):
            color = severity_colors[vuln.severity.value]
            console.print(f"  {i}. [{color}][{vuln.severity.value}][/{color}] {vuln.title}")
            console.print(f"     {vuln.description[:80]}...")
            console.print()
    
    async def generate_reports(self, server, vulnerabilities):
        """Generate requested report formats"""
        if self.output_format == "terminal":
            return
        
        console.print("\n[bold]📝 Generating reports...[/bold]\n")
        
        reporter = ReportGenerator()
        formats_to_generate = []
        
        if self.output_format == "all":
            formats_to_generate = ["json", "html", "pdf"]
        else:
            formats_to_generate = [self.output_format]
        
        generated_files = []
        
        for fmt in formats_to_generate:
            try:
                if fmt == "pdf":
                    # Use PDF reporter
                    from scanner.pdf_reporter import PDFReportGenerator
                    pdf_gen = PDFReportGenerator()
                    path = pdf_gen.generate(
                        server,
                        vulnerabilities,
                        f"{self.output_path}.pdf"
                    )
                else:
                    path = await reporter.generate(
                        server_info=server,
                        vulnerabilities=vulnerabilities,
                        output_path=f"{self.output_path}.{fmt}",
                        format=fmt
                    )
                
                console.print(f"  ✓ {fmt.upper()}: {path}")
                generated_files.append((fmt, path))
            
            except Exception as e:
                console.print(f"  ✗ {fmt.upper()}: Failed ({e})")
        
        console.print()
        
        # Offer to open reports
        if generated_files and Confirm.ask("Would you like to open the reports?", default=True):
            for fmt, path in generated_files:
                if fmt == "html":
                    import webbrowser
                    webbrowser.open(f"file://{Path(path).absolute()}")
                elif fmt == "pdf":
                    import subprocess
                    try:
                        subprocess.run(["xdg-open", path], check=False)
                    except:
                        console.print(f"  Please manually open: {path}")
    
    async def run(self):
        """Run the complete wizard"""
        self.show_welcome()
        
        try:
            # Step 1: Choose scan type
            self.choose_scan_type()
            
            # Step 2: Get target
            self.get_target()
            
            # Step 3: Choose output
            self.choose_output_format()
            
            # Step 4: Confirm and scan
            console.print("\n" + "="*60)
            console.print("[bold]Ready to scan![/bold]")
            console.print("="*60)
            console.print(f"\n  Target: [cyan]{self.target}[/cyan]")
            console.print(f"  Type: {self.scan_type}")
            console.print(f"  Output: {self.output_format}\n")
            
            if not Confirm.ask("Start scan?", default=True):
                console.print("\n[yellow]Scan cancelled[/yellow]")
                return
            
            # Step 5: Run scan
            if self.scan_type == "single":
                server, vulnerabilities = await self.run_single_scan()
            else:
                servers, vulnerabilities = await self.run_network_scan()
                server = servers[0] if servers else None
            
            if not server:
                return
            
            # Step 6: Display results
            self.display_results(server, vulnerabilities)
            
            # Step 7: Generate reports
            await self.generate_reports(server, vulnerabilities)
            
            # Step 8: Done!
            console.print("\n" + "="*60)
            console.print("[bold green]✅ Scan Complete![/bold green]")
            console.print("="*60 + "\n")
            
            if Confirm.ask("Run another scan?", default=False):
                await self.run()
        
        except KeyboardInterrupt:
            console.print("\n\n[yellow]👋 Scan cancelled. Goodbye![/yellow]\n")
            sys.exit(0)
        except Exception as e:
            console.print(f"\n[bold red]❌ Error: {e}[/bold red]\n")
            raise


async def main():
    """Main entry point for wizard"""
    wizard = ScanWizard()
    await wizard.run()


if __name__ == "__main__":
    asyncio.run(main())
