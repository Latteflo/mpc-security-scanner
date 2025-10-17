#!/usr/bin/env python3
"""
Test the scanner with mock data
"""

import asyncio
from src.models import MCPServer
from src.scanner import SecurityAnalyzer, ReportGenerator

async def test_scanner():
    print("🔍 Testing MCP Security Scanner\n")
    
    # Create a mock vulnerable server
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        name="Test Vulnerable Server",
        version="1.0.0",
        tools=["read_file", "execute_command", "get_credentials"],
        resources=["file:///etc/passwd", "file:///var/log"],
        has_authentication=False,
        has_encryption=False
    )
    
    print(f"Target: {server.url}")
    print(f"Tools: {server.tools}")
    print(f"Resources: {server.resources}")
    print(f"Authentication: {server.has_authentication}")
    print(f"Encryption: {server.has_encryption}\n")
    
    # Run security analysis
    print("Running security analysis...")
    analyzer = SecurityAnalyzer()
    vulnerabilities = await analyzer.scan(server)
    
    print(f"\n✅ Found {len(vulnerabilities)} vulnerabilities:\n")
    
    for vuln in vulnerabilities:
        print(f"  [{vuln.severity.value}] {vuln.title}")
        print(f"      {vuln.description[:80]}...")
        print()
    
    # Generate reports
    print("Generating reports...")
    reporter = ReportGenerator()
    
    # JSON report
    await reporter.generate(
        server_info=server,
        vulnerabilities=vulnerabilities,
        output_path="reports/demo_scan.json",
        format="json"
    )
    
    # HTML report
    await reporter.generate(
        server_info=server,
        vulnerabilities=vulnerabilities,
        output_path="reports/demo_scan.html",
        format="html"
    )
    
    print("\n✅ Demo scan complete!")
    print("   Reports saved to:")
    print("   - reports/demo_scan.json")
    print("   - reports/demo_scan.html")

if __name__ == "__main__":
    asyncio.run(test_scanner())
