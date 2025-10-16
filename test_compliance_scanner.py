#!/usr/bin/env python3
"""
Test Compliance Scanner
Demonstrates compliance framework integration
"""

import asyncio
from src.models import MCPServer
from src.scanner import SecurityAnalyzer
from src.compliance import ComplianceReportGenerator, ComplianceMapper

async def main():
    print("=" * 80)
    print("  🔒 MCP SECURITY SCANNER - COMPLIANCE ASSESSMENT DEMO")
    print("=" * 80)
    print()
    
    # Create test server with vulnerabilities
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        name="Test Vulnerable Server",
        version="1.0.0",
        tools=["read_file", "execute_command", "get_credentials", "sql_query"],
        resources=["file:///etc/passwd", "file:///var/log"],
        has_authentication=False,
        has_encryption=False
    )
    
    print(f"Target Server: {server.url}")
    print(f"Tools: {len(server.tools)}")
    print(f"Authentication: {'✓' if server.has_authentication else '✗'}")
    print(f"Encryption: {'✓' if server.has_encryption else '✗'}")
    print()
    
    # Run security analysis
    print("Running security analysis with compliance mapping...")
    analyzer = SecurityAnalyzer()
    vulnerabilities = await analyzer.scan(server)
    
    print(f"✓ Found {len(vulnerabilities)} vulnerabilities")
    print()
    
    # Show compliance mappings
    print("Compliance Framework Mappings:")
    print("-" * 80)
    
    mapper = ComplianceMapper()
    for vuln in vulnerabilities[:3]:  # Show first 3
        print(f"\n[{vuln.severity.value}] {vuln.title} ({vuln.id})")
        frameworks = mapper.get_frameworks(vuln.id)
        print(f"  Affects {len(frameworks)} frameworks:")
        for fw in frameworks:
            controls = mapper.get_controls(vuln.id, fw)
            print(f"    • {fw.value}: {len(controls)} controls")
    
    print()
    print("=" * 80)
    print()
    
    # Generate compliance report
    print("Generating compliance reports...")
    reporter = ComplianceReportGenerator()
    
    # Terminal report
    print("\n" + "=" * 80)
    reporter.generate_terminal_report(server, vulnerabilities)
    
    # JSON report
    json_path = reporter.generate_json_report(
        server, vulnerabilities, "reports/compliance_demo.json"
    )
    print(f"\n✓ JSON report: {json_path}")
    
    # Markdown report
    md_path = reporter.generate_markdown_report(
        server, vulnerabilities, "reports/compliance_demo.md"
    )
    print(f"✓ Markdown report: {md_path}")
    
    print("\n" + "=" * 80)
    print("✅ Compliance assessment demo complete!")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(main())
