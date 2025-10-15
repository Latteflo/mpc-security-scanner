#!/usr/bin/env python3
"""Test scanner with PDF output"""
import asyncio
from src.models import MCPServer
from src.scanner import SecurityAnalyzer
from src.scanner.pdf_reporter import PDFReportGenerator

async def main():
    server = MCPServer(
        host="localhost", port=3000, protocol="http",
        name="Test Server", version="1.0.0",
        tools=["read_file", "execute_command", "get_credentials"],
        resources=["file:///etc/passwd"],
        has_authentication=False, has_encryption=False
    )
    
    analyzer = SecurityAnalyzer()
    vulnerabilities = await analyzer.scan(server)
    
    print(f"✅ Found {len(vulnerabilities)} vulnerabilities")
    
    # Generate PDF
    pdf_gen = PDFReportGenerator()
    pdf_path = pdf_gen.generate(server, vulnerabilities, "reports/demo_scan.pdf")
    print(f"📄 PDF report: {pdf_path}")

if __name__ == "__main__":
    asyncio.run(main())
