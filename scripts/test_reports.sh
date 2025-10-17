#!/usr/bin/env bash
set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          TESTING REPORT GENERATION (PDF & HTML)            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# First, let's verify the demo scan files exist
echo "📁 Checking existing reports..."
ls -lh reports/ 2>/dev/null || echo "  ℹ No reports directory yet"
echo ""

# Create a test target (mock server data)
echo "🎭 Creating mock scan for testing reports..."
python << 'PYEOF'
import asyncio
from src.models import MCPServer
from src.scanner import SecurityAnalyzer, ReportGenerator

async def test_reports():
    # Create a mock vulnerable server
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        name="Test Demo Server",
        version="1.0.0",
        tools=["read_file", "execute_command", "get_credentials"],
        resources=["file:///etc/passwd", "file:///var/log"],
        has_authentication=False,
        has_encryption=False
    )
    
    print(f"  📡 Mock server: {server.url}")
    print(f"  🔧 Tools: {len(server.tools)}")
    print(f"  📦 Resources: {len(server.resources)}")
    print("")
    
    # Run security analysis
    print("  🔍 Running security analysis...")
    analyzer = SecurityAnalyzer()
    vulnerabilities = await analyzer.scan(server)
    print(f"  ✓ Found {len(vulnerabilities)} vulnerabilities")
    print("")
    
    # Generate reports
    reporter = ReportGenerator()
    
    # Test 1: JSON Report
    print("  📄 Test 1: Generating JSON report...")
    try:
        json_path = await reporter.generate(
            server_info=server,
            vulnerabilities=vulnerabilities,
            output_path="reports/test_report.json",
            format="json"
        )
        print(f"    ✓ JSON report: {json_path}")
        
        # Verify JSON file
        import json
        with open(json_path) as f:
            data = json.load(f)
            print(f"    ✓ Contains {len(data.get('vulnerabilities', []))} vulnerabilities")
    except Exception as e:
        print(f"    ✗ JSON generation failed: {e}")
    print("")
    
    # Test 2: HTML Report
    print("  🌐 Test 2: Generating HTML report...")
    try:
        html_path = await reporter.generate(
            server_info=server,
            vulnerabilities=vulnerabilities,
            output_path="reports/test_report.html",
            format="html"
        )
        print(f"    ✓ HTML report: {html_path}")
        
        # Verify HTML file
        with open(html_path) as f:
            html_content = f.read()
            has_title = "<title>" in html_content
            has_vulns = "vulnerability" in html_content.lower()
            print(f"    ✓ Has title tag: {has_title}")
            print(f"    ✓ Contains vulnerabilities: {has_vulns}")
            print(f"    ✓ Size: {len(html_content)} bytes")
    except Exception as e:
        print(f"    ✗ HTML generation failed: {e}")
    print("")
    
    # Test 3: PDF Report (if supported)
    print("  📑 Test 3: Generating PDF report...")
    try:
        # Check if PDF reporter is available
        from src.scanner.pdf_reporter import PDFReportGenerator
        
        pdf_gen = PDFReportGenerator()
        pdf_path = pdf_gen.generate(
            server, 
            vulnerabilities, 
            "reports/test_report.pdf"
        )
        print(f"    ✓ PDF report: {pdf_path}")
        
        # Check file size
        import os
        if os.path.exists(pdf_path):
            size = os.path.getsize(pdf_path)
            print(f"    ✓ Size: {size:,} bytes")
        
    except ImportError:
        print("    ℹ PDF reporter not found (optional feature)")
    except Exception as e:
        print(f"    ⚠ PDF generation error: {e}")
    print("")
    
    return len(vulnerabilities)

# Run the async function
vuln_count = asyncio.run(test_reports())
print(f"✅ Report generation test complete! ({vuln_count} vulnerabilities)")
PYEOF

echo ""
echo "📊 Checking generated reports..."
ls -lh reports/test_report.* 2>/dev/null || echo "  No test reports found"
echo ""

# Show report contents summary
if [ -f "reports/test_report.json" ]; then
    echo "📄 JSON Report Summary:"
    python << 'PYEOF'
import json
with open("reports/test_report.json") as f:
    data = json.load(f)
    print(f"  Scan ID: {data.get('scan_id', 'N/A')}")
    print(f"  Target: {data.get('target', {}).get('host', 'N/A')}")
    print(f"  Vulnerabilities: {len(data.get('vulnerabilities', []))}")
    
    # Show severity breakdown
    severities = {}
    for v in data.get('vulnerabilities', []):
        sev = v.get('severity', 'UNKNOWN')
        severities[sev] = severities.get(sev, 0) + 1
    
    print("  Severity breakdown:")
    for sev, count in sorted(severities.items()):
        print(f"    {sev}: {count}")
PYEOF
    echo ""
fi

if [ -f "reports/test_report.html" ]; then
    echo "🌐 HTML Report Summary:"
    echo "  File size: $(wc -c < reports/test_report.html) bytes"
    echo "  Lines: $(wc -l < reports/test_report.html)"
    echo "  Contains CSS: $(grep -c '<style>' reports/test_report.html || echo 0)"
    echo "  Contains vulnerabilities: $(grep -c 'vulnerability' reports/test_report.html || echo 0)"
    echo ""
    echo "  ℹ To view: open reports/test_report.html"
    echo ""
fi

if [ -f "reports/test_report.pdf" ]; then
    echo "📑 PDF Report Summary:"
    echo "  File size: $(wc -c < reports/test_report.pdf) bytes"
    echo ""
    echo "  ℹ To view: xdg-open reports/test_report.pdf"
    echo ""
fi

echo "╔════════════════════════════════════════════════════════════╗"
echo "║                   REPORT TEST SUMMARY                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Generated reports in reports/ directory:"
ls -1 reports/test_report.* 2>/dev/null || echo "  No test reports found"
echo ""
echo "✅ Report generation tests complete!"
echo ""

