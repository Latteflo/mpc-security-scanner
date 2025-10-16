#!/usr/bin/env bash

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     COMPREHENSIVE FEATURE TEST - MCP SECURITY SCANNER      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass_count=0
fail_count=0

# Function to run test
run_test() {
    local test_name="$1"
    local command="$2"
    
    echo -e "${YELLOW}Testing: ${test_name}${NC}"
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        ((pass_count++))
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((fail_count++))
    fi
    echo ""
}

# Test 1: Check Python imports
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. IMPORT TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Core scanner imports" "python -c 'from src.scanner import MCPDiscovery, SecurityAnalyzer, ReportGenerator'"
run_test "Network scanner import" "python -c 'from src.scanner import NetworkScanner, scan_network_for_mcp'"
run_test "Plugin system import" "python -c 'from src.scanner import PluginManager, SecurityCheckPlugin'"
run_test "Enhanced PDF reporter import" "python -c 'from src.scanner.pdf_reporter_enhanced import EnhancedPDFReportGenerator'"
run_test "Word reporter import" "python -c 'from src.scanner.word_reporter import WordReportGenerator'"
run_test "Interactive mode import" "python -c 'import sys; sys.path.insert(0, \"src\"); import interactive'"

# Test 2: CLI Commands
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. CLI COMMAND TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Main help" "python src/main.py --help"
run_test "Scan help" "python src/main.py scan --help"
run_test "Network scan help" "python src/main.py network-scan --help"
run_test "Checks command" "python src/main.py checks"
run_test "Plugins command" "python src/main.py plugins"
run_test "Interactive command exists" "python src/main.py --help | grep -q interactive"

# Test 3: Report Generation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. REPORT GENERATION TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Generate test reports
python << 'PYEOF'
import asyncio
from src.models import MCPServer
from src.scanner import SecurityAnalyzer, ReportGenerator

async def test_reports():
    server = MCPServer(
        host="test.example.com", port=3000, protocol="http",
        name="Test Server", version="1.0.0",
        tools=["read_file", "execute"], resources=["file:///etc/passwd"],
        has_authentication=False, has_encryption=False
    )
    
    analyzer = SecurityAnalyzer()
    vulns = await analyzer.scan(server)
    
    reporter = ReportGenerator()
    
    # JSON
    await reporter.generate(server, vulns, "reports/test.json", "json")
    print("✓ JSON report generated")
    
    # HTML
    await reporter.generate(server, vulns, "reports/test.html", "html")
    print("✓ HTML report generated")
    
    # Enhanced PDF
    try:
        from src.scanner.pdf_reporter_enhanced import EnhancedPDFReportGenerator
        pdf_gen = EnhancedPDFReportGenerator()
        pdf_gen.generate(server, vulns, "reports/test_enhanced.pdf")
        print("✓ Enhanced PDF report generated")
    except Exception as e:
        print(f"⚠ Enhanced PDF: {e}")
    
    # Word
    try:
        from src.scanner.word_reporter import WordReportGenerator
        word_gen = WordReportGenerator()
        word_gen.generate(server, vulns, "reports/test.docx")
        print("✓ Word report generated")
    except Exception as e:
        print(f"⚠ Word report: {e}")

asyncio.run(test_reports())
PYEOF

echo ""

# Check if report files were created
run_test "JSON report created" "test -f reports/test.json"
run_test "HTML report created" "test -f reports/test.html"
run_test "Enhanced PDF created" "test -f reports/test_enhanced.pdf"
run_test "Word document created" "test -f reports/test.docx"

# Test 4: File Validity
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. REPORT VALIDITY TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "reports/test.json" ]; then
    run_test "JSON is valid" "python -c 'import json; json.load(open(\"reports/test.json\"))'"
fi

if [ -f "reports/test.html" ]; then
    run_test "HTML has content" "grep -q 'vulnerability' reports/test.html"
    run_test "HTML has CSS" "grep -q '<style>' reports/test.html"
fi

if [ -f "reports/test_enhanced.pdf" ]; then
    run_test "Enhanced PDF has size > 10KB" "test $(stat -f%z reports/test_enhanced.pdf 2>/dev/null || stat -c%s reports/test_enhanced.pdf) -gt 10000"
fi

if [ -f "reports/test.docx" ]; then
    run_test "Word doc has size > 5KB" "test $(stat -f%z reports/test.docx 2>/dev/null || stat -c%s reports/test.docx) -gt 5000"
fi

# Test 5: Network Scanner
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. NETWORK SCANNER TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Network scan (localhost)" "python src/main.py network-scan --cidr 127.0.0.1/32 --ports 22"

# Test 6: Plugin System
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. PLUGIN SYSTEM TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Plugin directory exists" "test -d plugins"
run_test "Example plugin exists" "test -f plugins/example_headers_check.py"
run_test "Plugin loads" "python test_plugins.py"

# Summary
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                      TEST SUMMARY                          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Passed: $pass_count${NC}"
echo -e "${RED}Failed: $fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED!${NC}"
    echo ""
    echo "📊 Generated Reports:"
    ls -lh reports/test.* 2>/dev/null || echo "  No test reports found"
    echo ""
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    echo ""
    exit 1
fi

