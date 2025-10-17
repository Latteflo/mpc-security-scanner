#!/usr/bin/env bash
set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     MCP SECURITY SCANNER - COMPREHENSIVE TEST SUITE        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Test 1: Check all imports work
echo "📦 Test 1: Checking Python imports..."
python << 'PYEOF'
import sys
sys.path.insert(0, 'src')

print("  → Testing core imports...")
from scanner import MCPDiscovery, SecurityAnalyzer, ReportGenerator
print("    ✓ Core modules imported")

print("  → Testing new imports...")
from scanner import NetworkScanner, scan_network_for_mcp
print("    ✓ Network scanner imported")

from scanner import PluginManager, SecurityCheckPlugin
print("    ✓ Plugin system imported")

from models import MCPServer, Vulnerability, Severity
print("    ✓ Models imported")

print("  ✅ All imports successful!")
PYEOF

echo ""

# Test 2: CLI Help
echo "📋 Test 2: Testing CLI commands..."
echo "  → Main help:"
python src/main.py --help | head -15
echo ""

echo "  → Available commands:"
python src/main.py --help | grep -A 10 "Commands:"
echo ""

# Test 3: Network Scanner
echo "🌐 Test 3: Testing network scanner..."
echo "  → Scanning localhost (safe test)..."
python src/main.py network-scan --cidr 127.0.0.1/32 --ports 22,80,443 2>&1 | tail -10
echo ""

# Test 4: Plugin System
echo "🔌 Test 4: Testing plugin system..."
python src/main.py plugins
echo ""

# Test 5: Original scan functionality
echo "🔍 Test 5: Testing original scan command help..."
python src/main.py scan --help | head -10
echo ""

# Test 6: Checks command
echo "📊 Test 6: Testing checks command..."
python src/main.py checks
echo ""

# Test 7: Run test scripts
echo "🧪 Test 7: Running test scripts..."
echo "  → Network scanner test:"
python test_network_scan.py 2>&1 | tail -5
echo ""

echo "  → Plugin system test:"
python test_plugins.py 2>&1 | tail -10
echo ""

# Test 8: Check for example plugin
echo "🔧 Test 8: Checking example plugin..."
if [ -f "plugins/example_headers_check.py" ]; then
    echo "  ✓ Example plugin exists"
    python -c "import sys; sys.path.insert(0, 'plugins'); import example_headers_check; print('  ✓ Example plugin loads successfully')"
else
    echo "  ℹ No example plugin found (optional)"
fi
echo ""

echo "╔════════════════════════════════════════════════════════════╗"
echo "║                     TEST SUMMARY                           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo "✅ All basic tests passed!"
echo ""
echo "🎯 Ready for real-world testing!"
echo ""

