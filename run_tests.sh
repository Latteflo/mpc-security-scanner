#!/usr/bin/env bash
# Test runner script

echo "🧪 Running MCP Security Scanner Tests"
echo "======================================"
echo ""

# Run tests with coverage
pytest --cov=src --cov-report=term-missing --cov-report=html -v

# Check exit code
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ All tests passed!"
    echo "📊 Coverage report: htmlcov/index.html"
else
    echo ""
    echo "❌ Some tests failed!"
    exit 1
fi
