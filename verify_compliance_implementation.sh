#!/bin/bash

echo "=========================================="
echo "  Compliance Framework Verification"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check files exist
echo "Checking files..."
files=(
    "src/compliance/__init__.py"
    "src/compliance/frameworks.py"
    "src/compliance/mapper.py"
    "src/compliance/reporter.py"
    "tests/test_compliance/test_frameworks.py"
    "tests/test_compliance/test_mapper.py"
    "test_compliance_scanner.py"
)

all_exist=true
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $file"
    else
        echo -e "${RED}✗${NC} $file"
        all_exist=false
    fi
done

if [ "$all_exist" = false ]; then
    echo ""
    echo -e "${RED}Some files are missing!${NC}"
    exit 1
fi

echo ""
echo "Running tests..."
if pytest tests/test_compliance/ -v --tb=short; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
else
    echo -e "${RED}✗ Some tests failed${NC}"
fi

echo ""
echo "Testing CLI commands..."

echo ""
echo "1. Testing 'frameworks' command..."
if python src/main.py frameworks > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} frameworks command works"
else
    echo -e "${RED}✗${NC} frameworks command failed"
fi

echo ""
echo "2. Testing 'frameworks --framework ISO27001' command..."
if python src/main.py frameworks --framework ISO27001 > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} frameworks detail command works"
else
    echo -e "${RED}✗${NC} frameworks detail command failed"
fi

echo ""
echo "3. Testing 'checks' command..."
if python src/main.py checks > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} checks command works"
else
    echo -e "${RED}✗${NC} checks command failed"
fi

echo ""
echo "=========================================="
echo "  Verification Complete!"
echo "=========================================="
echo ""
echo "Available commands:"
echo "  python src/main.py frameworks"
echo "  python src/main.py frameworks --framework ISO27001"
echo "  python src/main.py compliance --target http://localhost:3000"
echo "  python src/main.py checks"
echo ""
echo "Demo script:"
echo "  python test_compliance_scanner.py"
echo ""
