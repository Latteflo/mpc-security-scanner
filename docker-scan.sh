#!/usr/bin/env bash
# Docker-based scanning script
# Usage: ./docker-scan.sh -t <target> [-f format] [-o output]

set -e

echo "🔒 MCP Security Scanner - Docker Edition"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
TARGET=""
FORMAT="html"
OUTPUT="reports/scan_results"

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 -t <target> [-f format] [-o output]"
            echo ""
            echo "Options:"
            echo "  -t, --target    Target URL (required)"
            echo "  -f, --format    Report format: json, html, pdf, terminal (default: html)"
            echo "  -o, --output    Output file path (default: reports/scan_results)"
            echo "  -h, --help      Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 -t http://localhost:3000"
            echo "  $0 -t http://example.com:8080 -f pdf -o my_report.pdf"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use -h for help"
            exit 1
            ;;
    esac
done

# Validate target
if [ -z "$TARGET" ]; then
    echo -e "${RED}❌ Target is required${NC}"
    echo "Usage: $0 -t <target>"
    exit 1
fi

# Add extension if not provided
if [[ ! "$OUTPUT" =~ \.(json|html|pdf)$ ]]; then
    OUTPUT="${OUTPUT}.${FORMAT}"
fi

# Create reports directory
mkdir -p reports

echo -e "${GREEN}🔍 Starting scan...${NC}"
echo "Target: $TARGET"
echo "Format: $FORMAT"
echo "Output: $OUTPUT"
echo ""

# Build image if not exists
if ! docker image inspect mcp-security-scanner:latest > /dev/null 2>&1; then
    echo -e "${YELLOW}📦 Building Docker image...${NC}"
    docker build -t mcp-security-scanner:latest . || {
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    }
fi

# Run scan
docker run --rm \
    -v "$(pwd)/reports:/app/reports" \
    --network host \
    mcp-security-scanner:latest \
    scan --target "$TARGET" --format "$FORMAT" --output "$OUTPUT" || {
    echo -e "${RED}❌ Scan failed${NC}"
    exit 1
}

echo ""
echo -e "${GREEN}✅ Scan completed!${NC}"
echo "Report saved to: $OUTPUT"

# Open report if HTML or PDF
if [ "$FORMAT" = "html" ] || [ "$FORMAT" = "pdf" ]; then
    echo ""
    read -p "Open report? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v xdg-open > /dev/null; then
            xdg-open "$OUTPUT"
        elif command -v open > /dev/null; then
            open "$OUTPUT"
        else
            echo "Please open $OUTPUT manually"
        fi
    fi
fi
