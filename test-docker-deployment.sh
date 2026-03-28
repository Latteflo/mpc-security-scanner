#!/usr/bin/env bash
# Automated Docker Deployment Testing Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

# Functions
print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_test() {
    echo -e "${YELLOW}▶${NC} Testing: $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
    ((TOTAL_TESTS++))
}

print_failure() {
    echo -e "${RED}✗${NC} $1"
    ((TESTS_FAILED++))
    ((TOTAL_TESTS++))
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    print_test "Docker installation"
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | tr -d ',')
        print_success "Docker installed (version $DOCKER_VERSION)"
    else
        print_failure "Docker not found"
        exit 1
    fi
    
    print_test "Docker daemon running"
    if docker info &> /dev/null; then
        print_success "Docker daemon is running"
    else
        print_failure "Docker daemon not running"
        exit 1
    fi
    
    print_test "Reports directory"
    mkdir -p reports
    if [ -d "reports" ]; then
        print_success "Reports directory exists"
    else
        print_failure "Cannot create reports directory"
        exit 1
    fi
}

# Test 1: Build main image
test_build_main() {
    print_header "Test 1: Building Main Docker Image"
    
    print_test "Building mcp-security-scanner image"
    if docker build -t mcp-security-scanner:latest . &> build.log; then
        print_success "Main image built successfully"
        
        if docker images | grep -q "mcp-security-scanner"; then
            IMAGE_SIZE=$(docker images mcp-security-scanner:latest --format "{{.Size}}")
            print_success "Image created (size: $IMAGE_SIZE)"
        else
            print_failure "Image not found after build"
        fi
    else
        print_failure "Build failed (check build.log)"
        cat build.log
        return 1
    fi
}

# Test 2: Basic functionality
test_basic_functionality() {
    print_header "Test 2: Basic Functionality"
    
    print_test "Help command"
    if docker run --rm mcp-security-scanner:latest --help &> /dev/null; then
        print_success "Help command works"
    else
        print_failure "Help command failed"
    fi
    
    print_test "Checks command"
    if docker run --rm mcp-security-scanner:latest checks &> /dev/null; then
        print_success "Checks command works"
    else
        print_failure "Checks command failed"
    fi
}

# Test 3: Demo scan
test_demo_scan() {
    print_header "Test 3: Demo Scan"
    
    print_test "Running demo scan"
    if docker run --rm \
        -v "$(pwd)/reports:/app/reports" \
        mcp-security-scanner:latest \
        python test_scanner.py &> demo.log; then
        print_success "Demo scan completed"
        
        if [ -f "reports/demo_scan.json" ]; then
            print_success "JSON report generated"
        else
            print_failure "JSON report not found"
        fi
        
        if [ -f "reports/demo_scan.html" ]; then
            print_success "HTML report generated"
        else
            print_failure "HTML report not found"
        fi
    else
        print_failure "Demo scan failed (check demo.log)"
    fi
}

# Cleanup function
cleanup() {
    print_header "Cleanup"
    
    print_test "Removing test files"
    rm -f build.log demo.log
    print_success "Test files removed"
}

# Summary
print_summary() {
    print_header "Test Summary"
    
    echo ""
    echo -e "${BLUE}Total Tests:${NC}  $TOTAL_TESTS"
    echo -e "${GREEN}Passed:${NC}       $TESTS_PASSED"
    echo -e "${RED}Failed:${NC}       $TESTS_FAILED"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}  ✓ ALL TESTS PASSED!${NC}"
        echo -e "${GREEN}  Docker deployment is ready!${NC}"
        echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}  ✗ SOME TESTS FAILED${NC}"
        echo -e "${RED}  Please review failures above${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        return 1
    fi
}

# Main execution
main() {
    echo ""
    echo "🔒 MCP Security Scanner - Docker Deployment Tests"
    echo "=================================================="
    echo ""
    
    check_prerequisites
    test_build_main
    test_basic_functionality
    test_demo_scan
    cleanup
    print_summary
}

main
exit $TESTS_FAILED
