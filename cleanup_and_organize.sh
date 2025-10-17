#!/usr/bin/env bash

echo "=========================================="
echo "  Repository Cleanup and Organization"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Step 1: Remove backup files
echo "Step 1: Removing backup files..."
rm -f src/main_backup.py
rm -f src/main.py.backup
rm -f src/models/vulnerability_backup.py
rm -f src/scanner/analyzer_backup.py
rm -f src/scanner/analyzer.py.backup
rm -f src/scanner/discovery.py.backup
rm -f src/utils/network.py.backup
rm -f tests/test_compliance/__init__.py~
echo -e "${GREEN}✓ Backup files removed${NC}"

# Step 2: Clean up __pycache__
echo ""
echo "Step 2: Cleaning __pycache__ directories..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete 2>/dev/null
find . -name "*.pyo" -delete 2>/dev/null
echo -e "${GREEN}✓ __pycache__ cleaned${NC}"

# Step 3: Organize reports directory
echo ""
echo "Step 3: Organizing reports directory..."
mkdir -p reports/demos
mkdir -p reports/scans
mkdir -p reports/compliance

# Move demo reports
mv reports/demo_scan.json reports/demos/ 2>/dev/null
mv reports/demo_scan.html reports/demos/ 2>/dev/null
mv reports/demo_scan.pdf reports/demos/ 2>/dev/null
mv reports/compliance_demo.json reports/demos/ 2>/dev/null
mv reports/compliance_demo.md reports/demos/ 2>/dev/null

# Move test reports
mv reports/test.json reports/demos/ 2>/dev/null
mv reports/test.html reports/demos/ 2>/dev/null
mv reports/test.docx reports/demos/ 2>/dev/null
mv reports/test_enhanced.pdf reports/demos/ 2>/dev/null

# Create .gitkeep files
touch reports/.gitkeep
touch reports/demos/.gitkeep
touch reports/scans/.gitkeep
touch reports/compliance/.gitkeep

echo -e "${GREEN}✓ Reports organized${NC}"

# Step 4: Create scripts directory and organize
echo ""
echo "Step 4: Organizing scripts..."
mkdir -p scripts

# Move test and demo scripts
mv test_compliance_scanner.py scripts/ 2>/dev/null
mv test_scanner.py scripts/ 2>/dev/null
mv test_scanner_with_pdf.py scripts/ 2>/dev/null
mv test_network_scan.py scripts/ 2>/dev/null
mv test_plugins.py scripts/ 2>/dev/null
mv verify_compliance_implementation.sh scripts/ 2>/dev/null
mv test_all_features.sh scripts/ 2>/dev/null
mv test_everything.sh scripts/ 2>/dev/null
mv test_reports.sh scripts/ 2>/dev/null
mv run_tests.sh scripts/ 2>/dev/null

# Make scripts executable
chmod +x scripts/*.sh scripts/*.py 2>/dev/null

echo -e "${GREEN}✓ Scripts organized${NC}"

# Step 5: Organize documentation
echo ""
echo "Step 5: Organizing documentation..."
mkdir -p docs

# Move compliance docs
mv README_COMPLIANCE.md docs/COMPLIANCE.md 2>/dev/null
mv COMPLIANCE_SUCCESS.md docs/COMPLIANCE_SUCCESS.md 2>/dev/null

# Remove empty main file
rm -f main

echo -e "${GREEN}✓ Documentation organized${NC}"

# Step 6: Clean htmlcov (should be gitignored)
echo ""
echo "Step 6: Cleaning coverage reports..."
rm -rf htmlcov/
echo -e "${GREEN}✓ Coverage reports cleaned${NC}"

# Step 7: Update .gitignore
echo ""
echo "Step 7: Updating .gitignore..."
cat > .gitignore << 'GITIGNORE'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual Environment
.venv/
venv/
ENV/
env/

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/
.hypothesis/
coverage.xml

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store

# Nix
result
result-*
.direnv/

# Reports (keep structure, ignore generated files)
reports/scans/*.json
reports/scans/*.html
reports/scans/*.pdf
reports/scans/*.md
reports/scans/*.docx
reports/compliance/*.json
reports/compliance/*.html
reports/compliance/*.pdf
reports/compliance/*.md
!reports/.gitkeep
!reports/demos/
!reports/demos/.gitkeep
!reports/demos/*.json
!reports/demos/*.html
!reports/demos/*.md

# Logs
*.log
logs/

# Config with secrets
config/secrets.yaml
config/production.yaml
.env
.env.local

# Backups
*_backup.*
*_old.*
*.bak
*.backup

# OS
Thumbs.db
.DS_Store

# Compiled files
*.pyc
*.pyo

# Database
*.db
*.sqlite
*.sqlite3

# Node (for dashboard)
dashboard/*/node_modules/
dashboard/*/dist/
dashboard/*/build/
GITIGNORE

echo -e "${GREEN}✓ .gitignore updated${NC}"

# Step 8: Create missing __init__.py files
echo ""
echo "Step 8: Ensuring __init__.py files exist..."
touch tests/test_compliance/__init__.py
echo -e "${GREEN}✓ __init__.py files created${NC}"

echo ""
echo "=========================================="
echo -e "${GREEN}  ✅ Cleanup Complete!${NC}"
echo "=========================================="
echo ""
echo "Summary of changes:"
echo "  • Removed all backup files"
echo "  • Cleaned __pycache__ directories"
echo "  • Organized reports/ directory"
echo "  • Moved scripts to scripts/ directory"
echo "  • Organized documentation in docs/"
echo "  • Updated .gitignore"
echo "  • Cleaned coverage reports"
echo ""
echo "New directory structure:"
echo "  scripts/          - Test and demo scripts"
echo "  docs/             - Documentation"
echo "  reports/demos/    - Demo reports (tracked)"
echo "  reports/scans/    - Scan reports (gitignored)"
echo "  reports/compliance/ - Compliance reports (gitignored)"
echo ""

