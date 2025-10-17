#!/bin/bash

echo "=========================================="
echo "  Repository Cleanup and Organization"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Remove backup files
echo "Removing backup files..."
find . -name "*_backup.py" -type f -delete
find . -name "*_updated.py" -type f -delete
find . -name "*.pyc" -type f -delete
find . -name "*.pyo" -type f -delete
find . -name "*~" -type f -delete
echo -e "${GREEN}✓ Backup files removed${NC}"

# Clean up __pycache__ directories
echo ""
echo "Cleaning __pycache__ directories..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
echo -e "${GREEN}✓ __pycache__ cleaned${NC}"

# Remove empty directories
echo ""
echo "Removing empty directories..."
find . -type d -empty -delete 2>/dev/null
echo -e "${GREEN}✓ Empty directories removed${NC}"

# Organize reports directory
echo ""
echo "Organizing reports directory..."
mkdir -p reports/demos
mkdir -p reports/scans
mkdir -p reports/compliance

# Move demo reports
if [ -f "reports/demo_scan.json" ]; then
    mv reports/demo_scan.json reports/demos/ 2>/dev/null
fi
if [ -f "reports/demo_scan.html" ]; then
    mv reports/demo_scan.html reports/demos/ 2>/dev/null
fi
if [ -f "reports/demo_scan.pdf" ]; then
    mv reports/demo_scan.pdf reports/demos/ 2>/dev/null
fi
if [ -f "reports/compliance_demo.json" ]; then
    mv reports/compliance_demo.json reports/demos/ 2>/dev/null
fi
if [ -f "reports/compliance_demo.md" ]; then
    mv reports/compliance_demo.md reports/demos/ 2>/dev/null
fi

echo -e "${GREEN}✓ Reports organized${NC}"

# Create proper .gitignore
echo ""
echo "Updating .gitignore..."
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

# Reports (keep structure, ignore content except demos)
reports/scans/*.json
reports/scans/*.html
reports/scans/*.pdf
reports/scans/*.md
reports/compliance/*.json
reports/compliance/*.html
reports/compliance/*.pdf
reports/compliance/*.md
!reports/.gitkeep
!reports/demos/
!reports/demos/.gitkeep

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

# OS
Thumbs.db
.DS_Store

# Coverage
coverage.xml
.coverage.*
GITIGNORE

echo -e "${GREEN}✓ .gitignore updated${NC}"

# Create .gitkeep files for empty directories
echo ""
echo "Creating .gitkeep files..."
touch reports/.gitkeep
touch reports/demos/.gitkeep
touch reports/scans/.gitkeep
touch reports/compliance/.gitkeep
touch config/.gitkeep
touch logs/.gitkeep
echo -e "${GREEN}✓ .gitkeep files created${NC}"

# Remove duplicate or unnecessary files
echo ""
echo "Checking for duplicate files..."
if [ -f "main" ]; then
    rm main
    echo -e "${GREEN}✓ Removed empty 'main' file${NC}"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}  ✅ Cleanup Complete!${NC}"
echo "=========================================="
echo ""
echo "Repository structure:"
tree -L 2 -I '__pycache__|.venv|*.pyc' . 2>/dev/null || ls -la

