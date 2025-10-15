# Usage Guide

## Installation

### Quick Install
```bash
git clone https://github.com/Latteflo/mpc-security-scanner.git
cd mpc-security-scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Basic Usage

### Scan a Single Server
```bash
python src/main.py scan --target http://example.com:3000
```

### Generate Different Report Formats

**Terminal Output (default):**
```bash
python src/main.py scan --target http://example.com:3000 --format terminal
```

**JSON Report:**
```bash
python src/main.py scan --target http://example.com:3000 --format json --output reports/scan.json
```

**HTML Report:**
```bash
python src/main.py scan --target http://example.com:3000 --format html --output reports/scan.html
```

### List Available Checks
```bash
python src/main.py checks
```

### Verbose Mode
```bash
python src/main.py scan --target http://example.com:3000 --verbose
```

## Demo Mode

Test the scanner without a real server:
```bash
python test_scanner.py
xdg-open reports/demo_scan.html
```

## Advanced Usage

### Scanning HTTPS Servers
```bash
python src/main.py scan --target https://secure.example.com:443
```

### Custom Output Location
```bash
python src/main.py scan --target http://example.com:3000 \
  --format html \
  --output /path/to/custom/report.html
```

## Understanding Results

### Severity Levels
- **CRITICAL** (🔴) - Immediate action required
- **HIGH** (🟠) - Important security issue
- **MEDIUM** (🟡) - Should be addressed
- **LOW** (🔵) - Minor issue
- **INFO** (🟢) - Informational

### Risk Score
- **0-30**: Low risk
- **31-60**: Medium risk
- **61-100**: High risk

## Troubleshooting

### "Could not connect to MCP server"
- Verify the server is running
- Check firewall rules
- Ensure correct URL format

### "Permission denied"
- Check file permissions on reports directory
- Run with appropriate user permissions

### Import errors
- Ensure virtual environment is activated
- Run `pip install -r requirements.txt`

## New Features (v0.2.0)

### PDF Reports

Generate professional PDF security reports:
```bash
python src/main.py scan --target http://example.com:3000 \
  --format pdf \
  --output compliance_report.pdf
```

PDF reports include:
- Executive summary with risk score
- Detailed vulnerability findings
- Color-coded severity levels
- Remediation guidance
- CWE/CVSS references

### Advanced Security Checks

**Test for SQL Injection:**
```bash
# Automatically tests SQL-related tools
python src/main.py scan --target http://example.com:3000
```

**Test for Command Injection:**
```bash
# Automatically tests command execution tools
python src/main.py scan --target http://example.com:3000
```

**Test for Path Traversal:**
```bash
# Automatically tests file access tools
python src/main.py scan --target http://example.com:3000
```

All checks run automatically during a scan!
