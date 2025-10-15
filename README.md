# 🔒 MCP Security Scanner

[![Tests](https://github.com/Latteflo/mpc-security-scanner/workflows/Tests/badge.svg)](https://github.com/Latteflo/mpc-security-scanner/actions/workflows/tests.yml)
[![Code Quality](https://github.com/Latteflo/mpc-security-scanner/workflows/Code%20Quality/badge.svg)](https://github.com/Latteflo/mpc-security-scanner/actions/workflows/code-quality.yml)
[![Security](https://github.com/Latteflo/mpc-security-scanner/workflows/Security/badge.svg)](https://github.com/Latteflo/mpc-security-scanner/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Coverage](https://img.shields.io/badge/coverage-45%25-yellow.svg)](#)

A comprehensive security auditing tool for Model Context Protocol (MCP) servers. Automatically detects vulnerabilities, misconfigurations, and security weaknesses in MCP deployments.

## 🎯 Why This Tool?

With over **7,000 MCP servers** currently exposed on the internet, many lack proper security controls. This scanner helps identify and remediate critical security issues before they're exploited.

## ✨ Features

- 🔍 **Automatic Discovery** - Probe and fingerprint MCP servers
- 🛡️ **5+ Security Checks** - Authentication, encryption, authorization, configuration, and information disclosure
- 📊 **Multiple Report Formats** - JSON, HTML, and beautiful terminal output
- 🎨 **Professional Reports** - Color-coded HTML reports with risk scoring and statistics
- ⚡ **Fast & Async** - Efficient async/await architecture for parallel scanning
- 🔧 **Extensible** - Modular architecture makes adding new checks easy

## 🚨 Vulnerabilities Detected

| Check | Description | Severity |
|-------|-------------|----------|
| **Missing Authentication** | No authentication required to access server | 🔴 CRITICAL |
| **Unencrypted Connection** | HTTP instead of HTTPS | 🟠 HIGH |
| **Dangerous Tools Exposed** | Commands like `execute`, `read_file` without authorization | 🔴 CRITICAL |
| **Default Configuration** | Running on default ports (3000, 8080, etc.) | 🔵 LOW |
| **Information Disclosure** | Server version and internal details exposed | 🟢 INFO |

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- NixOS (optional but recommended) or any Linux/macOS system

### Installation
```bash
# Clone the repository
git clone https://github.com/Latteflo/mpc-security-scanner.git
cd mpc-security-scanner

# Option 1: NixOS (Recommended)
nix-shell -p python311 python311Packages.pip python311Packages.virtualenv

# Option 2: Standard Python
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
```bash
# Scan a single MCP server
python src/main.py scan --target http://example.com:3000

# Scan with verbose output
python src/main.py scan --target http://example.com:3000 --verbose

# Generate JSON report
python src/main.py scan --target http://example.com:3000 --format json --output reports/my_scan.json

# Generate HTML report (recommended!)
python src/main.py scan --target http://example.com:3000 --format html --output reports/my_scan.html

# List all available security checks
python src/main.py checks

# View help
python src/main.py --help
```

### Demo Mode

Test the scanner with a mock vulnerable server:
```bash
python test_scanner.py
```

This will:
- Create a mock MCP server with known vulnerabilities
- Run all security checks
- Generate JSON and HTML reports in `reports/`
- Display findings in terminal

Then open the HTML report:
```bash
# View the beautiful HTML report
firefox reports/demo_scan.html
# or
xdg-open reports/demo_scan.html
```

## 📊 Example Output

### Terminal Output
```
🔍 Starting MCP Security Scan
Target: http://localhost:3000

✓ Server discovered
  Name: Test Vulnerable Server
  Tools: 3
  Resources: 2

✓ Analysis complete
  Found 5 potential issues

📊 Scan Results:

┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │   2   │
│ HIGH     │   1   │
│ LOW      │   1   │
│ INFO     │   1   │
└──────────┴───────┘

🚨 Key Findings:

  1. Missing Authentication
     The MCP server at http://localhost:3000 does not require authentication...

  2. Unencrypted Connection
     The MCP server at http://localhost:3000 does not use TLS/SSL encryption...
```

### JSON Report

Machine-readable format perfect for automation and CI/CD integration:
```json
{
  "scan_id": "scan-20251015-220005",
  "target": {
    "host": "localhost",
    "port": 3000,
    "url": "http://localhost:3000"
  },
  "vulnerabilities": [
    {
      "id": "MCP-AUTH-001",
      "title": "Missing Authentication",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "cwe_id": "CWE-306"
    }
  ],
  "risk_score": 26
}
```

### HTML Report

Beautiful, professional security report with:

#### 📋 Executive Summary
- Target server information
- Scan metadata (ID, date, duration)
- **Risk Score** with color-coded indicator (0-100 scale)
- Quick statistics overview

#### 📊 Statistics Dashboard
Interactive visual dashboard showing:
- Total security checks performed
- Number of vulnerabilities found
- Breakdown by severity (Critical/High/Medium/Low/Info)
- Color-coded stat cards for quick assessment

#### 🔍 Detailed Vulnerability Findings

Each vulnerability includes:
- **Severity Badge** - Color-coded (Red/Orange/Yellow/Blue/Green)
- **Vulnerability ID** - Unique identifier (e.g., MCP-AUTH-001)
- **Category** - Authentication, Encryption, Authorization, etc.
- **Description** - Clear explanation of the security issue
- **Evidence** - Specific findings from the scan
  - Server details
  - Exposed tools/resources
  - Configuration issues
- **Remediation** - Step-by-step fix instructions
- **References** - CWE/CVSS scores when applicable

#### 🎨 Professional Styling
- Clean, modern design
- Color-coded severity levels:
  - 🔴 **Critical** - Red background, urgent attention needed
  - 🟠 **High** - Orange background, high priority
  - 🟡 **Medium** - Yellow background, should be addressed
  - 🔵 **Low** - Blue background, minor issue
  - 🟢 **Info** - Green background, informational
- Responsive layout
- Print-friendly
- Professional typography
- Box shadows and rounded corners
- Easy to share with stakeholders

**Perfect for:**
- 📧 Emailing to security teams
- 📑 Including in compliance reports
- 🎤 Presenting to management
- 💾 Archiving scan results
- 📤 Sharing with clients

## 🏗️ Project Structure
```
mpc-security-scanner/
├── src/
│   ├── main.py              # CLI entry point
│   ├── scanner/             # Core scanning modules
│   │   ├── discovery.py     # MCP server discovery & fingerprinting
│   │   ├── analyzer.py      # Security vulnerability analysis
│   │   └── reporter.py      # Multi-format report generation
│   ├── checks/              # Security check modules (extensible)
│   ├── models/              # Data models (Pydantic)
│   │   ├── vulnerability.py # Vulnerability data structure
│   │   ├── server.py        # MCP server information
│   │   └── report.py        # Scan report format
│   └── utils/               # Utility functions
│       ├── logger.py        # Colored logging with Rich
│       ├── config.py        # Configuration management
│       └── network.py       # Async HTTP & network utilities
├── tests/                   # Test suite (19 tests, 45% coverage)
├── examples/                # Example vulnerable servers
│   └── vulnerable_server.py # Intentionally vulnerable MCP server
├── reports/                 # Generated scan reports
│   ├── *.json              # JSON format reports
│   └── *.html              # HTML format reports
├── docs/                    # Documentation
│   ├── USAGE.md            # Usage guide
│   ├── API.md              # API reference
│   └── SECURITY.md         # Security best practices
├── config/                  # Configuration files
└── test_scanner.py          # Demo scanner test
```

## 🔧 How It Works

1. **Discovery Phase**
   - Probes target URL for MCP protocol
   - Sends JSON-RPC `initialize` request
   - Enumerates available tools and resources
   - Detects server version and capabilities

2. **Analysis Phase**
   - Runs 5+ security checks in parallel
   - Tests authentication requirements
   - Validates encryption (TLS/SSL)
   - Identifies dangerous tool exposure
   - Checks configuration security
   - Detects information disclosure

3. **Reporting Phase**
   - Calculates risk score (0-100)
   - Generates findings with evidence
   - Provides remediation guidance
   - Exports in multiple formats (JSON/HTML/Terminal)

## 🧪 Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test
pytest tests/test_models/test_vulnerability.py -v

# Run demo
python test_scanner.py
```

**Current test status:**
- ✅ 19 tests passing
- 📊 45% code coverage
- 🚀 Models at 100% coverage
- ⚡ Analyzer at 95% coverage

## 🔧 Development

### Adding New Security Checks

Create a new check in `src/scanner/analyzer.py`:
```python
async def _check_new_vulnerability(self, server: MCPServer):
    """Check for new vulnerability type"""
    
    if condition_detected:
        vuln = Vulnerability.create(
            id="MCP-NEW-001",
            title="New Vulnerability",
            description="Description of the issue...",
            severity=Severity.HIGH,
            category="Category",
            remediation="How to fix..."
        )
        self.vulnerabilities.append(vuln)
```

### Code Style
```bash
# Format code
black src/ tests/

# Lint code
ruff check src/ tests/

# Type check
mypy src/ --ignore-missing-imports
```

## 📚 Documentation

- **[Usage Guide](docs/USAGE.md)** - Detailed usage instructions
- **[API Reference](docs/API.md)** - Complete API documentation
- **[Security Guide](docs/SECURITY.md)** - Security best practices
- **[Contributing](CONTRIBUTING.md)** - How to contribute

## 📈 Roadmap

- [x] Core scanning engine
- [x] Authentication & encryption checks
- [x] HTML/JSON report generation
- [x] CLI interface
- [x] Beautiful HTML reports with statistics
- [x] Test suite with 19 tests
- [x] GitHub Actions CI/CD
- [x] Comprehensive documentation
- [ ] Network scanning (CIDR ranges)
- [ ] Additional checks (CORS, rate limiting, SQL injection)
- [ ] PDF report generation
- [ ] Web dashboard UI
- [ ] Docker deployment
- [ ] Plugin system for custom checks
- [ ] PyPI package distribution

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io/) ecosystem
- Inspired by the need for better MCP security practices
- Security research showing 7,000+ vulnerable MCP servers online
- Thanks to the open source security community

## 🔗 Resources

- [Report Issues](https://github.com/Latteflo/mpc-security-scanner/issues)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [OWASP Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Database](https://cwe.mitre.org/)

## ⚠️ Disclaimer

This tool is for **authorized security research and testing only**. Always obtain proper authorization before scanning systems you don't own. The authors are not responsible for misuse or damage caused by this tool.

---

**Made with ❤️ for the security community** | Star ⭐ this repo if you find it useful!
