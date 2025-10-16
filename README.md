# 🔒 MCP Security Scanner

[![Tests](https://github.com/Latteflo/mpc-security-scanner/workflows/Tests/badge.svg)](https://github.com/Latteflo/mpc-security-scanner/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive security auditing tool for Model Context Protocol (MCP) servers. Automatically detects vulnerabilities, misconfigurations, and security weaknesses in MCP deployments.

## 🎯 Why This Tool?

With over **7,000 MCP servers** currently exposed on the internet, many lack proper security controls. This scanner helps identify and remediate critical security issues before they're exploited.

## ✨ Features

### 🔍 Core Scanning
- **Single Server Scanning** - Deep security analysis of individual MCP servers
- **Network Scanning** - CIDR range scanning to discover MCP servers
- **10+ Security Checks** - Comprehensive vulnerability detection
  - Authentication & Authorization
  - Encryption (TLS/SSL)
  - CORS Misconfigurations
  - Rate Limiting & DoS Protection
  - SQL Injection
  - Command Injection
  - Path Traversal
  - Information Disclosure

### 🎨 User Experience
- **Interactive Mode** - Guided scanning wizard for easy use
- **CLI Mode** - Full command-line interface for automation
- **Beautiful Output** - Rich terminal output with progress bars

### 📊 Reporting
- **JSON** - Machine-readable for automation
- **HTML** - Beautiful web-based reports
- **PDF** - Professional documents for stakeholders
- **DOCX** - Microsoft Word format for easy editing

### 🔌 Extensibility
- **Plugin System** - Create custom security checks
- **Auto-loading** - Drop plugins in `plugins/` directory
- **Easy Development** - Simple API for plugin creation

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/Latteflo/mpc-security-scanner.git
cd mpc-security-scanner

# Setup virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Interactive Mode (Easiest!)
```bash
python src/main.py interactive
```

The interactive mode will guide you through:
1. Choosing scan type (single server or network)
2. Entering target URL or CIDR range
3. Selecting output format
4. Running the scan and viewing results

### Command Line Usage
```bash
# Scan a single MCP server
python src/main.py scan --target http://example.com:3000

# Scan with HTML report
python src/main.py scan --target http://example.com:3000 \\
  --format html --output report.html

# Scan with PDF report
python src/main.py scan --target http://example.com:3000 \\
  --format pdf --output report.pdf

# Scan with Word document
python src/main.py scan --target http://example.com:3000 \\
  --format docx --output report.docx

# Scan entire network
python src/main.py network-scan --cidr 192.168.1.0/24 --ports 3000,8080

# List available security checks
python src/main.py checks

# List available plugins
python src/main.py plugins
```

## 📋 Example Output

### Terminal
```
🔍 Starting MCP Security Scan
Target: http://localhost:3000

✓ Server discovered: Test Server
  Tools: 3 | Resources: 2

✓ Analysis complete: Found 7 issues

📊 Scan Results:
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL │   3   │
│ HIGH     │   2   │
│ MEDIUM   │   1   │
│ LOW      │   1   │
└──────────┴───────┘
```

### Report Formats

**HTML Report** - Interactive web-based report with:
- Color-coded severity levels
- Detailed vulnerability cards
- Risk scoring dashboard
- Remediation guidance

**PDF Report** - Professional document with:
- Executive summary
- Risk assessment
- Detailed findings
- Recommendations

**Word Report** - Editable document with:
- Complete vulnerability details
- Easy customization
- Share with stakeholders

## 🔍 Security Checks

### Authentication & Authorization
- Missing authentication detection
- Weak credential testing
- Authorization bypass checks
- Dangerous tool exposure

### Encryption & Transport
- TLS/SSL validation
- Certificate verification
- Weak cipher detection

### CORS (Cross-Origin Resource Sharing)
- Wildcard origin detection
- Origin reflection vulnerabilities
- Credentials with wildcard

### Rate Limiting & DoS
- Absence of rate limiting
- Weak throttling thresholds
- Denial-of-service protection

### Injection Attacks
**SQL Injection:**
- Query parameter testing
- Error-based detection

**Command Injection:**
- Shell command execution
- System command testing

**Path Traversal:**
- Directory traversal testing
- File access validation

### Information Disclosure
- Version information leaks
- Error message analysis

## 🔌 Plugin Development

Create custom security checks easily:
```python
# plugins/my_check.py
from src.scanner.plugins import SecurityCheckPlugin
from src.models import Vulnerability, Severity

class MyCustomCheck(SecurityCheckPlugin):
    name = "My Custom Check"
    version = "1.0.0"
    description = "Custom security check"
    author = "Your Name"
    
    async def check(self, server):
        # Your check logic here
        if some_condition:
            return Vulnerability.create(
                id="CUSTOM-001",
                title="Issue Found",
                description="Description of the issue",
                severity=Severity.HIGH,
                category="Custom",
                remediation="How to fix it"
            )
        return None
```

List your plugins:
```bash
python src/main.py plugins
```

## 🧪 Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Test network scanner
python test_network_scan.py

# Test plugin system
python test_plugins.py
```

## 📚 Documentation

- **[Usage Guide](docs/USAGE.md)** - Detailed usage examples
- **[API Reference](docs/API.md)** - Developer documentation
- **[Security Guide](docs/SECURITY.md)** - Security best practices
- **[Plugin Development](NETWORK_PLUGIN_FEATURES.md)** - Create custom plugins

## 🎯 Use Cases

### For Security Teams
- Regular security audits
- Compliance reporting
- Vulnerability assessments
- Penetration testing

### For Development Teams
- CI/CD integration
- Pre-deployment checks
- Security regression testing

### For DevOps
- Infrastructure monitoring
- Configuration validation
- Security baseline enforcement

## 📈 Roadmap

- [x] Core scanning engine
- [x] 10+ security checks
- [x] HTML/JSON/PDF/DOCX reports
- [x] Interactive mode
- [x] Network scanning (CIDR)
- [x] Plugin system
- [ ] Scheduled scanning
- [ ] Web dashboard
- [ ] Docker deployment
- [ ] PyPI package

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📝 License

MIT License - see [LICENSE](LICENSE) file.

## 🙏 Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io/) ecosystem
- Security research community
- OWASP and CWE projects

## ⚠️ Disclaimer

**For authorized security testing only.** Always obtain permission before scanning systems you don't own.

---

**Made with ❤️ for the security community** | [⭐ Star this repo](https://github.com/Latteflo/mpc-security-scanner)

**Latest:** Interactive Mode, Network Scanning, Plugin System, PDF/Word Reports!
