# 🔒 MCP Security Scanner

[![Tests](https://github.com/Latteflo/mpc-security-scanner/workflows/Tests/badge.svg)](https://github.com/Latteflo/mpc-security-scanner/actions/workflows/tests.yml)
[![Code Quality](https://github.com/Latteflo/mpc-security-scanner/workflows/Code%20Quality/badge.svg)](https://github.com/Latteflo/mpc-security-scanner/actions/workflows/code-quality.yml)
[![Security](https://github.com/Latteflo/mpc-security-scanner/workflows/Security/badge.svg)](https://github.com/Latteflo/mpc-security-scanner/actions/workflows/security.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A comprehensive security auditing tool for Model Context Protocol (MCP) servers. Automatically detects vulnerabilities, misconfigurations, and security weaknesses in MCP deployments.

## 🎯 Why This Tool?

With over **7,000 MCP servers** currently exposed on the internet, many lack proper security controls. This scanner helps identify and remediate critical security issues before they're exploited.

## ✨ Features

- 🔍 **Automatic Discovery** - Probe and fingerprint MCP servers
- 🛡️ **10+ Security Checks** - Comprehensive vulnerability detection
  - Authentication & Authorization
  - Encryption (TLS/SSL)
  - CORS Misconfigurations
  - Rate Limiting & DoS Protection
  - SQL Injection
  - Command Injection
  - Path Traversal
  - Information Disclosure
- 📊 **Multiple Report Formats** - JSON, HTML, **PDF**, and terminal output
- 🎨 **Professional Reports** - Executive summaries, risk scoring, remediation guidance
- ⚡ **Fast & Async** - Efficient async/await architecture
- 🔧 **Extensible** - Easy to add custom checks

## 🚨 Vulnerabilities Detected

| Category | Vulnerabilities | Severity |
|----------|----------------|----------|
| **Authentication** | Missing authentication, weak credentials | 🔴 CRITICAL |
| **Encryption** | Unencrypted connections, weak TLS | 🟠 HIGH |
| **CORS** | Wildcard origins, credential leaks | 🔴 CRITICAL |
| **Rate Limiting** | No DoS protection, weak limits | 🟠 HIGH |
| **SQL Injection** | Unvalidated SQL queries | 🔴 CRITICAL |
| **Command Injection** | Shell command execution | 🔴 CRITICAL |
| **Path Traversal** | Unauthorized file access | 🔴 CRITICAL |
| **Configuration** | Default ports, version disclosure | 🔵 LOW/INFO |

**Total: 10+ security checks covering OWASP Top 10 and CWE database**

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

### Basic Usage
```bash
# Scan a single MCP server
python src/main.py scan --target http://example.com:3000

# Generate HTML report
python src/main.py scan --target http://example.com:3000 --format html --output report.html

# Generate PDF report (NEW!)
python src/main.py scan --target http://example.com:3000 --format pdf --output report.pdf

# Generate JSON for automation
python src/main.py scan --target http://example.com:3000 --format json --output report.json

# List all security checks
python src/main.py checks

# Verbose output
python src/main.py scan --target http://example.com:3000 --verbose
```

### Demo Mode
```bash
# Test with mock vulnerable server
python test_scanner.py

# Test PDF generation
python test_scanner_with_pdf.py

# View reports
firefox reports/demo_scan.html
xdg-open reports/demo_scan.pdf
```

## 📊 Example Output

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

### PDF Report (NEW! 📄)
Professional security reports with:
- **Executive Summary** with risk scoring
- **Color-coded** severity indicators
- **Detailed vulnerability cards** with:
  - CWE/CVSS references
  - Evidence from scan
  - Step-by-step remediation
- **Statistics dashboard**
- **Print-friendly** formatting

Perfect for:
- 📧 Emailing to stakeholders
- 📑 Compliance documentation
- 🎤 Executive presentations
- 💾 Long-term archival

## 🔍 Security Checks

### 1. Authentication & Authorization
- Missing authentication detection
- Weak credential testing
- Authorization bypass checks
- Dangerous tool exposure

### 2. Encryption & Transport
- TLS/SSL validation
- Certificate verification
- Weak cipher detection
- Protocol downgrade risks

### 3. CORS (Cross-Origin Resource Sharing)
- Wildcard origin detection
- Origin reflection vulnerabilities
- Credentials with wildcard
- CORS misconfiguration

### 4. Rate Limiting & DoS
- Absence of rate limiting
- Weak throttling thresholds
- Denial-of-service protection
- Brute-force vulnerability

### 5. Injection Attacks
**SQL Injection:**
- Query parameter testing
- Error-based detection
- Blind SQL injection

**Command Injection:**
- Shell command execution
- System command testing
- Path manipulation

**Path Traversal:**
- Directory traversal testing
- File access validation
- Sensitive file exposure

### 6. Information Disclosure
- Version information leaks
- Error message analysis
- Internal path exposure

## 🏗️ Architecture
```
mpc-security-scanner/
├── src/
│   ├── main.py              # CLI interface
│   ├── scanner/             # Core scanning engine
│   │   ├── discovery.py     # Server discovery
│   │   ├── analyzer.py      # Security analysis
│   │   ├── reporter.py      # HTML/JSON reports
│   │   └── pdf_reporter.py  # PDF generation (NEW!)
│   ├── checks/              # Security checks
│   │   ├── cors.py          # CORS checks (NEW!)
│   │   ├── rate_limiting.py # Rate limiting (NEW!)
│   │   └── injection.py     # Injection checks (NEW!)
│   ├── models/              # Data models
│   └── utils/               # Utilities
├── tests/                   # 29+ tests
├── docs/                    # Documentation
└── reports/                 # Generated reports
```

## 🧪 Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test category
pytest tests/test_checks/ -v

# Test demo
python test_scanner.py
```

**Test Coverage:**
- ✅ 29+ tests
- 📊 50%+ code coverage
- 🧪 Models: 100% coverage
- 🔍 Analyzer: 95% coverage

## 📚 Documentation

- **[Usage Guide](docs/USAGE.md)** - Detailed usage examples
- **[API Reference](docs/API.md)** - Developer documentation
- **[Security Guide](docs/SECURITY.md)** - Security best practices
- **[Contributing](CONTRIBUTING.md)** - Contribution guidelines

## 🎯 Use Cases

### For Security Teams
- Regular security audits
- Compliance reporting (SOC2, ISO27001)
- Vulnerability assessments
- Penetration testing

### For Development Teams
- CI/CD integration
- Pre-deployment checks
- Security regression testing
- Automated scanning

### For DevOps
- Infrastructure monitoring
- Configuration validation
- Security baseline enforcement
- Incident response

## 📈 Roadmap

- [x] Core scanning engine
- [x] 10+ security checks
- [x] HTML/JSON/PDF reports
- [x] CORS vulnerability detection
- [x] Rate limiting checks
- [x] Injection attack detection
- [x] PDF report generation
- [x] Comprehensive test suite
- [x] GitHub Actions CI/CD
- [ ] Network scanning (CIDR)
- [ ] Web dashboard
- [ ] Docker deployment
- [ ] PyPI package
- [ ] Plugin system
- [ ] Scheduled scanning
- [ ] Slack/Email notifications

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
```bash
# Setup development environment
git clone https://github.com/Latteflo/mpc-security-scanner.git
cd mpc-security-scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run tests
pytest -v

# Format code
black src/ tests/
ruff check src/ tests/
```

## 📝 License

MIT License - see [LICENSE](LICENSE) file.

## 🙏 Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io/) ecosystem
- Security research community
- OWASP and CWE projects

## 🔗 Resources

- [GitHub Issues](https://github.com/Latteflo/mpc-security-scanner/issues)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)

## ⚠️ Disclaimer

**For authorized security testing only.** Always obtain permission before scanning systems you don't own.

---

**Made with ❤️ for the security community** | [⭐ Star this repo](https://github.com/Latteflo/mpc-security-scanner)

**NEW in v0.2.0:** PDF Reports, Injection Checks, CORS Detection, Rate Limiting!
