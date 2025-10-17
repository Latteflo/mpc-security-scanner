# 🔒 MCP Security Scanner

[![Tests](https://github.com/Latteflo/mpc-security-scanner/workflows/Tests/badge.svg)](https://github.com/Latteflo/mpc-security-scanner/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.2.0-green.svg)](https://github.com/Latteflo/mpc-security-scanner/releases)

A comprehensive security auditing tool for Model Context Protocol (MCP) servers with **full compliance framework support**.

> **NEW in v0.2.0:** 🎉 Compliance Framework Support - ISO 27001, NIST CSF, NIST 800-53, MITRE ATT&CK, PCI DSS, SOC 2

## ✨ Key Features

### 🔍 Security Scanning
- **10+ Security Checks** - Authentication, Encryption, CORS, Rate Limiting, Injection attacks
- **Automatic Discovery** - Probe and fingerprint MCP servers
- **Fast & Async** - Efficient async/await architecture
- **Multiple Report Formats** - JSON, HTML, PDF, Markdown, Terminal

### 📋 Compliance Framework Support
- **ISO/IEC 27001:2013** - Information Security Management (12+ controls)
- **NIST Cybersecurity Framework** - Risk-based approach (5+ functions)
- **NIST SP 800-53 Rev. 5** - Security and privacy controls (9+ controls)
- **MITRE ATT&CK** - Adversarial tactics and techniques (8+ techniques)
- **PCI DSS 3.2.1** - Payment card security (3+ requirements)
- **SOC 2 Type II** - Service organization controls (3+ criteria)

### 🎯 Advanced Features
- **Automatic Compliance Mapping** - Every vulnerability mapped to framework controls
- **Gap Analysis** - Identify specific compliance gaps
- **Remediation Priorities** - Risk-based prioritization
- **Audit-Ready Reports** - Professional reports for auditors
- **CI/CD Integration** - Automate compliance scanning

## 🚀 Quick Start

### Installation
```bash
git clone https://github.com/Latteflo/mpc-security-scanner.git
cd mpc-security-scanner
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Basic Usage
```bash
# Scan a server
python src/main.py scan --target http://example.com:3000

# Run compliance assessment
python src/main.py compliance --target http://example.com:3000

# List all frameworks
python src/main.py frameworks

# View specific framework
python src/main.py frameworks --framework ISO27001

# Generate reports
python src/main.py scan --target http://example.com:3000 --format pdf
python src/main.py compliance --target http://example.com:3000 --format json
```

### Demo Mode
```bash
# Run demos
python scripts/test_scanner.py
python scripts/test_compliance_scanner.py

# View demo reports
xdg-open reports/demos/demo_scan.html
xdg-open reports/demos/compliance_demo.md
```

## 📊 Security Checks

| Check | Severity | Frameworks |
|-------|----------|------------|
| **Authentication** | 🔴 CRITICAL | ISO 27001, NIST CSF, PCI DSS, SOC 2 |
| **Encryption** | 🟠 HIGH | ISO 27001, NIST CSF, PCI DSS |
| **CORS** | 🔴 CRITICAL | ISO 27001, NIST 800-53, MITRE |
| **Rate Limiting** | 🟠 HIGH | ISO 27001, NIST CSF, SOC 2 |
| **SQL Injection** | 🔴 CRITICAL | ISO 27001, NIST 800-53, PCI DSS |
| **Command Injection** | 🔴 CRITICAL | ISO 27001, NIST 800-53, PCI DSS |
| **Path Traversal** | 🔴 CRITICAL | ISO 27001, NIST 800-53, PCI DSS |
| **Authorization** | 🔴 CRITICAL | ISO 27001, NIST 800-53, SOC 2 |
| **Configuration** | 🔵 LOW | ISO 27001, NIST CSF |
| **Info Disclosure** | 🟢 INFO | ISO 27001, NIST 800-53 |

## 🏗️ Project Structure
```
mcp-security-scanner/
├── src/                     # Source code
│   ├── compliance/          # Compliance framework support
│   │   ├── frameworks.py    # Framework definitions (50+ controls)
│   │   ├── mapper.py        # Vulnerability-to-control mapping
│   │   └── reporter.py      # Compliance report generators
│   ├── scanner/             # Core scanning engine
│   │   ├── discovery.py     # Server discovery
│   │   ├── analyzer.py      # Security analysis
│   │   ├── reporter.py      # Report generation
│   │   └── pdf_reporter.py  # PDF reports
│   ├── checks/              # Security checks
│   │   ├── cors.py          # CORS checks
│   │   ├── rate_limiting.py # Rate limiting
│   │   └── injection.py     # Injection checks
│   ├── models/              # Data models
│   │   ├── vulnerability.py # Vulnerability (with compliance)
│   │   ├── server.py        # Server model
│   │   └── report.py        # Report model
│   ├── utils/               # Utilities
│   │   ├── network.py       # Network utilities
│   │   ├── logger.py        # Logging
│   │   └── config.py        # Configuration
│   └── main.py              # CLI interface
├── tests/                   # Test suite (30+ tests)
│   ├── test_compliance/     # Compliance tests
│   ├── test_scanner/        # Scanner tests
│   ├── test_checks/         # Security check tests
│   ├── test_models/         # Model tests
│   └── test_utils/          # Utility tests
├── docs/                    # Documentation
│   ├── COMPLIANCE.md        # Compliance guide
│   ├── USAGE.md            # Usage guide
│   ├── API.md              # API reference
│   └── SECURITY.md         # Security guide
├── scripts/                 # Scripts and demos
│   ├── test_compliance_scanner.py
│   ├── test_scanner.py
│   └── verify_compliance_implementation.sh
├── reports/                 # Generated reports
│   ├── demos/              # Demo reports (tracked)
│   ├── scans/              # Scan reports (gitignored)
│   └── compliance/         # Compliance reports (gitignored)
└── examples/               # Example servers
```

## 📚 Documentation

- **[Compliance Guide](docs/COMPLIANCE.md)** - Framework documentation
- **[Usage Guide](docs/USAGE.md)** - Detailed usage examples
- **[API Reference](docs/API.md)** - Developer documentation
- **[Security Guide](docs/SECURITY.md)** - Security best practices
- **[Contributing](CONTRIBUTING.md)** - Contribution guidelines
- **[Changelog](CHANGELOG.md)** - Version history

## 🧪 Testing
```bash
# Run all tests
pytest -v

# Run specific test suite
pytest tests/test_compliance/ -v

# Run with coverage
pytest --cov=src --cov-report=html

# Run verification
bash scripts/verify_compliance_implementation.sh
```

## 📈 Statistics

- **Version:** 0.2.0
- **Security Checks:** 10+
- **Compliance Frameworks:** 6
- **Framework Controls:** 50+
- **Test Coverage:** 50%+
- **Tests:** 30+
- **Report Formats:** 4

## 🔧 CI/CD Integration
```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: |
          python src/main.py compliance \
            --target ${{ secrets.MCP_SERVER_URL }} \
            --format json \
            --output compliance-report.json
      - uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: compliance-report.json
```

## 🎯 Use Cases

- **Security Teams** - Regular audits, compliance reporting, vulnerability assessments
- **Development Teams** - CI/CD integration, pre-deployment checks, regression testing
- **DevOps** - Configuration validation, security baseline enforcement
- **Compliance & Audit** - Framework compliance checks, gap analysis, audit documentation

## 🗺️ Roadmap

### v0.3.0 (Planned)
- [ ] GDPR and HIPAA compliance mapping
- [ ] Custom framework definitions
- [ ] Historical compliance tracking
- [ ] Interactive web dashboard
- [ ] REST API

### v0.4.0 (Future)
- [ ] Real-time monitoring
- [ ] Slack/Email notifications
- [ ] Multi-server scanning
- [ ] Plugin system
- [ ] Advanced analytics

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).
```bash
git clone https://github.com/Latteflo/mpc-security-scanner.git
cd mpc-security-scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -v
```

## 📝 License

MIT License - see [LICENSE](LICENSE).

## 🙏 Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/)
- OWASP and CWE projects
- NIST, ISO, and MITRE frameworks
- Security research community

## 🔗 Links

- **Repository:** [GitHub](https://github.com/Latteflo/mpc-security-scanner)
- **Issues:** [Issue Tracker](https://github.com/Latteflo/mpc-security-scanner/issues)
- **Releases:** [Releases](https://github.com/Latteflo/mpc-security-scanner/releases)

## ⚠️ Disclaimer

**For authorized security testing only.** Always obtain permission before scanning systems you don't own.

---

**Made with ❤️ for the security community**

[⭐ Star this repo](https://github.com/Latteflo/mpc-security-scanner) • [📖 Read the docs](docs/) • [🐛 Report issues](https://github.com/Latteflo/mpc-security-scanner/issues)
