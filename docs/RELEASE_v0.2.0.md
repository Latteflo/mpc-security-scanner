# 🎉 Release v0.2.0 - Compliance Framework Support

## Overview

This major release adds comprehensive compliance framework support to the MCP Security Scanner, making it suitable for enterprise security audits and regulatory compliance assessments.

## 🆕 Major Features

### Six Compliance Frameworks

- **ISO/IEC 27001:2013** - Information Security Management (12 controls mapped)
- **NIST Cybersecurity Framework** - Risk-based cybersecurity (5 functions mapped)
- **NIST SP 800-53 Rev. 5** - Security and privacy controls (9 controls mapped)
- **MITRE ATT&CK** - Adversarial tactics and techniques (8 techniques mapped)
- **PCI DSS 3.2.1** - Payment card security (3 requirements mapped)
- **SOC 2 Type II** - Service organization controls (3 criteria mapped)

### Key Capabilities

✨ **Automatic Compliance Mapping** - Every vulnerability automatically mapped to relevant framework controls  
✨ **Gap Analysis** - Detailed compliance gap reports per framework  
✨ **Multiple Report Formats** - Terminal, JSON, Markdown, PDF  
✨ **Risk-Based Prioritization** - Remediation priorities based on framework impact  
✨ **Audit-Ready Reports** - Professional reports for compliance auditors  

## 🔍 New Security Checks

- **CORS Misconfiguration** - Detect wildcard origins and origin reflection
- **Rate Limiting & DoS** - Test for denial-of-service protection
- **SQL Injection** - Automated SQL injection vulnerability testing
- **Command Injection** - Shell command execution vulnerability testing
- **Path Traversal** - Directory traversal vulnerability testing

## 🚀 Installation
```bash
git clone https://github.com/Latteflo/mpc-security-scanner.git
cd mcp-security-scanner
pip install -r requirements.txt
```

## 📖 Quick Start

### Basic Security Scan
```bash
python src/main.py scan --target http://example.com:3000 --format html
```

### Compliance Assessment
```bash
# Full compliance assessment
python src/main.py compliance --target http://example.com:3000

# Specific frameworks only
python src/main.py compliance --target http://example.com:3000 \
  -fw ISO27001 -fw NIST_CSF

# Generate JSON report
python src/main.py compliance --target http://example.com:3000 \
  --format json --output compliance.json
```

### Explore Frameworks
```bash
# List all frameworks
python src/main.py frameworks

# View specific framework controls
python src/main.py frameworks --framework ISO27001
python src/main.py frameworks --framework MITRE_ATTCK
```

## 📊 Example Output
```
Compliance Framework Summary

╭──────────────────────────────┬──────────────────┬───────────────────┬──────────┬──────╮
│ Framework                    │      Status      │ Affected Controls │ Critical │ High │
├──────────────────────────────┼──────────────────┼───────────────────┼──────────┼──────┤
│ ISO/IEC 27001:2013           │ ❌ Non-Compliant │         8         │    2     │  2   │
│ NIST Cybersecurity Framework │ ❌ Non-Compliant │         4         │    2     │  2   │
│ NIST SP 800-53 Rev. 5        │ ❌ Non-Compliant │         8         │    2     │  2   │
│ MITRE ATT&CK Framework       │ ❌ Non-Compliant │         3         │    2     │  2   │
│ PCI DSS 3.2.1                │ ❌ Non-Compliant │         3         │    2     │  2   │
│ SOC 2 Type II                │ ❌ Non-Compliant │         2         │    2     │  2   │
╰──────────────────────────────┴──────────────────┴───────────────────┴──────────┴──────╯
```

## 🎯 Use Cases

### For Security Teams
- Perform regular compliance audits
- Generate SOC2/ISO 27001/PCI DSS reports
- Track compliance status over time
- Identify security gaps quickly

### For DevOps
- Integrate into CI/CD pipelines
- Automate compliance checking
- Generate audit documentation
- Monitor configuration drift

### For Compliance Officers
- Get audit-ready reports
- Track framework coverage
- Document remediation progress
- Maintain compliance evidence

## 📈 Statistics

- **6** compliance frameworks supported
- **50+** framework controls mapped
- **11** vulnerability types covered
- **10+** security checks
- **4** report formats
- **30+** tests with 50%+ coverage

## 🔧 CI/CD Integration
```yaml
name: Compliance Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -r requirements.txt
      - run: python src/main.py compliance --target ${{ secrets.MCP_URL }} --format json
```

## 📚 Documentation

- [Compliance Guide](../docs/COMPLIANCE.md) - Detailed framework documentation
- [Usage Guide](../docs/USAGE.md) - Comprehensive usage examples
- [API Reference](../docs/API.md) - Developer documentation
- [Changelog](../CHANGELOG.md) - Full version history

## 🐛 Known Issues

None at this time. Report issues at: https://github.com/Latteflo/mpc-security-scanner/issues

## 🗺️ What's Next (v0.3.0)

- GDPR and HIPAA compliance mapping
- Custom framework definitions
- Historical compliance tracking
- Interactive web dashboard
- REST API for integration

## 💬 Community

- **Report Issues:** [GitHub Issues](https://github.com/Latteflo/mpc-security-scanner/issues)
- **Contribute:** See [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Discussions:** [GitHub Discussions](https://github.com/Latteflo/mpc-security-scanner/discussions)

## 📄 License

MIT License - see [LICENSE](../LICENSE)

## 🙏 Acknowledgments

Thanks to all contributors and the security community for making this release possible!

---

**Download:** [v0.2.0](https://github.com/Latteflo/mpc-security-scanner/releases/tag/v0.2.0)  
**Full Changelog:** [v0.1.0...v0.2.0](https://github.com/Latteflo/mpc-security-scanner/compare/v0.1.0...v0.2.0)
