# 🔒 Compliance Framework Support

## Supported Frameworks

The MCP Security Scanner now maps vulnerabilities to major compliance frameworks:

### ✅ ISO/IEC 27001:2013
- **12+ Controls** mapped
- Information Security Management System (ISMS)
- Domains: Access Control, Cryptography, Communications Security

### ✅ NIST Cybersecurity Framework
- **5+ Functions** covered
- Risk-based approach to cybersecurity
- Categories: Identify, Protect, Detect, Respond, Recover

### ✅ NIST SP 800-53 Rev. 5
- **15+ Controls** mapped
- Security and privacy controls for information systems
- Families: Access Control, Identification & Authentication, System Protection

### ✅ MITRE ATT&CK Framework
- **8+ Techniques** identified
- Adversary tactics and techniques knowledge base
- Tactics: Initial Access, Execution, Persistence, Privilege Escalation

### ✅ PCI DSS 3.2.1
- **4+ Requirements** addressed
- Payment Card Industry Data Security Standard
- Critical for organizations handling cardholder data

### ✅ SOC 2 Type II
- **3+ Trust Service Criteria** evaluated
- Service Organization Control reporting
- Common Criteria: Security, Availability, Confidentiality

## Usage

### Run Compliance Assessment
```bash
# Terminal output (default)
python src/main.py compliance --target http://localhost:3000

# JSON report
python src/main.py compliance --target http://localhost:3000 \
  --format json --output compliance_report.json

# Markdown report
python src/main.py compliance --target http://localhost:3000 \
  --format markdown --output compliance_report.md
```

### List All Frameworks
```bash
# Show all supported frameworks
python src/main.py frameworks

# Show specific framework controls
python src/main.py frameworks --framework ISO27001
python src/main.py frameworks --framework NIST_CSF
python src/main.py frameworks --framework MITRE_ATTCK
```

### Demo Compliance Scanner
```bash
# Run demo with mock vulnerable server
python test_compliance_scanner.py
```

## Compliance Report Features

### Terminal Report
- Executive summary with framework status
- Affected controls per framework
- Remediation priorities
- Color-coded severity indicators

### JSON Report
- Machine-readable format
- Complete compliance mappings
- Gap analysis per framework
- Integration with CI/CD pipelines

### Markdown Report
- Human-readable documentation
- Framework-by-framework analysis
- Control mapping tables
- Remediation recommendations

## Example Output
```
🔒 COMPLIANCE ASSESSMENT REPORT
================================================================================

Assessment Overview
┌─────────────────────┬──────────────────────────────────────┐
│ Target Server       │ http://localhost:3000                │
│ Server Name         │ Test Vulnerable Server               │
│ Assessment Date     │ 2025-01-15 10:30:00                 │
│ Total Vulnerabilities│ 7                                   │
└─────────────────────┴──────────────────────────────────────┘

Compliance Framework Summary
┌──────────────────────────────┬─────────────────┬──────────────┬──────┬──────┐
│ Framework                    │ Status          │ Controls     │ Crit │ High │
├──────────────────────────────┼─────────────────┼──────────────┼──────┼──────┤
│ ISO/IEC 27001:2013          │ ❌ Non-Compliant│ 12           │ 3    │ 2    │
│ NIST Cybersecurity Framework │ ❌ Non-Compliant│ 5            │ 3    │ 2    │
│ NIST SP 800-53 Rev. 5       │ ❌ Non-Compliant│ 9            │ 3    │ 2    │
│ MITRE ATT&CK Framework      │ ⚠️  Multiple TTPs│ 6            │ 3    │ 2    │
└──────────────────────────────┴─────────────────┴──────────────┴──────┴──────┘
```

## Integration Examples

### CI/CD Pipeline
```yaml
# .github/workflows/security-compliance.yml
name: Security Compliance Scan

on: [push, pull_request]

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Compliance Scan
        run: |
          python src/main.py compliance \
            --target ${{ secrets.MCP_SERVER_URL }} \
            --format json \
            --output compliance-report.json
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: compliance-report.json
```

### Automated Auditing
```python
from src.scanner import SecurityAnalyzer
from src.compliance import ComplianceReportGenerator

# Scan server
analyzer = SecurityAnalyzer()
vulnerabilities = await analyzer.scan(server)

# Generate compliance report
reporter = ComplianceReportGenerator()
report = reporter.generate_json_report(
    server, vulnerabilities, "audit-report.json"
)
```

## Compliance Mapping

Each vulnerability is automatically mapped to relevant framework controls:
```python
# Example: MCP-AUTH-001 (Missing Authentication)
{
  "ISO27001": ["A.9.2.1", "A.9.4.2"],
  "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
  "NIST_800_53": ["IA-2", "AC-2"],
  "MITRE_ATTCK": ["T1078"],
  "PCI_DSS": ["8.2"],
  "SOC2": ["CC6.1"]
}
```

## Benefits

✅ **Automated Compliance Mapping** - No manual mapping required  
✅ **Multiple Framework Support** - One scan, multiple compliance reports  
✅ **Gap Analysis** - Identify specific controls that need attention  
✅ **Audit-Ready Reports** - Professional reports for auditors  
✅ **Continuous Compliance** - Integrate into CI/CD pipelines  
✅ **Risk Prioritization** - Focus on highest-impact vulnerabilities  

## Roadmap

- [ ] GDPR compliance mapping
- [ ] HIPAA compliance mapping
- [ ] Custom framework definitions
- [ ] Compliance scoring algorithms
- [ ] Historical compliance tracking
- [ ] Compliance dashboard

## Contributing

To add new frameworks or controls, edit:
- `src/compliance/frameworks.py` - Framework definitions
- `src/compliance/mapper.py` - Vulnerability mappings

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
# 🔒 Compliance Framework Support

## Supported Frameworks

The MCP Security Scanner now maps vulnerabilities to major compliance frameworks:

### ✅ ISO/IEC 27001:2013
- **12+ Controls** mapped
- Information Security Management System (ISMS)
- Domains: Access Control, Cryptography, Communications Security

### ✅ NIST Cybersecurity Framework
- **5+ Functions** covered
- Risk-based approach to cybersecurity
- Categories: Identify, Protect, Detect, Respond, Recover

### ✅ NIST SP 800-53 Rev. 5
- **15+ Controls** mapped
- Security and privacy controls for information systems
- Families: Access Control, Identification & Authentication, System Protection

### ✅ MITRE ATT&CK Framework
- **8+ Techniques** identified
- Adversary tactics and techniques knowledge base
- Tactics: Initial Access, Execution, Persistence, Privilege Escalation

### ✅ PCI DSS 3.2.1
- **4+ Requirements** addressed
- Payment Card Industry Data Security Standard
- Critical for organizations handling cardholder data

### ✅ SOC 2 Type II
- **3+ Trust Service Criteria** evaluated
- Service Organization Control reporting
- Common Criteria: Security, Availability, Confidentiality

## Usage

### Run Compliance Assessment
```bash
# Terminal output (default)
python src/main.py compliance --target http://localhost:3000

# JSON report
python src/main.py compliance --target http://localhost:3000 \
  --format json --output compliance_report.json

# Markdown report
python src/main.py compliance --target http://localhost:3000 \
  --format markdown --output compliance_report.md
```

### List All Frameworks
```bash
# Show all supported frameworks
python src/main.py frameworks

# Show specific framework controls
python src/main.py frameworks --framework ISO27001
python src/main.py frameworks --framework NIST_CSF
python src/main.py frameworks --framework MITRE_ATTCK
```

### Demo Compliance Scanner
```bash
# Run demo with mock vulnerable server
python test_compliance_scanner.py
```

## Compliance Report Features

### Terminal Report
- Executive summary with framework status
- Affected controls per framework
- Remediation priorities
- Color-coded severity indicators

### JSON Report
- Machine-readable format
- Complete compliance mappings
- Gap analysis per framework
- Integration with CI/CD pipelines

### Markdown Report
- Human-readable documentation
- Framework-by-framework analysis
- Control mapping tables
- Remediation recommendations

## Example Output
```
🔒 COMPLIANCE ASSESSMENT REPORT
================================================================================

Assessment Overview
┌─────────────────────┬──────────────────────────────────────┐
│ Target Server       │ http://localhost:3000                │
│ Server Name         │ Test Vulnerable Server               │
│ Assessment Date     │ 2025-01-15 10:30:00                 │
│ Total Vulnerabilities│ 7                                   │
└─────────────────────┴──────────────────────────────────────┘

Compliance Framework Summary
┌──────────────────────────────┬─────────────────┬──────────────┬──────┬──────┐
│ Framework                    │ Status          │ Controls     │ Crit │ High │
├──────────────────────────────┼─────────────────┼──────────────┼──────┼──────┤
│ ISO/IEC 27001:2013          │ ❌ Non-Compliant│ 12           │ 3    │ 2    │
│ NIST Cybersecurity Framework │ ❌ Non-Compliant│ 5            │ 3    │ 2    │
│ NIST SP 800-53 Rev. 5       │ ❌ Non-Compliant│ 9            │ 3    │ 2    │
│ MITRE ATT&CK Framework      │ ⚠️  Multiple TTPs│ 6            │ 3    │ 2    │
└──────────────────────────────┴─────────────────┴──────────────┴──────┴──────┘
```

## Integration Examples

### CI/CD Pipeline
```yaml
# .github/workflows/security-compliance.yml
name: Security Compliance Scan

on: [push, pull_request]

jobs:
  compliance-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Compliance Scan
        run: |
          python src/main.py compliance \
            --target ${{ secrets.MCP_SERVER_URL }} \
            --format json \
            --output compliance-report.json
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: compliance-report.json
```

### Automated Auditing
```python
from src.scanner import SecurityAnalyzer
from src.compliance import ComplianceReportGenerator

# Scan server
analyzer = SecurityAnalyzer()
vulnerabilities = await analyzer.scan(server)

# Generate compliance report
reporter = ComplianceReportGenerator()
report = reporter.generate_json_report(
    server, vulnerabilities, "audit-report.json"
)
```

## Compliance Mapping

Each vulnerability is automatically mapped to relevant framework controls:
```python
# Example: MCP-AUTH-001 (Missing Authentication)
{
  "ISO27001": ["A.9.2.1", "A.9.4.2"],
  "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
  "NIST_800_53": ["IA-2", "AC-2"],
  "MITRE_ATTCK": ["T1078"],
  "PCI_DSS": ["8.2"],
  "SOC2": ["CC6.1"]
}
```

## Benefits

✅ **Automated Compliance Mapping** - No manual mapping required  
✅ **Multiple Framework Support** - One scan, multiple compliance reports  
✅ **Gap Analysis** - Identify specific controls that need attention  
✅ **Audit-Ready Reports** - Professional reports for auditors  
✅ **Continuous Compliance** - Integrate into CI/CD pipelines  
✅ **Risk Prioritization** - Focus on highest-impact vulnerabilities  

## Roadmap

- [ ] GDPR compliance mapping
- [ ] HIPAA compliance mapping
- [ ] Custom framework definitions
- [ ] Compliance scoring algorithms
- [ ] Historical compliance tracking
- [ ] Compliance dashboard

## Contributing

To add new frameworks or controls, edit:
- `src/compliance/frameworks.py` - Framework definitions
- `src/compliance/mapper.py` - Vulnerability mappings

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
