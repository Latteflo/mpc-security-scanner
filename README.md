# MCP Security Scanner

[![Tests](https://github.com/Latteflo/mcp-security-scanner/workflows/Tests/badge.svg)](https://github.com/Latteflo/mcp-security-scanner/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.2.1-green.svg)](https://github.com/Latteflo/mcp-security-scanner/releases)

Security auditing tool for [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) servers. Detects authentication gaps, injection risks, AI-specific attack vectors (tool poisoning, indirect prompt injection), and maps findings to compliance frameworks.

Usable as a **web dashboard**, a **CLI**, or in **CI/CD pipelines** via SARIF output.

## Features

### Security Checks (22 total)

| Check | ID | Severity |
|-------|----|----------|
| Missing authentication | MCP-AUTH-001 | CRITICAL |
| Unencrypted transport | MCP-CRYPTO-001 | HIGH |
| CORS misconfiguration | MCP-CORS-001 | HIGH/CRITICAL |
| No rate limiting | MCP-RATE-001 | HIGH |
| SQL injection | MCP-INJ-001 | CRITICAL |
| Command injection | MCP-INJ-003 | CRITICAL |
| Path traversal | MCP-INJ-005 | CRITICAL |
| Sensitive tool exposure | MCP-AUTHZ-001 | varies |
| Insecure configuration | MCP-CONFIG-001/002 | LOW/INFO |
| **Tool poisoning** | **MCP-AI-001** | **HIGH/CRITICAL** |
| **Over-permissive schema** | **MCP-AI-002** | **MEDIUM** |
| **Indirect prompt injection** | **MCP-AI-003** | **MEDIUM/HIGH** |
| **System prompt leakage** | **MCP-AI-004** | **MEDIUM/HIGH** |
| **SSRF via tool parameters** | **MCP-SSRF-001** | **HIGH/CRITICAL** |
| **Weak TLS protocol** | **MCP-TLS-001** | **HIGH** |
| **TLS certificate issues** | **MCP-TLS-002** | **HIGH** |
| **Missing security headers** | **MCP-HDR-001** | **LOW** |
| **Verbose error disclosure** | **MCP-ERR-001** | **MEDIUM** |
| **Debug endpoint exposure** | **MCP-DEBUG-001** | **MEDIUM/HIGH** |
| **JWT authentication bypass** | **MCP-JWT-001** | **HIGH/CRITICAL** |
| **Dangerous capability exposure** | **MCP-CAP-001** | **MEDIUM/HIGH** |
| **Unbounded tool output** | **MCP-DOS-001** | **MEDIUM/HIGH** |

### Transport Support
- HTTP/HTTPS JSON-RPC 2.0
- SSE (Server-Sent Events) — the transport used by Claude Desktop and VS Code MCP integrations

### Report Formats
- Terminal (default)
- JSON
- HTML
- PDF
- **SARIF 2.1.0** — consumed by GitHub Security tab and VS Code Problems pane

### Compliance Frameworks
Every finding is automatically mapped to applicable controls across:
- ISO/IEC 27001:2013
- NIST Cybersecurity Framework (CSF)
- NIST SP 800-53 Rev. 5
- MITRE ATT&CK
- PCI DSS 3.2.1
- SOC 2 Type II

## Web Dashboard

The easiest way to use the scanner — no CLI knowledge required:

```bash
pip install mcp-security-scanner
mcp-security-scanner serve
```

Opens `http://localhost:8080` in your browser automatically. From there:
- Enter a target URL and pick a compliance framework
- Watch findings stream in live as each check runs
- Expand any finding for description, remediation steps, evidence, and mapped compliance controls
- Switch to the **Compliance** tab for a per-framework score, gap analysis, and control breakdown
- Download the report (JSON / HTML / PDF / SARIF)
- Fully responsive — works on mobile and tablet

```bash
mcp-security-scanner serve --port 9090   # custom port
mcp-security-scanner serve --no-browser  # headless / server use
```

## Installation

### pip (recommended)
```bash
pip install mcp-security-scanner
mcp-security-scanner scan --target http://localhost:3000
```

### From source
```bash
git clone https://github.com/Latteflo/mcp-security-scanner.git
cd mcp-security-scanner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/main.py scan --target http://localhost:3000
```

### Docker
```bash
make build && make demo
```

## CLI Usage

### Scan
```bash
# Basic scan — terminal output
mcp-security-scanner scan --target http://localhost:3000

# Save SARIF for GitHub Security tab
mcp-security-scanner scan --target http://localhost:3000 --format sarif --output results.sarif

# HTML report
mcp-security-scanner scan --target http://localhost:3000 --format html --output report.html

# Scan an SSE endpoint (Claude Desktop / VS Code)
mcp-security-scanner scan --target http://localhost:3000/sse
```

### Baseline / diff mode
```bash
# Save current findings as a baseline
mcp-security-scanner scan --target http://localhost:3000 --save-baseline baseline.json

# Future scans only show NEW findings not in the baseline
mcp-security-scanner scan --target http://localhost:3000 --baseline baseline.json
```

### Compliance
```bash
# Full compliance assessment across all frameworks
mcp-security-scanner compliance --target http://localhost:3000

# Single framework
mcp-security-scanner compliance --target http://localhost:3000 --framework ISO27001

# List all supported frameworks and their controls
mcp-security-scanner frameworks
```

### Exit codes (for CI/CD)
| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | HIGH severity findings present |
| 2 | CRITICAL severity findings present |
| 3 | Could not connect to target |

## CI/CD Integration

### GitHub Actions with SARIF upload
```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install mcp-security-scanner
      - run: |
          mcp-security-scanner scan \
            --target ${{ secrets.MCP_SERVER_URL }} \
            --format sarif \
            --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

Findings appear inline on pull requests in the GitHub Security tab without any extra tooling.

### Fail the build on critical findings
```yaml
      - run: |
          mcp-security-scanner scan --target ${{ secrets.MCP_SERVER_URL }}
          # exits 2 if CRITICAL, 1 if HIGH, 0 if clean
```

## Testing
```bash
pytest -v                          # all 76 tests
pytest tests/test_checks/ -v       # check-level tests only
pytest --cov=src --cov-report=html # with coverage
```

## Architecture

```
src/
├── main.py              # Click CLI: scan, compliance, frameworks subcommands
├── checks/
│   ├── ai_specific.py   # MCP-AI-001/002/003 (tool poisoning, schema, injection)
│   ├── cors.py
│   ├── injection.py
│   └── rate_limiting.py
├── scanner/
│   ├── discovery.py     # HTTP + SSE transport detection, full tool schema extraction
│   ├── analyzer.py      # Orchestrates all checks
│   ├── reporter.py      # JSON / HTML / SARIF / terminal output
│   └── pdf_reporter.py
├── compliance/
│   ├── frameworks.py    # 50+ controls across 6 frameworks
│   ├── mapper.py        # Vulnerability → framework control mapping
│   └── reporter.py      # Compliance-specific report formats
├── web/
│   ├── app.py           # FastAPI backend: scan lifecycle, SSE, report download
│   └── static/
│       └── index.html   # Self-contained SPA (no CDN, works offline)
└── models/              # MCPServer, Vulnerability, ScanReport
```

## Disclaimer

For authorized security testing only. Always obtain permission before scanning systems you do not own.

---

[Issues](https://github.com/Latteflo/mcp-security-scanner/issues) · [Releases](https://github.com/Latteflo/mcp-security-scanner/releases) · [License: MIT](LICENSE)
