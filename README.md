# MCP Security Scanner

[![Tests](https://github.com/Latteflo/mcp-scanner/workflows/Tests/badge.svg)](https://github.com/Latteflo/mcp-scanner/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](https://github.com/Latteflo/mcp-scanner/releases)

Security auditing tool for [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) servers. Detects authentication gaps, injection risks, AI-specific attack vectors (tool poisoning, indirect prompt injection), and maps findings to compliance frameworks.

Usable as a **web dashboard**, a **CLI**, or in **CI/CD pipelines** via SARIF output.

---

## Features

### Security Checks (27 total)

| ID | Check | Severity |
|----|-------|----------|
| MCP-AUTH-001 | Missing authentication | CRITICAL |
| MCP-CRYPTO-001 | Unencrypted transport | HIGH |
| MCP-CORS-001 | CORS misconfiguration | HIGH |
| MCP-RATE-001 | No rate limiting | HIGH |
| MCP-INJ-001 | SQL injection | CRITICAL |
| MCP-INJ-003 | Command injection | CRITICAL |
| MCP-INJ-005 | Path traversal | CRITICAL |
| MCP-INJ-007 | XML External Entity (XXE) | CRITICAL |
| MCP-AUTHZ-001 | Sensitive tool exposure | CRITICAL |
| MCP-CONFIG-001 | Default port in use | LOW |
| MCP-INFO-001 | Version disclosure | INFO |
| MCP-AI-001 | Tool description poisoning | HIGH |
| MCP-AI-002 | Over-permissive tool schema | MEDIUM |
| MCP-AI-003 | Indirect prompt injection | HIGH |
| MCP-AI-004 | System prompt leakage | HIGH |
| MCP-AI-005 | Confused deputy / tool chaining | HIGH |
| MCP-SSRF-001 | SSRF via tool parameters | HIGH |
| MCP-HDR-001 | Missing security headers | LOW |
| MCP-ERR-001 | Verbose error disclosure | MEDIUM |
| MCP-DEBUG-001 | Debug endpoint exposure | MEDIUM |
| MCP-JWT-001 | JWT authentication bypass (alg:none) | CRITICAL |
| MCP-CAP-001 | Dangerous capability exposure | HIGH |
| MCP-DOS-001 | Unbounded tool output | MEDIUM |
| MCP-DOS-002 | ReDoS via schema regex | HIGH |
| MCP-PROTO-001 | Protocol version not enforced | LOW |
| MCP-RES-001 | Resource URI path traversal | CRITICAL |
| MCP-OAUTH-001 | OAuth scope bypass | HIGH |

### Transport Support
- HTTP/HTTPS JSON-RPC 2.0
- SSE (Server-Sent Events) — used by Claude Desktop and VS Code MCP integrations

### Report Formats
- Terminal (default)
- JSON
- HTML
- PDF — A4, cover page, executive summary, remediation plan
- SARIF 2.1.0 — consumed by GitHub Security tab and VS Code Problems pane

### Compliance Frameworks
Every finding is automatically mapped to applicable controls across:
- ISO/IEC 27001:2013
- NIST Cybersecurity Framework (CSF)
- NIST SP 800-53 Rev. 5
- MITRE ATT&CK
- PCI DSS 3.2.1
- SOC 2 Type II

---

## Web Dashboard

The easiest way to use the scanner — no CLI knowledge required:

```bash
pip install mcp-security-scanner
mcp-security-scanner serve
```

Opens `http://localhost:8080` automatically.

**What you get:**
- Enter a target URL and pick a compliance framework
- Live progress bar tracking each of the 27 checks as they run
- Findings stream in real time — expand any finding for description, evidence, remediation, and compliance controls
- **Results** — severity summary cards, donut chart, category bar chart, full findings list
- **Compliance** — per-framework score cards, coverage overview, control-level breakdown
- **History** — every past scan with target, date, framework, findings count, and risk score
- Export in any format (JSON / HTML / PDF / SARIF) from the toolbar at the top or bottom of the page

```bash
mcp-security-scanner serve --port 9090   # custom port
mcp-security-scanner serve --no-browser  # headless / server use
```

---

## Installation

### pip (recommended)
```bash
pip install mcp-security-scanner
mcp-security-scanner scan --target http://localhost:3000
```

### From source
```bash
git clone https://github.com/Latteflo/mcp-scanner.git
cd mcp-scanner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/main.py scan --target http://localhost:3000
```

### Docker
```bash
make build && make demo
```

---

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

# Future scans only report NEW findings not in the baseline
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

### List all checks
```bash
mcp-security-scanner checks
```

### Exit codes (for CI/CD)
| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | HIGH severity findings present |
| 2 | CRITICAL severity findings present |
| 3 | Could not connect to target |

---

## Testing the Scanner

The repo ships an intentionally vulnerable MCP server that triggers all 27 checks. Use it to verify the scanner works or to develop new checks.

> **Warning:** This server contains real vulnerabilities by design. Run it only in an isolated environment — never expose it to the internet.

### Start the test server
```bash
# Default port 3000 (also triggers MCP-CONFIG-001)
python examples/vulnerable_server_http.py

# Custom port
MCP_PORT=3001 python examples/vulnerable_server_http.py
```

### Run the scanner against it
```bash
python src/main.py scan --target http://localhost:3000

# Expected output
# ┌──────────┬───────┐
# │ Severity │ Count │
# ├──────────┼───────┤
# │ CRITICAL │     8 │
# │ HIGH     │    11 │
# │ MEDIUM   │     4 │
# │ LOW      │     3 │
# │ INFO     │     1 │
# └──────────┴───────┘
```

### What the test server covers

| Vulnerability | How it's implemented |
|---------------|----------------------|
| No auth | Any request accepted without credentials |
| JWT alg:none | `WWW-Authenticate: Bearer` advertised; server accepts tokens with `alg: none` |
| OAuth scope bypass | Write tools accessible with read-only or empty-scope tokens |
| CORS wildcard | `Access-Control-Allow-Origin: *` on all responses |
| Command injection | `execute_command` tool runs `id && <user_input>` via shell |
| Path traversal | `read_file` tool reads any path including `/etc/passwd` |
| SQL injection | `query_database` leaks database error messages |
| XXE | `parse_xml` uses Python's default XML parser (entity expansion enabled) |
| SSRF | `fetch_url` makes outbound HTTP requests to any URL |
| ReDoS | `validate_input` schema uses `([a-zA-Z]+)+$` — catastrophic backtracking |
| Tool poisoning | `helpful_assistant` description contains `IGNORE PREVIOUS INSTRUCTIONS` |
| Confused deputy | `search_web` (read) + `send_email` (write) exposed with no auth |
| Debug endpoints | `/debug`, `/metrics`, `/swagger.json`, `/docs` unauthenticated |

---

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

Findings appear inline on pull requests in the GitHub Security tab.

### Fail the build on critical findings
```yaml
      - run: |
          mcp-security-scanner scan --target ${{ secrets.MCP_SERVER_URL }}
          # exits 2 if CRITICAL, 1 if HIGH, 0 if clean
```

---

## Testing
```bash
python -m pytest -v                           # all 125 tests
python -m pytest tests/test_checks/ -v       # check-level tests only
python -m pytest --cov=src --cov-report=html  # with coverage
```

---

## Architecture

```
mcp-scanner/
├── .github/
│   ├── CONTRIBUTING.md
│   ├── SECURITY.md
│   ├── ISSUE_TEMPLATE/
│   └── workflows/          # CI: tests, code quality, security scan
├── docker/
│   ├── Dockerfile
│   ├── Dockerfile.test-server
│   └── docker-compose.yml
├── docs/
│   ├── CHANGELOG.md
│   ├── API.md
│   ├── COMPLIANCE.md
│   └── USAGE.md
├── examples/
│   └── vulnerable_server_http.py  # Intentionally vulnerable server (all 27 checks)
├── plugins/
│   └── example_headers_check.py   # Custom check plugin example
├── src/
│   ├── main.py              # Click CLI: scan, compliance, frameworks, checks
│   ├── checks/              # 19 check modules (one per vulnerability class)
│   ├── scanner/
│   │   ├── discovery.py     # HTTP + SSE transport detection, tool schema extraction
│   │   ├── analyzer.py      # Orchestrates all 27 checks
│   │   ├── reporter.py      # JSON / HTML / SARIF / terminal output
│   │   └── pdf_reporter.py  # PDF: A4 layout, cover, exec summary, remediation plan
│   ├── compliance/
│   │   ├── frameworks.py    # 50+ controls across 6 frameworks
│   │   ├── mapper.py        # Vulnerability → framework control mapping
│   │   └── reporter.py      # Compliance report formats
│   ├── web/
│   │   ├── app.py           # FastAPI backend: SSE streaming, scan lifecycle, export
│   │   └── static/
│   │       └── index.html   # Self-contained SPA — no CDN, works offline
│   └── models/              # MCPServer, Vulnerability, ScanReport
└── tests/                   # 125 tests across checks, compliance, models, scanner
```

---

## Disclaimer

For authorized security testing only. Always obtain permission before scanning systems you do not own.

---

[Issues](https://github.com/Latteflo/mcp-scanner/issues) · [Changelog](docs/CHANGELOG.md) · [License: MIT](LICENSE)
