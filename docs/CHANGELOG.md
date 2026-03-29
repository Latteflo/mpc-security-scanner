# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.0] - 2026-03-29

### Added
- Web dashboard (`mcp-security-scanner serve`) with live SSE streaming
- Scan history panel — timestamp, target, framework, findings count, risk score
- SVG charts on Results page — severity donut and category bar chart
- Compliance section with per-framework score cards and coverage bars
- Compact export toolbar in sticky topbar (JSON / HTML / PDF / SARIF)
- On-demand report export via `POST /api/scan/{id}/export`
- 10 new security checks bringing total to 27:
  - MCP-JWT-001: JWT alg:none bypass
  - MCP-CAP-001: Dangerous capability exposure
  - MCP-DOS-001: Unbounded tool output
  - MCP-DOS-002: ReDoS via schema regex
  - MCP-PROTO-001: Protocol version not enforced
  - MCP-RES-001: Resource URI path traversal
  - MCP-OAUTH-001: OAuth scope bypass
  - MCP-AI-003: Indirect prompt injection
  - MCP-AI-004: System prompt leakage
  - MCP-AI-005: Confused deputy / tool chaining
- SSE transport support (Claude Desktop / VS Code MCP integrations)
- SARIF 2.1.0 output for GitHub Security tab integration
- Compliance mapping across ISO 27001, NIST CSF, NIST 800-53, MITRE ATT&CK, PCI DSS, SOC 2
- Baseline / diff mode (`--save-baseline` / `--baseline`)
- PDF report: A4 layout, cover page, executive summary, remediation plan

### Fixed
- CORS check: case-insensitive header lookup
- Path traversal: tests all payload variants including absolute paths
- Check ordering: OAuth probe runs before ReDoS to prevent timeout

### Changed
- PDF reporter fully rewritten — no emoji, clean A4 layout, colored severity cells
- Repository restructured: Docker files in `docker/`, community files in `.github/`

## [0.2.0] - 2025-10-15

### Added
- PDF report generation with ReportLab
- CORS misconfiguration check (MCP-CORS-001)
- Rate limiting detection (MCP-RATE-001)
- SQL injection, command injection, path traversal checks
- GitHub Actions CI/CD
- Pytest suite with coverage

### Changed
- Upgraded from 5 to 10+ security checks
- Improved vulnerability detection accuracy

## [0.1.0] - 2025-10-14

### Added
- Initial release
- Core scanning engine with async architecture
- Authentication and encryption checks
- HTML and JSON report generation
- Click-based CLI

[0.3.0]: https://github.com/Latteflo/mcp-scanner/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Latteflo/mcp-scanner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Latteflo/mcp-scanner/releases/tag/v0.1.0
