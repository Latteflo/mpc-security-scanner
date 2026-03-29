# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, email: [your-email@example.com]

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Development**: Depends on severity
- **Public Disclosure**: After fix is released

## Scope

### In Scope
- Vulnerabilities in the scanner code (`src/` directory)
- Security issues in dependencies
- Authentication/authorization bypasses
- Data leakage or exposure

### Out of Scope
- Vulnerabilities in `examples/` directory (these are intentionally vulnerable test targets)
- Issues requiring physical access
- Social engineering attacks

## Responsible Disclosure

We practice coordinated vulnerability disclosure. We will:
- Work with you to understand and reproduce the issue
- Develop and test a fix
- Credit you in the release notes (unless you prefer anonymity)
- Coordinate public disclosure timing

## Security Best Practices for Users

### When Using This Scanner

1. **Always obtain authorization** before scanning
2. **Document scope** and timing of scans
3. **Use appropriate flags** (`--allow-private`, `--insecure`) only when needed
4. **Protect reports** - they contain sensitive vulnerability data
5. **Keep updated** - use the latest version

### When Developing

1. **Run tests** before committing
2. **No secrets** in code or git history
3. **Dependencies** - keep updated, check for CVEs
4. **Code review** all security-related changes

## Known Security Considerations

### SSL Verification
- Default: Enabled (secure)
- Can be disabled with `--insecure` flag for testing
- Only disable when scanning trusted test environments

### SSRF Protection
- Private IPs blocked by default
- Cloud metadata endpoints always blocked
- Use `--allow-private` only for authorized internal scans

### Examples Directory
The `examples/` directory contains **intentionally vulnerable** code for testing the scanner. **Never** use this code in production.

---

Thank you for helping keep MCP Security Scanner secure!
