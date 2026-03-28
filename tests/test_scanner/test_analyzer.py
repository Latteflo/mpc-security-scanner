"""
Tests for SecurityAnalyzer.

Architecture note
─────────────────
The analyzer runs two categories of checks:

  Property-based (no HTTP):
    auth, encryption, tool exposure, configuration
    These inspect MCPServer fields directly and are fully testable without mocking.

  Network-dependent (makes HTTP calls):
    CORS, rate limiting, SQL injection, command injection, path traversal
    These are imported into analyzer.py's namespace and called from there.

All network-dependent checks are patched in every test so that:
  1. Tests don't make real HTTP calls or depend on a running server.
  2. Tests don't accidentally pass because ConnectionError → None — that
     would mean a test "passes" by silently skipping the check, not by
     confirming the check logic is correct.

Patching target: `src.scanner.analyzer.<function_name>` (the name as it lives
in the analyzer module's namespace after import).
"""

import pytest
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from src.scanner import SecurityAnalyzer
from src.models import MCPServer, Severity


# All network-dependent check functions as they appear in analyzer.py's namespace
_NETWORK_CHECKS = [
    "src.scanner.analyzer.check_cors_misconfiguration",
    "src.scanner.analyzer.check_rate_limiting",
    "src.scanner.analyzer.check_sql_injection",
    "src.scanner.analyzer.check_command_injection",
    "src.scanner.analyzer.check_path_traversal",
]


def silence_network_checks():
    """
    Context manager that patches all network-dependent checks to return None.

    Use this in every test that doesn't specifically need to exercise CORS,
    rate limiting, or injection checks. Without it, a test that passes because
    the connection was refused is not testing anything meaningful.
    """
    stack = ExitStack()
    for target in _NETWORK_CHECKS:
        stack.enter_context(patch(target, new=AsyncMock(return_value=None)))
    return stack


@pytest.mark.asyncio
async def test_analyzer_starts_empty():
    """Freshly constructed analyzer has no accumulated state."""
    analyzer = SecurityAnalyzer()
    assert analyzer.vulnerabilities == []


@pytest.mark.asyncio
async def test_missing_auth_is_flagged_critical():
    """
    has_authentication=False → MCP-AUTH-001 CRITICAL.

    This is a pure property check — no HTTP call is made regardless of mocking.
    We still silence network checks so the assertion on critical count is exact.
    """
    server = MCPServer(
        host="localhost",
        port=9001,  # non-default port so config check doesn't add noise
        protocol="https",
        has_authentication=False,
        has_encryption=True,
    )

    with silence_network_checks():
        analyzer = SecurityAnalyzer()
        vulns = await analyzer.scan(server)

    ids = {v.id for v in vulns}
    assert "MCP-AUTH-001" in ids
    auth_vuln = next(v for v in vulns if v.id == "MCP-AUTH-001")
    assert auth_vuln.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_unencrypted_connection_is_flagged_high():
    """has_encryption=False → MCP-CRYPTO-001 HIGH."""
    server = MCPServer(
        host="localhost",
        port=9001,
        protocol="http",
        has_authentication=True,
        has_encryption=False,
    )

    with silence_network_checks():
        analyzer = SecurityAnalyzer()
        vulns = await analyzer.scan(server)

    ids = {v.id for v in vulns}
    assert "MCP-CRYPTO-001" in ids
    crypto_vuln = next(v for v in vulns if v.id == "MCP-CRYPTO-001")
    assert crypto_vuln.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_dangerous_tools_without_auth_are_critical():
    """
    Dangerous tools + no auth → CRITICAL.

    Severity is elevated when auth is missing because unauthenticated access
    to dangerous tools means any caller can use them.
    """
    server = MCPServer(
        host="localhost",
        port=9001,
        protocol="https",
        tools=["execute_command", "sql_query"],
        has_authentication=False,
        has_encryption=True,
    )

    with silence_network_checks():
        analyzer = SecurityAnalyzer()
        vulns = await analyzer.scan(server)

    tool_vulns = [v for v in vulns if v.id == "MCP-AUTHZ-001"]
    assert len(tool_vulns) == 1
    assert tool_vulns[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_dangerous_tools_with_auth_are_high():
    """
    Dangerous tools + auth present → HIGH (not CRITICAL).

    Authentication reduces the blast radius even if the tools themselves
    are dangerous — at least the caller had to authenticate.
    """
    server = MCPServer(
        host="localhost",
        port=9001,
        protocol="https",
        tools=["execute_command"],
        has_authentication=True,
        has_encryption=True,
    )

    with silence_network_checks():
        analyzer = SecurityAnalyzer()
        vulns = await analyzer.scan(server)

    tool_vulns = [v for v in vulns if v.id == "MCP-AUTHZ-001"]
    assert len(tool_vulns) == 1
    assert tool_vulns[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_default_port_flagged_low():
    """Port 3000 (and 8080, 5000) are well-known defaults → LOW config finding."""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="https",
        has_authentication=True,
        has_encryption=True,
    )

    with silence_network_checks():
        analyzer = SecurityAnalyzer()
        vulns = await analyzer.scan(server)

    port_vulns = [v for v in vulns if v.id == "MCP-CONFIG-001"]
    assert len(port_vulns) == 1
    assert port_vulns[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_secure_server_has_no_critical_findings():
    """
    Well-configured server (auth + TLS + non-default port + safe tools) should
    produce zero CRITICAL findings.

    With network checks silenced, the only remaining checks are property-based.
    This gives us confidence the property checks don't over-report.
    """
    server = MCPServer(
        host="secure.example.com",
        port=12345,
        protocol="https",
        has_authentication=True,
        has_encryption=True,
        tools=["get_status", "list_resources"],  # no dangerous patterns
    )

    with silence_network_checks():
        analyzer = SecurityAnalyzer()
        vulns = await analyzer.scan(server)

    critical = [v for v in vulns if v.severity == Severity.CRITICAL]
    assert critical == [], (
        f"Expected no CRITICAL findings on a secure server, got: "
        f"{[v.id for v in critical]}"
    )


@pytest.mark.asyncio
async def test_cors_finding_is_included_when_check_returns_one():
    """
    Verify the analyzer correctly collects findings from network checks.

    We inject a fake CORS vulnerability to confirm the analyzer appends it
    to the results — this tests the wiring, not the CORS logic itself.
    """
    from src.models import Vulnerability, Severity as S

    fake_cors_vuln = Vulnerability.create(
        id="MCP-CORS-001",
        title="Test CORS Finding",
        description="injected in test",
        severity=S.HIGH,
        category="CORS",
        remediation="n/a",
        evidence=[],
        affected_component="CORS",
    )

    server = MCPServer(host="localhost", port=9001, protocol="https",
                       has_authentication=True, has_encryption=True)

    with ExitStack() as stack:
        # Return our fake vuln from the CORS check
        stack.enter_context(patch(
            "src.scanner.analyzer.check_cors_misconfiguration",
            new=AsyncMock(return_value=fake_cors_vuln),
        ))
        # Silence the rest
        for target in _NETWORK_CHECKS[1:]:
            stack.enter_context(patch(target, new=AsyncMock(return_value=None)))

        analyzer = SecurityAnalyzer()
        vulns = await analyzer.scan(server)

    assert any(v.id == "MCP-CORS-001" for v in vulns)
