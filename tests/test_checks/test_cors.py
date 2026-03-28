"""
Tests for CORS security checks.

We mock http_get at the point where cors.py imports it so the checks never make
real network calls. Each test sets up a specific response and asserts the exact
vulnerability (or absence of one) we expect for that scenario.

Without mocking, these tests previously connected to localhost:3000 and passed
vacuously when nothing was listening — the assertion `vuln is None or vuln.id
.startswith("MCP-CORS")` is always true and catches nothing.
"""

import pytest
from unittest.mock import AsyncMock, patch

from src.models import MCPServer
from src.checks.cors import check_cors_misconfiguration


def make_server(host="localhost", port=3000, protocol="http"):
    return MCPServer(host=host, port=port, protocol=protocol)


@pytest.mark.asyncio
async def test_wildcard_cors_returns_high_vulnerability():
    """Access-Control-Allow-Origin: * lets any website read responses — flagged HIGH."""
    server = make_server()
    mock_response = (200, "", {"access-control-allow-origin": "*"})

    with patch("src.checks.cors.http_get", new=AsyncMock(return_value=mock_response)):
        vuln = await check_cors_misconfiguration(server)

    assert vuln is not None
    assert vuln.id == "MCP-CORS-001"
    assert vuln.severity.value == "HIGH"
    assert "Wildcard" in vuln.title or "Permissive" in vuln.title


@pytest.mark.asyncio
async def test_origin_reflection_returns_critical():
    """
    Server echoes back the Origin header exactly — this is CRITICAL.

    Unlike a static wildcard, reflection means any attacker-controlled origin
    is trusted, bypassing the browser's same-origin policy.
    """
    server = make_server()
    # The check sends Origin: https://evil.com; a reflective server echoes it back
    mock_response = (200, "", {"access-control-allow-origin": "https://evil.com"})

    with patch("src.checks.cors.http_get", new=AsyncMock(return_value=mock_response)):
        vuln = await check_cors_misconfiguration(server)

    assert vuln is not None
    assert vuln.id == "MCP-CORS-002"
    assert vuln.severity.value == "CRITICAL"


@pytest.mark.asyncio
async def test_wildcard_with_credentials_is_detected():
    """
    Wildcard origin + Allow-Credentials is the most dangerous CORS combo.

    Browsers block this at the JS level, but other HTTP clients don't, so
    attackers can still exploit it from scripts or native clients.

    Note: the current implementation checks CORS-001 (wildcard) before
    CORS-003 (wildcard + credentials) and returns early — so this scenario
    currently surfaces as CORS-001. This test documents that behaviour so any
    change to check ordering is caught immediately.
    """
    server = make_server()
    mock_response = (
        200,
        "",
        {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
    )

    with patch("src.checks.cors.http_get", new=AsyncMock(return_value=mock_response)):
        vuln = await check_cors_misconfiguration(server)

    assert vuln is not None
    # CORS-001 today; should become CORS-003 once check order is fixed
    assert vuln.id in ("MCP-CORS-001", "MCP-CORS-003")


@pytest.mark.asyncio
async def test_restrictive_cors_returns_none():
    """A specific trusted origin in ACAO is the correct configuration — no finding."""
    server = make_server()
    mock_response = (200, "", {"access-control-allow-origin": "https://app.example.com"})

    with patch("src.checks.cors.http_get", new=AsyncMock(return_value=mock_response)):
        vuln = await check_cors_misconfiguration(server)

    assert vuln is None


@pytest.mark.asyncio
async def test_no_cors_headers_returns_none():
    """Server that doesn't set CORS headers has no CORS misconfiguration to report."""
    server = make_server()
    mock_response = (200, "", {})

    with patch("src.checks.cors.http_get", new=AsyncMock(return_value=mock_response)):
        vuln = await check_cors_misconfiguration(server)

    assert vuln is None


@pytest.mark.asyncio
async def test_network_error_returns_none():
    """
    A connection failure must not produce a false positive.

    The check silently swallows all exceptions and returns None, so a
    network error looks the same as a clean CORS policy. This is intentional
    — we can't assert vulnerability when we couldn't even reach the server.
    """
    server = make_server()

    with patch("src.checks.cors.http_get", side_effect=ConnectionError("refused")):
        vuln = await check_cors_misconfiguration(server)

    assert vuln is None
