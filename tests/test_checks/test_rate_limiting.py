"""
Tests for rate limiting checks.

We mock http_post to control exactly how many requests "succeed" vs are blocked.
This makes tests fast (no real 50-request loops) and deterministic.

Previously, these tests fired real HTTP requests at localhost:3000 and passed
vacuously when nothing was listening — the check silently returns None on
ConnectionError, so the assertion `vuln is None or vuln.id.startswith("MCP-RATE")`
was always true regardless of whether the logic worked.
"""

import pytest
from unittest.mock import AsyncMock, patch

from src.models import MCPServer
from src.checks.rate_limiting import check_rate_limiting


def make_server(host="localhost", port=3000, protocol="http"):
    return MCPServer(host=host, port=port, protocol=protocol)


@pytest.mark.asyncio
async def test_no_rate_limiting_detected():
    """
    All 50 probe requests succeed → server has no rate limiting → HIGH vulnerability.

    The threshold is >40 successful requests out of 50 (see check implementation).
    """
    server = make_server()
    # Every request returns 200 — the server never throttles us
    always_ok = AsyncMock(return_value=(200, '{"ok": true}', {}))

    with patch("src.checks.rate_limiting.http_post", new=always_ok):
        vuln = await check_rate_limiting(server)

    assert vuln is not None
    assert vuln.id == "MCP-RATE-001"
    assert vuln.severity.value == "HIGH"


@pytest.mark.asyncio
async def test_rate_limiting_present_returns_none():
    """
    Server blocks requests after a low threshold → rate limiting is functioning → no finding.

    We simulate a server that allows only 5 requests before returning 429.
    With fewer than 30 successful requests the check concludes rate limiting works.
    """
    server = make_server()
    call_count = 0

    async def rate_limited(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count > 5:
            return (429, '{"error": "too many requests"}', {})
        return (200, '{"ok": true}', {})

    with patch("src.checks.rate_limiting.http_post", new=rate_limited):
        vuln = await check_rate_limiting(server)

    # Fewer than 30 successful requests before being blocked → pass
    assert vuln is None


@pytest.mark.asyncio
async def test_weak_rate_limiting_detected():
    """
    Server allows 35 requests before throttling → weak rate limiting → MEDIUM finding.

    The threshold window: 30 ≤ successful < 40 with at least one 429 seen.
    """
    server = make_server()
    call_count = 0

    async def weak_limit(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count > 35:
            return (429, '{"error": "rate limit"}', {})
        return (200, '{"ok": true}', {})

    with patch("src.checks.rate_limiting.http_post", new=weak_limit):
        vuln = await check_rate_limiting(server)

    # 35 successes then throttled → weak, not absent
    assert vuln is not None
    assert vuln.id in ("MCP-RATE-001", "MCP-RATE-002")


@pytest.mark.asyncio
async def test_connection_error_returns_none():
    """
    Complete connection failure must not generate a false positive.

    If we can't reach the server at all, we have no evidence of missing rate
    limiting — failing safe to None is the correct behaviour.
    """
    server = make_server()

    with patch("src.checks.rate_limiting.http_post", side_effect=ConnectionError("refused")):
        vuln = await check_rate_limiting(server)

    assert vuln is None
