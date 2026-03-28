"""
Tests for injection attack checks.

All HTTP calls are mocked so tests are fast, deterministic, and don't need a
running server.

The central invariant being tested: a vulnerability is ONLY returned when
injection is *confirmed* by the server's own response content — not merely
because a tool name matches a keyword pattern.

Before the fix, all three checks had a fallback path that returned a MEDIUM/HIGH
vulnerability whenever a matching tool existed, regardless of whether injection
actually worked. This made a tool named "query_logs" or "run_workflow" always
get flagged, even if the implementation was perfectly safe.
"""

import pytest
from unittest.mock import AsyncMock, patch

from src.models import MCPServer
from src.checks.injection import (
    check_sql_injection,
    check_command_injection,
    check_path_traversal,
)


def make_server(tools=None):
    return MCPServer(host="localhost", port=3000, protocol="http", tools=tools or [])


# ──────────────────────────────────────────────────────────────────────────────
# SQL Injection
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sql_injection_confirmed_by_error_message():
    """Server leaks a SQL syntax error → CRITICAL confirmed injection."""
    server = make_server(tools=["query_data"])
    # Real-world MySQL error message in the response body
    mock_response = (500, "you have an error in your sql syntax near '1'='1'", {})

    with patch("src.checks.injection.http_post", new=AsyncMock(return_value=mock_response)):
        vuln = await check_sql_injection(server)

    assert vuln is not None
    assert vuln.id == "MCP-INJ-001"
    assert vuln.severity.value == "CRITICAL"
    # Evidence should record the specific tool and payload that triggered it
    assert any("query_data" in e for e in vuln.evidence)


@pytest.mark.asyncio
async def test_sql_tool_with_clean_response_returns_none():
    """
    Tool whose name matches 'query' but handles input safely → no finding.

    This is the key false-positive scenario the fix addresses. The old code
    returned MCP-INJ-002 (MEDIUM) here purely based on the tool name.
    """
    server = make_server(tools=["query_data"])
    # Server returns a normal, clean response — no SQL error in sight
    mock_response = (200, '{"results": []}', {})

    with patch("src.checks.injection.http_post", new=AsyncMock(return_value=mock_response)):
        vuln = await check_sql_injection(server)

    assert vuln is None


@pytest.mark.asyncio
async def test_sql_no_matching_tools_skips_http():
    """
    Tools with no SQL-pattern names means we never make an HTTP request.

    This verifies we don't send unsolicited probe requests to tools that
    have nothing to do with database access.
    """
    server = make_server(tools=["list_users", "get_profile"])

    with patch("src.checks.injection.http_post", new=AsyncMock()) as mock_post:
        vuln = await check_sql_injection(server)

    assert vuln is None
    mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_sql_no_tools_returns_none():
    """Server with no tools exposed → nothing to test, nothing to flag."""
    vuln = await check_sql_injection(make_server(tools=[]))
    assert vuln is None


@pytest.mark.asyncio
async def test_sql_connection_error_returns_none():
    """
    Network failure during testing must not create a false positive.

    If the connection is refused, the check logs the error and moves on.
    We can't assert vulnerability when we couldn't reach the tool.
    """
    server = make_server(tools=["query_data"])

    with patch("src.checks.injection.http_post", side_effect=ConnectionError("refused")):
        vuln = await check_sql_injection(server)

    assert vuln is None


# ──────────────────────────────────────────────────────────────────────────────
# Command Injection
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_command_injection_confirmed_by_uid_output():
    """Server returns `id` command output (uid=...) → CRITICAL confirmed RCE."""
    server = make_server(tools=["execute_task"])
    # The `id` command ran and its output leaked back in the response
    mock_response = (200, "uid=0(root) gid=0(root) groups=0(root)", {})

    with patch("src.checks.injection.http_post", new=AsyncMock(return_value=mock_response)):
        vuln = await check_command_injection(server)

    assert vuln is not None
    assert vuln.id == "MCP-INJ-003"
    assert vuln.severity.value == "CRITICAL"


@pytest.mark.asyncio
async def test_command_tool_with_clean_response_returns_none():
    """
    Tool whose name matches 'execute' but sanitises input → no finding.

    The old code returned MCP-INJ-004 (HIGH) for any tool matching 'exec',
    'run', 'shell', etc., regardless of the actual response.
    """
    server = make_server(tools=["execute_task"])
    mock_response = (200, '{"status": "ok", "output": "task completed"}', {})

    with patch("src.checks.injection.http_post", new=AsyncMock(return_value=mock_response)):
        vuln = await check_command_injection(server)

    assert vuln is None


@pytest.mark.asyncio
async def test_command_no_matching_tools_skips_http():
    """'run' as a substring must not match tools like 'run_report' by default."""
    # Note: 'run' was removed from the keyword list because it matched too broadly.
    # 'execute', 'exec', 'command', 'shell', 'system' are retained.
    server = make_server(tools=["list_files", "read_config"])

    with patch("src.checks.injection.http_post", new=AsyncMock()) as mock_post:
        vuln = await check_command_injection(server)

    assert vuln is None
    mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_command_no_tools_returns_none():
    vuln = await check_command_injection(make_server(tools=[]))
    assert vuln is None


# ──────────────────────────────────────────────────────────────────────────────
# Path Traversal
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_path_traversal_confirmed_by_passwd_content():
    """Server leaks /etc/passwd content → CRITICAL confirmed traversal."""
    server = make_server(tools=["read_file"])
    # Classic /etc/passwd content — root entry format is extremely specific
    mock_response = (
        200,
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        {},
    )

    with patch("src.checks.injection.http_post", new=AsyncMock(return_value=mock_response)):
        vuln = await check_path_traversal(server)

    assert vuln is not None
    assert vuln.id == "MCP-INJ-005"
    assert vuln.severity.value == "CRITICAL"


@pytest.mark.asyncio
async def test_file_tool_access_denied_returns_none():
    """
    File tool that blocks traversal attempts → no finding.

    The old code returned MCP-INJ-006 (MEDIUM) for any tool matching 'read',
    'file', 'write', etc., even when the server correctly rejected the request.
    """
    server = make_server(tools=["read_file"])
    # Server enforces access control and returns 403
    mock_response = (403, '{"error": "access denied: path outside allowed directory"}', {})

    with patch("src.checks.injection.http_post", new=AsyncMock(return_value=mock_response)):
        vuln = await check_path_traversal(server)

    assert vuln is None


@pytest.mark.asyncio
async def test_path_no_matching_tools_skips_http():
    """Tools with no file-access pattern names are not probed."""
    server = make_server(tools=["get_status", "list_users"])

    with patch("src.checks.injection.http_post", new=AsyncMock()) as mock_post:
        vuln = await check_path_traversal(server)

    assert vuln is None
    mock_post.assert_not_called()


@pytest.mark.asyncio
async def test_path_no_tools_returns_none():
    vuln = await check_path_traversal(make_server(tools=[]))
    assert vuln is None
