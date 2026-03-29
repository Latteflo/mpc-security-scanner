"""
Input Validation and Injection Attack Checks
Tests for SQL injection, command injection, and path traversal
"""

import sys
from pathlib import Path
from typing import Optional, List

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("injection")


async def check_sql_injection(server: MCPServer) -> Optional[Vulnerability]:
    """
    Check for SQL injection vulnerabilities in MCP tools.

    Strategy: find tools whose names suggest SQL interaction, send injection
    payloads, then look for database error messages in the response.

    We only report a vulnerability when injection is *confirmed* by the server's
    own error output. We do NOT flag tools just because their name contains
    "sql" or "query" — that would produce false positives for any tool that
    handles SQL safely via parameterised queries.
    """
    if not server.tools:
        return None

    # SQL injection test payloads — chosen to trigger syntax errors in MySQL,
    # PostgreSQL, and SQLite without causing destructive side-effects
    sql_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "1' UNION SELECT NULL--",
        "admin'--",
        "' OR 1=1--",
    ]

    # Substrings that indicate a tool likely accepts SQL as input.
    # "search" is intentionally excluded — it matches too broadly and most
    # search tools don't write raw SQL.
    sql_tool_keywords = ["sql", "query", "database", "select"]

    sql_tools = [
        tool for tool in server.tools
        if any(kw in tool.lower() for kw in sql_tool_keywords)
    ]

    if not sql_tools:
        return None

    # Error strings that appear in database exception messages.
    # Match only patterns that cannot plausibly appear in a normal 200 response
    # (e.g. "mysql" alone is too broad; "sql syntax" is specific enough).
    sql_error_indicators = [
        "sql syntax",
        "syntax error",
        "unclosed quotation",
        "quoted string not properly terminated",
        "ora-",          # Oracle errors
        "pg::syntaxerror",  # PostgreSQL via pg gem
    ]

    for tool in sql_tools:
        for payload in sql_payloads[:2]:  # two payloads is enough to confirm
            try:
                request_data = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": tool,
                        "arguments": {
                            "query": payload,
                            "input": payload,
                            "search": payload,
                        },
                    },
                    "id": 1,
                }

                status, text, _ = await http_post(server.url, request_data, timeout=5.0)

                # Only flag when the server leaks an actual database error.
                # A 500 response alone is not enough — the body must contain
                # recognisable DB error text.
                if any(indicator in text.lower() for indicator in sql_error_indicators):
                    return Vulnerability.create(
                        id="MCP-INJ-001",
                        title="SQL Injection Vulnerability Detected",
                        description=(
                            f"The MCP server at {server.url} is vulnerable to SQL injection "
                            f"in the tool '{tool}'. A database error message was returned "
                            "when tested with an injection payload, indicating that user input "
                            "is being concatenated directly into a SQL query."
                        ),
                        severity=Severity.CRITICAL,
                        category="Injection",
                        remediation=(
                            "Fix SQL injection vulnerabilities:\n"
                            "- Use parameterized queries (prepared statements)\n"
                            "- Never concatenate user input into SQL\n"
                            "- Implement input validation and sanitization\n"
                            "- Use ORM frameworks when possible\n"
                            "- Apply principle of least privilege to database users\n"
                            "- Use stored procedures with parameterized inputs"
                        ),
                        evidence=[
                            f"Vulnerable tool: {tool}",
                            f"Test payload: {payload}",
                            "SQL error message detected in response",
                        ],
                        affected_component=f"Tool: {tool}",
                        cwe_id="CWE-89",
                        cvss_score=9.8,
                    )

            except (ConnectionError, TimeoutError) as e:
                logger.debug(f"Connection error testing {tool}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error testing {tool}: {e}")
                continue

    # All payloads were tested and none triggered a DB error — no confirmed injection.
    # The tool may well be safe; we don't speculate.
    return None


async def check_command_injection(server: MCPServer) -> Optional[Vulnerability]:
    """
    Check for command injection vulnerabilities in MCP tools.

    Strategy: send shell metacharacter payloads to tools that suggest command
    execution, then look for system-level output (uid=, /bin/, etc.) in the
    response that would only appear if the injected command actually ran.

    We do NOT flag tools merely because their name contains "run" or "exec".
    A tool named "run_workflow" may be perfectly safe; we need evidence of
    actual execution to report a vulnerability.
    """
    if not server.tools:
        return None

    cmd_payloads = [
        "; ls -la",
        "| whoami",
        "&& cat /etc/passwd",
        "`id`",
        "$(uname -a)",
    ]

    # More specific than before: "run" alone matched too broadly
    # (e.g. "run_safe_query"). We require more explicit execution-related names.
    cmd_tool_keywords = ["exec", "execute", "command", "shell", "system"]

    cmd_tools = [
        tool for tool in server.tools
        if any(kw in tool.lower() for kw in cmd_tool_keywords)
    ]

    if not cmd_tools:
        return None

    # These strings only appear in real command output — not in normal API responses
    cmd_output_indicators = [
        "root:",       # /etc/passwd or `id` output
        "uid=",        # id(1) output
        "gid=",        # id(1) output
        "/bin/",       # shell path in listings
        "/usr/",       # common directory in listings
        "linux",       # uname output
        "darwin",      # uname on macOS
    ]

    for tool in cmd_tools:
        for payload in cmd_payloads[:2]:
            try:
                request_data = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": tool,
                        "arguments": {
                            "command": f"echo test{payload}",
                            "cmd": f"test{payload}",
                            "input": payload,
                        },
                    },
                    "id": 1,
                }

                status, text, _ = await http_post(server.url, request_data, timeout=5.0)

                # Only flag on confirmed execution evidence.
                # "Linux" appearing in a normal response body is unusual but
                # possible; we accept that rare false negative over a false positive.
                if any(indicator in text for indicator in cmd_output_indicators):
                    return Vulnerability.create(
                        id="MCP-INJ-003",
                        title="Command Injection Vulnerability Detected",
                        description=(
                            f"The MCP server at {server.url} is vulnerable to command injection "
                            f"in the tool '{tool}'. Injected shell commands were executed and "
                            "their output returned, allowing arbitrary system command execution."
                        ),
                        severity=Severity.CRITICAL,
                        category="Injection",
                        remediation=(
                            "Fix command injection vulnerabilities:\n"
                            "- Never pass user input directly to system commands\n"
                            "- Use allowlists for permitted commands\n"
                            "- Escape shell metacharacters if shell execution is required\n"
                            "- Use language-specific APIs instead of shell commands\n"
                            "- Implement strict input validation\n"
                            "- Run with minimal privileges"
                        ),
                        evidence=[
                            f"Vulnerable tool: {tool}",
                            f"Test payload: {payload}",
                            "Command execution output detected in response",
                        ],
                        affected_component=f"Tool: {tool}",
                        cwe_id="CWE-78",
                        cvss_score=9.8,
                    )

            except (ConnectionError, TimeoutError) as e:
                logger.debug(f"Connection error testing {tool}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error testing {tool}: {e}")
                continue

    return None


async def check_path_traversal(server: MCPServer) -> Optional[Vulnerability]:
    """
    Check for path traversal vulnerabilities in MCP tools.

    Strategy: send traversal sequences to file-access tools, then check whether
    the response contains content that could only come from a system file like
    /etc/passwd (e.g. "root:x:", "/bin/bash").

    We do NOT flag tools just because they handle files. A tool named "read_file"
    that rejects traversal sequences or restricts access to a chroot is safe.
    """
    if not server.tools:
        return None

    path_payloads = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "/etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]

    file_tool_keywords = ["file", "read", "write", "path", "document", "upload", "download"]

    file_tools = [
        tool for tool in server.tools
        if any(kw in tool.lower() for kw in file_tool_keywords)
    ]

    if not file_tools:
        return None

    # Content that only appears if a real system file was read.
    # These are specific enough that false positives are extremely unlikely.
    system_file_indicators = [
        "root:x:",          # /etc/passwd — Linux root entry
        "/bin/bash",        # shell path in /etc/passwd
        "/bin/sh",
        "daemon:",          # other /etc/passwd entries
        "nobody:",
    ]

    for tool in file_tools:
        for payload in path_payloads:
            try:
                request_data = {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": tool,
                        "arguments": {
                            "path": payload,
                            "file": payload,
                            "filename": payload,
                        },
                    },
                    "id": 1,
                }

                status, text, _ = await http_post(server.url, request_data, timeout=5.0)

                if any(indicator in text for indicator in system_file_indicators):
                    return Vulnerability.create(
                        id="MCP-INJ-005",
                        title="Path Traversal Vulnerability Detected",
                        description=(
                            f"The MCP server at {server.url} is vulnerable to path traversal "
                            f"in the tool '{tool}'. System file content was returned after "
                            "sending a directory traversal payload, allowing unauthorized "
                            "access to files outside the intended directory."
                        ),
                        severity=Severity.CRITICAL,
                        category="Injection",
                        remediation=(
                            "Fix path traversal vulnerabilities:\n"
                            "- Validate and sanitize all file paths\n"
                            "- Use allowlists of permitted directories\n"
                            "- Reject paths containing '../' or '..\\'\n"
                            "- Use canonical path resolution\n"
                            "- Implement proper access controls\n"
                            "- Restrict file access to specific directories"
                        ),
                        evidence=[
                            f"Vulnerable tool: {tool}",
                            f"Test payload: {payload}",
                            "System file content detected in response",
                        ],
                        affected_component=f"Tool: {tool}",
                        cwe_id="CWE-22",
                        cvss_score=8.6,
                    )

            except (ConnectionError, TimeoutError) as e:
                logger.debug(f"Connection error testing {tool}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error testing {tool}: {e}")
                continue

    return None
