"""
Tool Result Size / Unbounded Output Check

MCP-DOS-001  Unbounded Tool Output (Context Stuffing / Resource Exhaustion)

  MCP tools that return arbitrarily large responses create two distinct risks:

    1. Resource exhaustion — a single tool call can consume all available
       server memory or fill the network buffer, degrading or crashing the
       server (DoS).

    2. Context stuffing — when a tool floods the LLM context window with
       large outputs, legitimate instructions get pushed out and the model's
       reasoning degrades. Attackers can exploit this to hide malicious
       content at the end of an oversized result.

  Strategy:
    - Call each tool with empty / minimal arguments and measure the response
      body size.
    - Flag if any single response exceeds the threshold (default 512 KB).
    - Also check whether the tools/list result itself is suspiciously large
      (many tools is itself a form of schema flooding).
    - We do NOT send payloads designed to amplify responses — only empty
      argument calls that any legitimate client would make.
"""

import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("tool_dos")

# Response body size that warrants a finding
_LARGE_RESPONSE_BYTES = 512 * 1024       # 512 KB
_VERY_LARGE_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB

# Many tools exposed at once is a schema flooding risk
_EXCESSIVE_TOOL_COUNT = 50


async def check_tool_dos(server: MCPServer) -> Optional[Vulnerability]:
    """Check for unbounded tool output and excessive tool count."""
    if not server.tools:
        return None

    findings: list[str] = []
    worst_size = 0
    worst_tool = ""

    # Check tool count
    if len(server.tools) > _EXCESSIVE_TOOL_COUNT:
        findings.append(
            f"{len(server.tools)} tools exposed — excessive tool schemas can flood the "
            "LLM context window"
        )

    # Probe each tool with empty arguments
    for tool in server.tools:
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool, "arguments": {}},
            "id": 1,
        }
        try:
            _status, body, _headers = await http_post(server.url, request, timeout=8.0)
            size = len(body.encode("utf-8", errors="replace"))

            if size > worst_size:
                worst_size = size
                worst_tool = tool

            if size >= _LARGE_RESPONSE_BYTES:
                kb = size // 1024
                findings.append(f"Tool '{tool}' returned {kb} KB in a single call")

        except (ConnectionError, TimeoutError) as e:
            logger.debug(f"Error probing tool {tool}: {e}")
            continue
        except Exception as e:
            logger.debug(f"Unexpected error probing tool {tool}: {e}")
            continue

    if not findings:
        return None

    severity = (
        Severity.HIGH if worst_size >= _VERY_LARGE_RESPONSE_BYTES
        else Severity.MEDIUM
    )

    return Vulnerability.create(
        id="MCP-DOS-001",
        title="Unbounded Tool Output Detected",
        description=(
            f"One or more tools on {server.url} return responses without enforcing "
            "size limits. This enables context stuffing attacks (flooding the LLM "
            "context to displace legitimate instructions) and potential server-side "
            "resource exhaustion from a single tool call."
        ),
        severity=severity,
        category="Availability",
        remediation=(
            "Enforce output size limits:\n"
            "- Cap individual tool responses (e.g. 64 KB for text, configurable)\n"
            "- Implement pagination for tools that return collections\n"
            "- Truncate and summarise large results before returning to the client\n"
            "- Set a total context budget per session and reject calls that would "
            "exceed it\n"
            "- Limit the number of tools exposed to what is genuinely needed"
        ),
        evidence=[f"Server: {server.url}"] + findings,
        affected_component="Tool Responses",
        cwe_id="CWE-400",
        cvss_score=7.5 if severity == Severity.HIGH else 5.3,
    )
