"""
MCP Protocol Version Enforcement Check

MCP-PROTO-001  Weak / Arbitrary Protocol Version Accepted

  The MCP initialize handshake includes a `protocolVersion` field that the
  server should validate. A server that accepts any version string — including
  clearly invalid ones — is not enforcing the protocol contract.

  Practical impact:
    • Future protocol versions may add security-relevant features (capability
      negotiation, required auth fields). A server that ignores version checks
      will silently skip those features when an old client connects.
    • Accepting bogus versions indicates the server's initialize handler does
      minimal validation, which is a broader code-quality / security signal.

  We test with:
    1. A clearly bogus string ("0.0.0")
    2. An ancient placeholder version ("1970-01-01")
    3. A non-version garbage value ("../../etc/passwd" — also a light injection probe)

  We report a finding only when the server returns a successful result (not an
  error) for at least one bogus version, indicating it doesn't validate the field.
"""

import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("protocol_version")

_BOGUS_VERSIONS = [
    "0.0.0",
    "1970-01-01",
    "9999-99-99",
    "../../etc/passwd",
    "",
    "invalid-version",
]


async def check_protocol_version(server: MCPServer) -> Optional[Vulnerability]:
    """Check that the server rejects unknown / bogus protocol versions."""
    accepted: list[str] = []

    for version in _BOGUS_VERSIONS:
        request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "mcp-security-scanner", "version": "0.2.1"},
            },
            "id": 1,
        }
        try:
            status, body, _headers = await http_post(server.url, request, timeout=5.0)
            if status != 200:
                continue

            response = json.loads(body)
            # A proper rejection comes back as a JSON-RPC error object.
            # A result object means the server accepted it.
            if "result" in response and "capabilities" in response.get("result", {}):
                accepted.append(repr(version))

        except (json.JSONDecodeError, ConnectionError, TimeoutError) as e:
            logger.debug(f"Version probe error ({version!r}): {e}")
            continue
        except Exception as e:
            logger.debug(f"Unexpected error ({version!r}): {e}")
            continue

    if not accepted:
        return None

    return Vulnerability.create(
        id="MCP-PROTO-001",
        title="MCP Protocol Version Not Enforced",
        description=(
            f"The server at {server.url} accepted {len(accepted)} invalid protocol "
            "version(s) during the initialize handshake. A well-implemented server "
            "should reject version strings it does not recognise and return a JSON-RPC "
            "error. Accepting arbitrary versions indicates missing input validation in "
            "the handshake handler."
        ),
        severity=Severity.LOW,
        category="Configuration",
        remediation=(
            "Enforce protocol version validation:\n"
            "- Maintain an explicit allowlist of supported protocol version strings\n"
            "- Return a JSON-RPC error (-32600 Invalid Request) for unknown versions\n"
            "- Log and alert on version negotiation failures to detect scanning\n"
            "- Follow the MCP specification on version negotiation behaviour"
        ),
        evidence=[
            f"Server: {server.url}",
            f"Bogus versions accepted: {', '.join(accepted)}",
        ],
        affected_component="MCP Handshake",
        cwe_id="CWE-20",
        cvss_score=3.7,
    )
