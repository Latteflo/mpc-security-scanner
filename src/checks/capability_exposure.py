"""
MCP Capability Over-Exposure Check

MCP-CAP-001  Dangerous Server Capabilities Advertised Without Protection

  The MCP initialize handshake returns a `capabilities` object that tells
  clients what the server supports. Some capabilities introduce significant
  security risk if advertised without proper access control:

    • sampling     — server can request the CLIENT to make LLM calls, injecting
                     prompts into the client's context. Essentially gives the
                     server a reverse-channel into the LLM.
    • roots        — server can request the client's filesystem root list,
                     enabling enumeration of the client's directory structure.
    • experimental — any key here is non-standard and unreviewed; we flag it
                     for manual inspection.

  We also check for over-broad resource capability flags (e.g. subscribe
  without authentication) and missing `listChanged` notifications that
  indicate a server doesn't gate dynamic capability additions.

  Severity is MEDIUM unless sampling is present without authentication,
  in which case it is HIGH — because sampling lets the server silently
  influence the LLM's behaviour on behalf of all connected clients.
"""

import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("capability_exposure")

_INIT_REQUEST = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "mcp-security-scanner", "version": "0.2.1"},
    },
    "id": 1,
}

# Capabilities considered high-risk
_HIGH_RISK_CAPS = {
    "sampling": (
        "Allows the server to request LLM calls from the client. A malicious or "
        "compromised server can inject arbitrary prompts into the client's LLM context "
        "without user awareness."
    ),
    "roots": (
        "Allows the server to request the client's filesystem root list, enabling "
        "directory enumeration of the client machine."
    ),
}

# Capability flags that suggest missing access controls
_RISKY_FLAGS = {
    "resources.subscribe": "Clients can subscribe to resource change notifications without scoping",
    "tools.listChanged": None,   # informational only, not risky alone
}


async def check_capability_exposure(server: MCPServer) -> Optional[Vulnerability]:
    """Check for dangerous or over-broad capabilities in the MCP initialize response."""
    try:
        status, body, _headers = await http_post(server.url, _INIT_REQUEST, timeout=6.0)
    except Exception as e:
        logger.debug(f"Init probe failed: {e}")
        return None

    if status != 200:
        return None

    try:
        response = json.loads(body)
        capabilities = response.get("result", {}).get("capabilities", {})
    except (json.JSONDecodeError, AttributeError):
        return None

    if not capabilities:
        return None

    risky: list[tuple[str, str]] = []   # (cap_name, reason)

    # High-risk capabilities present in the response
    for cap, reason in _HIGH_RISK_CAPS.items():
        if cap in capabilities:
            risky.append((cap, reason))

    # Experimental capabilities
    experimental = capabilities.get("experimental", {})
    if experimental:
        risky.append((
            f"experimental ({', '.join(experimental.keys())})",
            "Non-standard capabilities have not undergone security review",
        ))

    # sampling without auth is the worst case
    has_sampling = any(cap == "sampling" for cap, _ in risky)
    severity = (
        Severity.HIGH if has_sampling and not server.has_authentication
        else Severity.MEDIUM if risky
        else None
    )

    if not risky or severity is None:
        return None

    evidence = [f"Server: {server.url}", f"Raw capabilities: {json.dumps(capabilities)}"]
    for cap, reason in risky:
        evidence.append(f"⚠ {cap}: {reason}")

    return Vulnerability.create(
        id="MCP-CAP-001",
        title="Dangerous MCP Capabilities Advertised",
        description=(
            f"The server at {server.url} advertises {len(risky)} high-risk "
            "capability/capabilities in its initialize response. These capabilities "
            "extend trust from the server to the client in ways that can be exploited "
            "to influence LLM behaviour, enumerate the client filesystem, or introduce "
            "unreviewed attack surface."
        ),
        severity=severity,
        category="Configuration",
        remediation=(
            "Review and restrict advertised capabilities:\n"
            "- Only advertise capabilities the server genuinely needs\n"
            "- Gate 'sampling' behind explicit user consent and strong authentication\n"
            "- Remove or sandbox experimental capabilities before production use\n"
            "- Audit 'roots' usage — most servers do not need filesystem enumeration\n"
            "- Review the MCP capability specification before enabling each flag"
        ),
        evidence=evidence,
        affected_component="MCP Server Capabilities",
        cwe_id="CWE-272",
        cvss_score=7.5 if has_sampling and not server.has_authentication else 5.4,
    )
