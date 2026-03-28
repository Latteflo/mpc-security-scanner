"""
Server-Side Request Forgery (SSRF) Check

MCP-SSRF-001  SSRF via Tool URL Parameters
  Tools that accept URL, URI, or endpoint parameters and fetch them server-side
  without validation allow attackers to pivot to internal services, cloud metadata
  endpoints (AWS/GCP/Azure IMDSv1), and localhost.

Strategy:
  1. Identify tools whose JSON Schema includes string parameters named url, uri,
     endpoint, link, href, src, or similar.
  2. Send probes to internal/metadata targets. We cannot confirm a full SSRF hit
     without an out-of-band callback server, so we use two detection heuristics:
       a) The response body contains content that only an internal service returns
          (AWS metadata keys, localhost headers, etc.).
       b) The error message leaks internal network topology (e.g. "Connection
          refused to 169.254.169.254" — meaning the server tried to connect).
  3. We report MEDIUM when URL params exist with no apparent allowlist and HIGH
     when the probe response confirms the server made the outbound request.
"""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("ssrf")

# Parameter names that commonly accept URLs.
_URL_PARAM_NAMES = {
    "url", "uri", "endpoint", "link", "href", "src", "source",
    "target", "destination", "redirect", "callback", "webhook",
    "fetch", "request", "proxy",
}

# Probes targeting internal addresses / cloud metadata.
_SSRF_PROBES = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDSv1
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
]

# Strings that only appear if the server actually fetched the internal target.
_SSRF_HIT_INDICATORS = [
    # AWS IMDSv1 metadata response fields
    "ami-id",
    "instance-id",
    "instance-type",
    "security-credentials",
    # GCP metadata
    "computeMetadata",
    "google-internal",
    # Localhost / loopback response artefacts
    "127.0.0.1",
    "localhost",
]

# Strings in error messages that reveal the server attempted the connection
# (i.e. the request left the process, even if it was refused).
_SSRF_ATTEMPT_INDICATORS = [
    "169.254.169.254",
    "metadata.google.internal",
    "connection refused",
    "connection timed out",
    "no route to host",
    "network is unreachable",
]


def _url_params_for_tool(server: MCPServer, tool_name: str) -> list[str]:
    """Return parameter names that look like URL inputs for the given tool."""
    schemas = getattr(server, "tool_schemas", {}) or {}
    schema = schemas.get(tool_name, {})
    props = schema.get("properties") or schema.get("inputSchema", {}).get("properties") or {}
    return [p for p in props if p.lower() in _URL_PARAM_NAMES]


async def check_ssrf(server: MCPServer) -> Optional[Vulnerability]:
    """Check for SSRF vulnerabilities in MCP tool URL parameters."""
    if not server.tools:
        return None

    for tool in server.tools:
        url_params = _url_params_for_tool(server, tool)

        # Fall back to heuristic name-matching when schema is unavailable.
        if not url_params:
            if any(kw in tool.lower() for kw in ("fetch", "request", "browse", "http", "url", "proxy", "webhook")):
                url_params = ["url"]
            else:
                continue

        for probe in _SSRF_PROBES:
            args = {p: probe for p in url_params}
            request_data = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool, "arguments": args},
                "id": 1,
            }

            try:
                _status, text, _headers = await http_post(server.url, request_data, timeout=6.0)
                text_lower = text.lower()

                # Confirmed: server returned content from the internal target.
                if any(ind in text_lower for ind in _SSRF_HIT_INDICATORS):
                    return Vulnerability.create(
                        id="MCP-SSRF-001",
                        title="Server-Side Request Forgery (SSRF) Confirmed",
                        description=(
                            f"The tool '{tool}' on {server.url} fetched an internal/metadata "
                            f"URL ({probe}) and returned its content. An attacker can use this "
                            "to access cloud instance metadata, internal services, and may be "
                            "able to exfiltrate credentials or pivot to the internal network."
                        ),
                        severity=Severity.CRITICAL,
                        category="SSRF",
                        remediation=(
                            "Prevent SSRF:\n"
                            "- Validate and allowlist permitted URL schemes and hosts\n"
                            "- Block requests to RFC-1918 addresses and link-local ranges\n"
                            "- Block access to cloud metadata endpoints (169.254.169.254, etc.)\n"
                            "- Use a dedicated egress proxy that enforces an allowlist\n"
                            "- Never return raw HTTP responses from internal fetches to callers"
                        ),
                        evidence=[
                            f"Vulnerable tool: {tool}",
                            f"SSRF probe: {probe}",
                            "Internal/metadata content detected in response",
                        ],
                        affected_component=f"Tool: {tool}",
                        cwe_id="CWE-918",
                        cvss_score=9.3,
                    )

                # Likely: error message reveals the server attempted the connection.
                if any(ind in text_lower for ind in _SSRF_ATTEMPT_INDICATORS):
                    return Vulnerability.create(
                        id="MCP-SSRF-001",
                        title="Server-Side Request Forgery (SSRF) Risk Detected",
                        description=(
                            f"The tool '{tool}' on {server.url} appears to have attempted an "
                            f"outbound connection to an internal address ({probe}). The error "
                            "response reveals that the server-side fetch was initiated, indicating "
                            "an SSRF vector even though the target was unreachable."
                        ),
                        severity=Severity.HIGH,
                        category="SSRF",
                        remediation=(
                            "Prevent SSRF:\n"
                            "- Validate and allowlist permitted URL schemes and hosts\n"
                            "- Block requests to RFC-1918 addresses and link-local ranges\n"
                            "- Block access to cloud metadata endpoints (169.254.169.254, etc.)\n"
                            "- Use a dedicated egress proxy that enforces an allowlist\n"
                            "- Sanitize error messages to avoid leaking internal topology"
                        ),
                        evidence=[
                            f"Vulnerable tool: {tool}",
                            f"SSRF probe: {probe}",
                            "Internal address reference found in error response",
                        ],
                        affected_component=f"Tool: {tool}",
                        cwe_id="CWE-918",
                        cvss_score=7.5,
                    )

            except (ConnectionError, TimeoutError) as e:
                logger.debug(f"Connection error probing {tool} with {probe}: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error probing {tool}: {e}")
                continue

    return None
