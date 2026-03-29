"""
MCP Resource URI Traversal Check

MCP-RES-001  Path Traversal via MCP Resource URIs

  MCP servers expose resources at URIs (e.g. file:///app/data/report.json,
  config://settings). If the server reads these URIs without canonicalising
  and validating the path, an attacker can:

    • Traverse to arbitrary files: file:///../../../etc/passwd
    • Access internal URIs not intended to be resources
    • Chain with SSRF if the server fetches http:// resource URIs

  Detection strategy:
    1. For each discovered resource URI, synthesise traversal variants by
       appending /../../../etc/passwd, replacing path components, or swapping
       the scheme to file://.
    2. Call resources/read with each payload URI.
    3. Flag if the response body contains content that only appears in real
       system files (same indicators used by the path traversal injection check).
    4. Also test with crafted URIs that don't derive from discovered resources,
       to catch servers that accept arbitrary resource URIs.
"""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("resource_traversal")

# System-file content indicators (same as injection check)
_SYSTEM_FILE_INDICATORS = [
    "root:x:",
    "/bin/bash",
    "/bin/sh",
    "daemon:",
    "nobody:",
    "[boot loader]",   # Windows boot.ini
    "for 16-bit app support",  # Windows system.ini
]

# Traversal payloads for file-scheme URIs
_TRAVERSAL_SUFFIXES = [
    "/../../../etc/passwd",
    "/../../etc/passwd",
    "/../etc/passwd",
    "%2F..%2F..%2Fetc%2Fpasswd",
    "/..%2F..%2Fetc%2Fpasswd",
]

# Standalone payloads to try even without discovered resources
_STANDALONE_URIS = [
    "file:///etc/passwd",
    "file:///../../../etc/passwd",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    "file://localhost/etc/passwd",
]


def _traversal_variants(uri: str) -> list[str]:
    """Generate path traversal variants from an existing resource URI."""
    variants = []
    # Append traversal to the URI path
    base = uri.rstrip("/")
    for suffix in _TRAVERSAL_SUFFIXES:
        variants.append(base + suffix)
    # Replace the last path segment entirely
    if "/" in base:
        parent = base.rsplit("/", 1)[0]
        variants.append(parent + "/../../../etc/passwd")
    return variants


async def _read_resource(server_url: str, uri: str) -> str | None:
    """Call resources/read with the given URI; return body text or None on error."""
    request = {
        "jsonrpc": "2.0",
        "method": "resources/read",
        "params": {"uri": uri},
        "id": 1,
    }
    try:
        _status, body, _headers = await http_post(server_url, request, timeout=5.0)
        return body
    except Exception as e:
        logger.debug(f"resources/read error for {uri!r}: {e}")
        return None


def _has_system_content(text: str) -> bool:
    return any(ind in text for ind in _SYSTEM_FILE_INDICATORS)


async def check_resource_traversal(server: MCPServer) -> Optional[Vulnerability]:
    """Check for path traversal vulnerabilities via MCP resource URIs."""
    hitting_uri: str | None = None

    # Test traversal variants of discovered resources
    for resource_uri in server.resources:
        for variant in _traversal_variants(resource_uri):
            body = await _read_resource(server.url, variant)
            if body and _has_system_content(body):
                hitting_uri = variant
                break
        if hitting_uri:
            break

    # Test standalone payloads regardless of discovered resources
    if not hitting_uri:
        for uri in _STANDALONE_URIS:
            body = await _read_resource(server.url, uri)
            if body and _has_system_content(body):
                hitting_uri = uri
                break

    if not hitting_uri:
        return None

    return Vulnerability.create(
        id="MCP-RES-001",
        title="Path Traversal via MCP Resource URI",
        description=(
            f"The MCP server at {server.url} is vulnerable to path traversal through "
            "the resources/read method. A crafted resource URI allowed reading an "
            "arbitrary file outside the intended resource scope, exposing sensitive "
            "system files to any caller."
        ),
        severity=Severity.CRITICAL,
        category="Injection",
        remediation=(
            "Fix resource URI validation:\n"
            "- Resolve all file:// URIs to their canonical absolute path before reading\n"
            "- Reject any URI whose canonical path falls outside the allowed resource root\n"
            "- Maintain an explicit allowlist of permitted URI schemes (e.g. only config://)\n"
            "- Never pass resource URIs directly to filesystem or HTTP fetch calls\n"
            "- Apply the same path validation used for file parameter injection (CWE-22)"
        ),
        evidence=[
            f"Server: {server.url}",
            f"Traversal URI: {hitting_uri}",
            "System file content detected in resources/read response",
        ],
        affected_component="resources/read",
        cwe_id="CWE-22",
        cvss_score=9.1,
    )
