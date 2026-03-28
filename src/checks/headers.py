"""
Security Headers Check

MCP-HDR-001  Missing HTTP Security Headers
  HTTP security headers are a low-cost, high-signal defensive layer. Their
  absence doesn't indicate a direct vulnerability, but it leaves open browser-
  level attack vectors (clickjacking, MIME-sniffing, cross-origin data theft)
  that are trivially prevented.

  We check for the headers most relevant to an API/dashboard surface:
    - Strict-Transport-Security (HSTS)       — force HTTPS, prevent downgrade
    - X-Content-Type-Options: nosniff        — prevent MIME-type sniffing
    - X-Frame-Options / frame-ancestors CSP  — clickjacking protection
    - Content-Security-Policy               — XSS / injection mitigation
    - Referrer-Policy                        — limit referrer leakage
    - Permissions-Policy                     — restrict browser feature access

  Severity is LOW — missing headers are defence-in-depth gaps, not critical
  attack paths. We still report them because they appear on compliance checklists
  (PCI DSS 6.5, OWASP ASVS) and are trivially fixable.
"""

import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_get
from utils.logger import get_logger

logger = get_logger("headers")


# Header name → (description, why it matters)
_SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "strict-transport-security": (
        "Strict-Transport-Security (HSTS)",
        "Prevents protocol downgrade attacks and cookie hijacking over HTTP",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "Prevents browsers from MIME-sniffing responses away from the declared content-type",
    ),
    "x-frame-options": (
        "X-Frame-Options",
        "Protects against clickjacking by controlling whether the page can be embedded in a frame",
    ),
    "content-security-policy": (
        "Content-Security-Policy",
        "Mitigates XSS and data-injection attacks by restricting resource loading origins",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        "Controls how much referrer information is included with requests to limit data leakage",
    ),
    "permissions-policy": (
        "Permissions-Policy",
        "Restricts browser feature access (camera, microphone, geolocation) to reduce attack surface",
    ),
}

# HSTS only matters for HTTPS; skip it for plain HTTP targets.
_HTTPS_ONLY_HEADERS = {"strict-transport-security"}


async def check_security_headers(server: MCPServer) -> Optional[Vulnerability]:
    """Check for missing HTTP security headers on the server's base URL."""
    try:
        _status, _body, headers = await http_get(server.url, timeout=5.0, verify_ssl=False)
    except (ConnectionError, TimeoutError) as e:
        logger.debug(f"Could not fetch headers from {server.url}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error fetching headers from {server.url}: {e}")
        return None

    is_https = server.url.lower().startswith("https")
    headers_lower = {k.lower(): v for k, v in headers.items()}

    missing: list[str] = []
    for header, (label, _reason) in _SECURITY_HEADERS.items():
        if header in _HTTPS_ONLY_HEADERS and not is_https:
            continue
        # X-Frame-Options can be replaced by CSP frame-ancestors — don't double-flag.
        if header == "x-frame-options":
            csp = headers_lower.get("content-security-policy", "")
            if "frame-ancestors" in csp.lower():
                continue
        if header not in headers_lower:
            missing.append(label)

    if not missing:
        return None

    return Vulnerability.create(
        id="MCP-HDR-001",
        title="Missing HTTP Security Headers",
        description=(
            f"The server at {server.url} is missing {len(missing)} recommended "
            "HTTP security header(s). These headers provide browser-level defence "
            "against clickjacking, MIME-sniffing, and cross-origin attacks."
        ),
        severity=Severity.LOW,
        category="Configuration",
        remediation=(
            "Add the following headers to all HTTP responses:\n"
            + "\n".join(
                f"- {label}: {_SECURITY_HEADERS[h][1]}"
                for h, (label, _) in _SECURITY_HEADERS.items()
                if label in missing
            )
            + "\n\nFor most frameworks a single middleware call adds all of them."
        ),
        evidence=[
            f"Server: {server.url}",
            f"Missing headers: {', '.join(missing)}",
        ],
        affected_component="HTTP Response Headers",
        cwe_id="CWE-693",
        cvss_score=4.3,
    )
