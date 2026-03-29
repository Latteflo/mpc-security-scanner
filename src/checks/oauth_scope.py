"""
OAuth 2.0 Scope Validation Check

MCP-OAUTH-001  Insufficient OAuth Scope Enforcement

  MCP servers that delegate authentication to an OAuth 2.0 provider must
  validate that the presented token has the required scopes for each operation.
  Common failures:

    1. Scope not checked at all — any valid token grants full access regardless
       of its scopes (scope escalation).
    2. Scope downgrade accepted — a token with a read-only scope can call
       write/destructive tools.
    3. Over-broad scope required — the server demands admin scope for basic
       read operations (excessive privilege).

  Detection strategy:
    1. Confirm the server uses Bearer / OAuth (401 + WWW-Authenticate: Bearer).
    2. Check whether the WWW-Authenticate header advertises required scopes.
    3. Send a token whose scope claim is deliberately minimal ("read") or
       mismatched ("openid profile") and check if write tools are accessible.
    4. Craft a JWT with a minimal scope and one with a mismatched scope,
       test them against read and write tools, and compare access.

  We use the same JWT construction helper as the jwt_auth check — minimal
  HMAC-SHA256 with a placeholder secret. The goal is scope bypass, not
  signature bypass; these tokens will typically fail signature validation.
  We report a finding only when the server grants access despite a scope
  mismatch, which indicates it is NOT validating signatures AND not validating
  scopes — a compounded failure.
"""

import base64
import hashlib
import hmac as _hmac
import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("oauth_scope")

# ── Minimal JWT builder (same as jwt_auth check) ─────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(payload: dict, secret: bytes = b"secret") -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig_input = f"{h}.{p}"
    sig = _hmac.new(secret, sig_input.encode(), hashlib.sha256).digest()
    return f"{sig_input}.{_b64url(sig)}"


# Scope scenarios to test
_SCOPE_SCENARIOS: list[tuple[str, dict]] = [
    ("read-only scope", {
        "sub": "scanner", "iat": 1700000000, "exp": 9999999999,
        "scope": "read openid",
    }),
    ("unrelated scope", {
        "sub": "scanner", "iat": 1700000000, "exp": 9999999999,
        "scope": "openid profile email",
    }),
    ("empty scope", {
        "sub": "scanner", "iat": 1700000000, "exp": 9999999999,
        "scope": "",
    }),
]

_WRITE_KEYWORDS = {
    "send", "post", "write", "delete", "remove", "execute", "run",
    "create", "update", "patch", "email", "message", "notify", "upload",
    "publish", "deploy", "commit", "push", "modify", "edit",
}

_PROBE_PAYLOAD = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}


def _is_write_tool(name: str) -> bool:
    return any(kw in name.lower() for kw in _WRITE_KEYWORDS)


def _bearer_scope_advertised(headers: dict) -> str | None:
    """Return the scope string from WWW-Authenticate if present."""
    for k, v in headers.items():
        if k.lower() == "www-authenticate" and "bearer" in v.lower():
            # e.g. Bearer realm="...", scope="read write"
            import re
            m = re.search(r'scope="([^"]+)"', v, re.IGNORECASE)
            return m.group(1) if m else ""
    return None


async def _tool_accessible(server_url: str, tool: str, token: str) -> bool:
    """Return True if the tool call returns something other than 401/403."""
    request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
        "id": 1,
    }
    try:
        status, body, _ = await http_post(
            server_url, request, timeout=5.0,
            headers={"Authorization": f"Bearer {token}"},
        )
        return status not in (401, 403)
    except Exception:
        return False


async def check_oauth_scope(server: MCPServer) -> Optional[Vulnerability]:
    """Check for insufficient OAuth scope enforcement."""
    # Step 1: confirm Bearer auth
    try:
        status, _body, resp_headers = await http_post(
            server.url, _PROBE_PAYLOAD, timeout=5.0
        )
    except Exception as e:
        logger.debug(f"OAuth scope probe init failed: {e}")
        return None

    advertised_scope = _bearer_scope_advertised(resp_headers)
    if advertised_scope is None and status not in (401, 403):
        return None   # No Bearer auth detected

    # Find write tools to test scope downgrade
    write_tools = [t for t in server.tools if _is_write_tool(t)]
    if not write_tools:
        # Fall back: test tools/list access with mismatched scope
        write_tools = []

    bypass_scenarios: list[str] = []

    for scenario_label, claims in _SCOPE_SCENARIOS:
        token = _make_jwt(claims)

        # Can we list tools with this token?
        try:
            list_status, list_body, _ = await http_post(
                server.url, _PROBE_PAYLOAD, timeout=5.0,
                headers={"Authorization": f"Bearer {token}"},
            )
            list_accessible = list_status == 200 and "result" in list_body
        except Exception:
            list_accessible = False

        if not list_accessible:
            continue   # Token was rejected — scope enforcement working (or sig check)

        # Can we access write tools too?
        for tool in write_tools[:3]:
            if await _tool_accessible(server.url, tool, token):
                bypass_scenarios.append(
                    f"{scenario_label}: write tool '{tool}' accessible"
                )
                break
        else:
            # At minimum, listing tools with a mismatched scope is a finding
            if claims.get("scope") == "":
                bypass_scenarios.append(
                    f"{scenario_label}: tools/list accessible with empty scope"
                )

    if not bypass_scenarios:
        return None

    return Vulnerability.create(
        id="MCP-OAUTH-001",
        title="Insufficient OAuth Scope Enforcement",
        description=(
            f"The MCP server at {server.url} does not properly enforce OAuth scope "
            "restrictions. Tokens with minimal or mismatched scopes were accepted, "
            "allowing scope escalation — a client with a read-only token can access "
            "write or destructive operations."
        ),
        severity=Severity.HIGH,
        category="Authentication",
        remediation=(
            "Enforce OAuth scope validation:\n"
            "- Validate the 'scope' claim on every request, not just at token issuance\n"
            "- Map each tool/endpoint to a required minimum scope\n"
            "- Return HTTP 403 with error='insufficient_scope' for scope mismatches\n"
            "- Advertise required scopes in WWW-Authenticate challenge headers\n"
            "- Use a well-tested OAuth middleware library rather than hand-rolled checks\n"
            "- Rotate tokens and audit grants when a scope bypass is confirmed"
        ),
        evidence=[
            f"Server: {server.url}",
            f"Advertised scope: {advertised_scope!r}",
        ] + bypass_scenarios,
        affected_component="OAuth 2.0 Scope Validation",
        cwe_id="CWE-863",
        cvss_score=8.1,
    )
