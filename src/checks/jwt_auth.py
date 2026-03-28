"""
JWT Authentication Validation Check

MCP-JWT-001  JWT Authentication Weaknesses
  When an MCP server uses JWT Bearer tokens for authentication, several common
  implementation mistakes allow complete authentication bypass:

    1. Algorithm confusion (alg:none) — the server accepts a token with no
       signature, trusting the claims verbatim.
    2. Algorithm confusion (HS256 with public key) — when the server accepts
       both RS256 and HS256, an attacker can sign a token with the public key
       (which is public knowledge) using HS256 and bypass verification.
    3. Weak / default secrets — we test a curated list of common JWT secrets.
       A hit here means the server's tokens can be forged by anyone.

  We only run these tests when the server explicitly advertises JWT/Bearer
  authentication (401 with WWW-Authenticate: Bearer). We never attempt to
  brute-force secrets beyond the short list of known defaults.
"""

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("jwt_auth")

# ── JWT helpers ───────────────────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict, secret: bytes | None = None) -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}"

    if secret is None or header.get("alg") == "none":
        # alg:none — no signature
        return f"{signing_input}."

    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(sig)}"


# Payload with very permissive claims
_CLAIMS = {
    "sub": "admin",
    "iat": 1700000000,
    "exp": 9999999999,
    "role": "admin",
    "scope": "read write admin",
}

# Common weak / default JWT secrets
_WEAK_SECRETS = [
    b"secret",
    b"password",
    b"changeme",
    b"jwt_secret",
    b"supersecret",
    b"your-256-bit-secret",
    b"my_secret_key",
    b"",
    b"dev",
    b"test",
    b"admin",
    b"key",
    b"1234567890",
    b"qwerty",
]

_PROBES: list[tuple[str, str, bytes | None]] = (
    # (label, alg, secret)
    [("alg:none bypass", "none", None)]
    + [("weak secret: " + s.decode(errors="replace"), "HS256", s) for s in _WEAK_SECRETS]
)

_PROBE_PAYLOAD = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}


def _uses_bearer_auth(headers: dict) -> bool:
    """Return True if the response asks for Bearer (JWT) authentication."""
    www_auth = ""
    for k, v in headers.items():
        if k.lower() == "www-authenticate":
            www_auth = v.lower()
            break
    return "bearer" in www_auth


async def check_jwt_auth(server: MCPServer) -> Optional[Vulnerability]:
    """
    Test for JWT authentication weaknesses.
    Only runs when the server uses Bearer token authentication.
    """
    # Step 1 — confirm the server uses Bearer auth
    try:
        status, _body, resp_headers = await http_post(
            server.url, _PROBE_PAYLOAD, timeout=5.0
        )
    except Exception as e:
        logger.debug(f"Initial probe failed: {e}")
        return None

    if status not in (401, 403) and not _uses_bearer_auth(resp_headers):
        # No auth or not Bearer — nothing to test
        return None

    uses_bearer = _uses_bearer_auth(resp_headers)
    if not uses_bearer and status not in (401, 403):
        return None

    # Step 2 — probe with crafted JWTs
    for label, alg, secret in _PROBES:
        header = {"alg": alg, "typ": "JWT"}
        token = _make_jwt(header, _CLAIMS, secret)

        try:
            probe_status, body, _h = await http_post(
                server.url,
                _PROBE_PAYLOAD,
                timeout=5.0,
                headers={"Authorization": f"Bearer {token}"},
            )
        except Exception as e:
            logger.debug(f"JWT probe error ({label}): {e}")
            continue

        if probe_status == 200 and ("result" in body or "tools" in body):
            severity = Severity.CRITICAL if "none" in label else Severity.HIGH
            return Vulnerability.create(
                id="MCP-JWT-001",
                title=f"JWT Authentication Bypass ({label})",
                description=(
                    f"The MCP server at {server.url} accepted a crafted JWT using "
                    f"'{label}'. An attacker can forge valid authentication tokens "
                    "without knowing the real secret, gaining full unauthenticated "
                    "access to all tools and resources."
                ),
                severity=severity,
                category="Authentication",
                remediation=(
                    "Fix JWT validation:\n"
                    "- Explicitly allowlist accepted algorithms (never accept 'none')\n"
                    "- Use a cryptographically random secret of at least 256 bits\n"
                    "- Rotate any compromised secrets immediately\n"
                    "- For RS256/ES256, pin the expected algorithm server-side\n"
                    "- Use a well-maintained JWT library — avoid hand-rolled validation\n"
                    "- Validate exp, iat, and iss claims on every request"
                ),
                evidence=[
                    f"Server: {server.url}",
                    f"Bypass technique: {label}",
                    f"Forged token accepted (HTTP {probe_status})",
                ],
                affected_component="JWT Authentication",
                cwe_id="CWE-347",
                cvss_score=9.8 if "none" in label else 8.8,
            )

    return None
