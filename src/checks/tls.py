"""
TLS / Certificate Security Checks

MCP-TLS-001  Weak TLS Protocol Version
  The server accepts TLS 1.0 or TLS 1.1, both deprecated and vulnerable to
  POODLE, BEAST, and similar downgrade attacks. Only TLS 1.2+ should be accepted.

MCP-TLS-002  TLS Certificate Issues
  The server's certificate is expired, self-signed, or uses a weak signature
  algorithm (MD5/SHA-1). Any of these conditions break the chain of trust and
  may indicate a misconfigured or low-assurance deployment.

These checks are only performed for HTTPS targets. HTTP servers are already
flagged by MCP-CRYPTO-001 (unencrypted connection) so there is nothing
TLS-specific to report there.
"""

import ssl
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils.logger import get_logger

logger = get_logger("tls")


def _target_host_port(server: MCPServer) -> tuple[str, int] | None:
    """Extract (host, port) from the server URL; return None for non-HTTPS."""
    parsed = urlparse(server.url)
    if parsed.scheme.lower() != "https":
        return None
    host = parsed.hostname or ""
    port = parsed.port or 443
    return host, port


def _get_cert_info(host: str, port: int, timeout: float = 5.0) -> dict | None:
    """
    Open a TLS connection and return cert + protocol info.
    Returns None if the connection fails entirely.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # we inspect manually, don't abort on invalid certs

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return {
                    "protocol": tls.version(),          # e.g. "TLSv1.2"
                    "cipher": tls.cipher(),             # (name, protocol, bits)
                    "cert": tls.getpeercert(binary_form=False),
                }
    except ssl.SSLError as e:
        logger.debug(f"SSL error connecting to {host}:{port}: {e}")
        return None
    except (OSError, socket.timeout) as e:
        logger.debug(f"Network error connecting to {host}:{port}: {e}")
        return None


_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}
_WEAK_SIG_ALGORITHMS = {"md5", "sha1"}


async def check_tls(server: MCPServer) -> list[Vulnerability]:
    """
    Check TLS protocol version and certificate quality.
    Returns a list (possibly empty, possibly two items).
    """
    target = _target_host_port(server)
    if target is None:
        # Non-HTTPS — already covered by MCP-CRYPTO-001.
        return []

    host, port = target
    info = _get_cert_info(host, port)
    if info is None:
        return []

    vulns: list[Vulnerability] = []

    # ── MCP-TLS-001: weak protocol ────────────────────────────────────────────
    protocol = info.get("protocol") or ""
    if protocol in _WEAK_PROTOCOLS:
        vulns.append(Vulnerability.create(
            id="MCP-TLS-001",
            title=f"Weak TLS Protocol Accepted ({protocol})",
            description=(
                f"The server at {server.url} negotiated {protocol}, which is deprecated "
                "and vulnerable to protocol downgrade attacks (POODLE, BEAST). Clients "
                "and servers should only accept TLS 1.2 or TLS 1.3."
            ),
            severity=Severity.HIGH,
            category="Cryptography",
            remediation=(
                "Harden TLS configuration:\n"
                "- Disable TLS 1.0 and TLS 1.1 in your web server / load balancer\n"
                "- Allow only TLS 1.2 and TLS 1.3\n"
                "- Use strong cipher suites (ECDHE + AES-GCM / ChaCha20)\n"
                "- Test with `openssl s_client -tls1 <host>` to verify old versions are rejected"
            ),
            evidence=[
                f"Server: {server.url}",
                f"Negotiated protocol: {protocol}",
            ],
            affected_component="TLS Configuration",
            cwe_id="CWE-326",
            cvss_score=7.4,
        ))

    # ── MCP-TLS-002: certificate issues ──────────────────────────────────────
    cert = info.get("cert") or {}
    cert_issues: list[str] = []

    # Expiry
    not_after_str = cert.get("notAfter", "")
    if not_after_str:
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if not_after < now:
                days_ago = (now - not_after).days
                cert_issues.append(f"Certificate expired {days_ago} day(s) ago ({not_after_str})")
        except ValueError:
            logger.debug(f"Could not parse notAfter: {not_after_str!r}")

    # Self-signed: issuer == subject
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    if subject and subject == issuer:
        cert_issues.append("Certificate is self-signed (issuer == subject)")

    # Weak signature algorithm
    sig_alg = (cert.get("signatureAlgorithm") or "").lower()
    if any(w in sig_alg for w in _WEAK_SIG_ALGORITHMS):
        cert_issues.append(f"Weak signature algorithm: {cert.get('signatureAlgorithm')}")

    if cert_issues:
        vulns.append(Vulnerability.create(
            id="MCP-TLS-002",
            title="TLS Certificate Issues Detected",
            description=(
                f"The TLS certificate for {server.url} has one or more problems that "
                "break the chain of trust or indicate a low-assurance deployment: "
                + "; ".join(cert_issues) + "."
            ),
            severity=Severity.HIGH,
            category="Cryptography",
            remediation=(
                "Fix certificate issues:\n"
                "- Obtain a certificate from a trusted CA (e.g. Let's Encrypt)\n"
                "- Renew expired certificates before their expiry date\n"
                "- Replace SHA-1 / MD5 certificates with SHA-256 or better\n"
                "- Automate renewal (certbot, ACME) to avoid future expiry"
            ),
            evidence=[f"Server: {server.url}"] + cert_issues,
            affected_component="TLS Certificate",
            cwe_id="CWE-295",
            cvss_score=7.4,
        ))

    return vulns
