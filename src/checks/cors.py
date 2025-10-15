"""
CORS (Cross-Origin Resource Sharing) Security Checks
"""

import sys
from pathlib import Path
from typing import Optional

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_get
from utils.logger import get_logger

logger = get_logger("cors")


async def check_cors_misconfiguration(server: MCPServer) -> Optional[Vulnerability]:
    """
    Check for CORS misconfigurations
    
    Args:
        server: MCPServer to check
        
    Returns:
        Vulnerability if CORS issue found, None otherwise
    """
    
    try:
        # Test with a malicious origin
        headers = {
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST"
        }
        
        status, text, response_headers = await http_get(
            server.url,
            headers=headers,
            timeout=10.0
        )
        
        # Check for overly permissive CORS
        acao = response_headers.get("access-control-allow-origin", "").lower()
        
        if acao == "*":
            return Vulnerability.create(
                id="MCP-CORS-001",
                title="Overly Permissive CORS Policy",
                description=(
                    f"The MCP server at {server.url} has a wildcard (*) CORS policy, "
                    "allowing any website to make requests. This can lead to data theft "
                    "and unauthorized actions if combined with credential exposure."
                ),
                severity=Severity.HIGH,
                category="CORS",
                remediation=(
                    "Restrict CORS to specific trusted origins:\n"
                    "- Use explicit origin whitelist\n"
                    "- Never use Access-Control-Allow-Origin: *\n"
                    "- Implement proper origin validation\n"
                    "- Consider using Access-Control-Allow-Credentials: true only with specific origins"
                ),
                evidence=[
                    f"Access-Control-Allow-Origin: {acao}",
                    "Tested with origin: https://evil.com",
                    "Server responded with permissive policy"
                ],
                affected_component="CORS Configuration",
                cwe_id="CWE-942",
                cvss_score=7.5
            )
        
        elif acao == "https://evil.com":
            return Vulnerability.create(
                id="MCP-CORS-002",
                title="CORS Origin Reflection Vulnerability",
                description=(
                    f"The MCP server at {server.url} reflects any requesting origin "
                    "in the Access-Control-Allow-Origin header. This is worse than "
                    "using a wildcard as it bypasses browser security checks."
                ),
                severity=Severity.CRITICAL,
                category="CORS",
                remediation=(
                    "Fix CORS configuration:\n"
                    "- Maintain an explicit whitelist of allowed origins\n"
                    "- Validate origin against whitelist before setting header\n"
                    "- Never reflect the Origin header directly\n"
                    "- Log and monitor CORS requests"
                ),
                evidence=[
                    f"Access-Control-Allow-Origin: {acao}",
                    "Origin reflection detected",
                    "Tested origin: https://evil.com",
                    "Server reflects attacker-controlled origin"
                ],
                affected_component="CORS Configuration",
                cwe_id="CWE-942",
                cvss_score=9.1
            )
        
        acac = response_headers.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            return Vulnerability.create(
                id="MCP-CORS-003",
                title="CORS Credentials with Wildcard Origin",
                description=(
                    f"The MCP server at {server.url} allows credentials (cookies, auth) "
                    "while using wildcard CORS. This configuration can lead to credential "
                    "theft and session hijacking."
                ),
                severity=Severity.CRITICAL,
                category="CORS",
                remediation=(
                    "Immediate action required:\n"
                    "- Remove Access-Control-Allow-Credentials OR\n"
                    "- Replace wildcard with specific trusted origins\n"
                    "- Never combine credentials with wildcard\n"
                    "- Review authentication mechanism"
                ),
                evidence=[
                    f"Access-Control-Allow-Origin: {acao}",
                    f"Access-Control-Allow-Credentials: {acac}",
                    "Dangerous combination detected"
                ],
                affected_component="CORS Configuration",
                cwe_id="CWE-942",
                cvss_score=9.8
            )
        
        logger.debug(f"CORS check passed for {server.url}")
        return None
        
    except Exception as e:
        logger.debug(f"CORS check error for {server.url}: {str(e)}")
        return None
