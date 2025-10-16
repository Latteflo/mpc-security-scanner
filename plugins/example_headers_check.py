"""
Example Security Headers Plugin
Checks for missing security headers
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner.plugins import SecurityCheckPlugin
from src.models import MCPServer, Vulnerability, Severity
from src.utils import http_get


class SecurityHeadersPlugin(SecurityCheckPlugin):
    """Checks for missing security headers"""
    
    name = "Security Headers Check"
    version = "1.0.0"
    description = "Checks for missing security headers"
    author = "MCP Security Team"
    
    async def check(self, server: MCPServer) -> Vulnerability:
        """Check for security headers"""
        try:
            status, text, headers = await http_get(server.url, timeout=10.0)
            
            missing_headers = []
            
            # Check for important security headers
            required_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY or SAMEORIGIN",
                "X-XSS-Protection": "1; mode=block",
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "restrictive policy"
            }
            
            for header, description in required_headers.items():
                if header.lower() not in [h.lower() for h in headers.keys()]:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers and len(missing_headers) >= 3:
                return Vulnerability.create(
                    id="PLUGIN-HEADERS-001",
                    title="Missing Security Headers",
                    description=(
                        f"The MCP server at {server.url} is missing {len(missing_headers)} "
                        "important security headers that protect against common web attacks."
                    ),
                    severity=Severity.MEDIUM,
                    category="Security Headers",
                    remediation=(
                        "Add the following security headers:\n" +
                        "\n".join([f"- {h}" for h in missing_headers])
                    ),
                    evidence=[
                        f"Missing {len(missing_headers)} security headers",
                        *missing_headers[:5]
                    ],
                    affected_component="HTTP Headers"
                )
        
        except Exception as e:
            # Fail silently - don't crash the scanner
            pass
        
        return None
