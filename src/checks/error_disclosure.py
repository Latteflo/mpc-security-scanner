"""
Error / Information Disclosure Check

MCP-ERR-001  Verbose Error / Stack Trace Disclosure
  Sending malformed or unexpected requests to many servers reveals internal
  details: stack traces, file paths, library versions, database connection
  strings, or server framework signatures. Attackers use this to fingerprint
  the stack and target known CVEs.

  Strategy:
    1. Send several intentionally malformed JSON-RPC payloads.
    2. Scan the response body for patterns that indicate internal disclosure
       (Python/Node/Java tracebacks, absolute file paths, DB connection strings,
       framework error pages, etc.).
    3. Only report when concrete disclosure patterns are found — a bare 500
       response is not enough.
"""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post, http_get
from utils.logger import get_logger

logger = get_logger("error_disclosure")


# Malformed payloads designed to trigger different error paths.
_BAD_PAYLOADS = [
    # Missing required fields
    {"jsonrpc": "2.0", "id": 1},
    # Unknown method
    {"jsonrpc": "2.0", "method": "___nonexistent___", "id": 1},
    # Wrong types
    {"jsonrpc": "2.0", "method": 12345, "params": None, "id": 1},
    # Deeply nested to trigger parser errors
    {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": None, "arguments": None}, "id": 1},
]

# Pattern → description of what it reveals
_DISCLOSURE_PATTERNS: list[tuple[str, str]] = [
    # Python tracebacks
    ("traceback (most recent call last)", "Python stack trace"),
    ("file \"/", "Python file path in traceback"),
    ("  file \"", "Python file path in traceback"),
    # Node.js / V8
    ("at object.<anonymous>", "Node.js stack trace"),
    ("at module._compile", "Node.js stack trace"),
    ("error: cannot find module", "Node.js module path"),
    # Java / Spring
    ("java.lang.", "Java exception"),
    ("at com.", "Java stack trace"),
    ("at org.springframework", "Spring framework stack trace"),
    ("caused by:", "Java exception chain"),
    # .NET
    ("system.exception", ".NET exception"),
    ("at system.", ".NET stack trace"),
    ("---> system.", ".NET inner exception"),
    # Generic
    ("/home/", "Unix home path"),
    ("/var/www/", "Web root path"),
    ("/usr/local/", "System library path"),
    ("c:\\users\\", "Windows user path"),
    ("c:\\inetpub\\", "IIS web root path"),
    # Database connection strings
    ("mongodb://", "MongoDB connection string"),
    ("postgresql://", "PostgreSQL connection string"),
    ("mysql://", "MySQL connection string"),
    ("redis://", "Redis connection string"),
    ("password=", "Credential in error output"),
    # Framework signatures in errors
    ("werkzeug debugger", "Flask/Werkzeug debug mode active"),
    ("django.core.exceptions", "Django internal error"),
    ("rails application trace", "Ruby on Rails stack trace"),
    ("express.js", "Express.js framework disclosure"),
    ("fastapi", "FastAPI framework version disclosure"),
    ("uvicorn", "Uvicorn server disclosure"),
    # Generic internal path indicators
    ("internal server error", None),   # alone is too vague — combined with others
]

# These on their own are not enough — require a companion pattern too.
_WEAK_PATTERNS = {"internal server error"}


async def check_error_disclosure(server: MCPServer) -> Optional[Vulnerability]:
    """Check whether malformed requests trigger verbose error disclosure."""
    found_patterns: list[str] = []
    triggering_payload: dict | None = None

    for payload in _BAD_PAYLOADS:
        try:
            _status, text, _headers = await http_post(server.url, payload, timeout=5.0)
            text_lower = text.lower()

            hits = [
                desc for pat, desc in _DISCLOSURE_PATTERNS
                if desc and pat in text_lower
            ]
            # Lone "internal server error" is noise without a stronger companion.
            weak_hits = [pat for pat, _ in _DISCLOSURE_PATTERNS if not _ and pat in text_lower]
            if weak_hits and not hits:
                continue

            if hits:
                found_patterns = hits
                triggering_payload = payload
                break

        except (ConnectionError, TimeoutError) as e:
            logger.debug(f"Error sending bad payload to {server.url}: {e}")
            continue
        except Exception as e:
            logger.debug(f"Unexpected error: {e}")
            continue

    if not found_patterns:
        return None

    return Vulnerability.create(
        id="MCP-ERR-001",
        title="Verbose Error / Internal Information Disclosure",
        description=(
            f"The server at {server.url} returns detailed internal error information "
            "in response to malformed requests. This gives attackers visibility into "
            "the technology stack, file system layout, or credentials, which they can "
            "use to target known CVEs or pivot further."
        ),
        severity=Severity.MEDIUM,
        category="Information Disclosure",
        remediation=(
            "Suppress internal error details in production:\n"
            "- Disable debug mode / development error pages\n"
            "- Return generic error messages to clients (e.g. 'Internal server error')\n"
            "- Log full details server-side only, never in HTTP responses\n"
            "- Set framework-specific debug flags: DEBUG=False (Django/Flask), "
            "NODE_ENV=production (Node), etc.\n"
            "- Ensure exception handlers catch all unhandled errors before they reach the wire"
        ),
        evidence=[
            f"Server: {server.url}",
            f"Disclosed: {', '.join(found_patterns)}",
            f"Triggered by payload: {triggering_payload}",
        ],
        affected_component="Error Handling",
        cwe_id="CWE-209",
        cvss_score=5.3,
    )
