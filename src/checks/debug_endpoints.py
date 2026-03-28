"""
Debug / Admin Endpoint Exposure Check

MCP-DEBUG-001  Exposed Debug or Admin Endpoints
  Development tooling (debuggers, profilers, metrics exporters, admin panels)
  is frequently left enabled or accessible in production MCP deployments.
  These endpoints often require no authentication and expose sensitive data
  such as environment variables, heap dumps, request logs, or remote code
  execution surfaces.

  We probe a curated list of common paths and flag any that return a
  non-404/non-connection-refused response with recognisable content.
  A path returning 200 is suspicious; 200 + matching content is a finding.
"""

import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_get
from utils.logger import get_logger

logger = get_logger("debug_endpoints")


# (path, label, content_hints)
# content_hints: substrings (lowercase) that confirm the endpoint is the real thing,
# not just a generic 200 page. Empty list = any 200 is enough.
_DEBUG_PATHS: list[tuple[str, str, list[str]]] = [
    # Health / readiness — low severity alone, but useful for fingerprinting
    ("/health",        "Health check",             ["status", "ok", "healthy", "up"]),
    ("/healthz",       "Health check (k8s)",        ["status", "ok", "healthy"]),
    ("/readyz",        "Readiness probe",           ["ready", "status"]),
    ("/livez",         "Liveness probe",            ["live", "status"]),
    # Metrics
    ("/metrics",       "Prometheus metrics",        ["# help", "# type", "process_"]),
    ("/actuator",      "Spring Boot Actuator",      ["_links", "actuator"]),
    ("/actuator/health", "Spring Boot health",      ["status", "components"]),
    ("/actuator/env",  "Spring Boot env dump",      ["propertysources", "systemproperties"]),
    ("/actuator/mappings", "Spring Boot routes",    ["dispatcherservlets", "mappings"]),
    # Debug / profiling
    ("/debug",         "Debug endpoint",            ["debug", "trace", "profile"]),
    ("/debug/pprof",   "Go pprof profiler",         ["goroutine", "heap", "profile"]),
    ("/_debug",        "Debug endpoint",            ["debug"]),
    ("/profiler",      "Profiler",                  ["profile", "heap", "cpu"]),
    # Admin panels
    ("/admin",         "Admin panel",               ["admin", "dashboard", "login"]),
    ("/_admin",        "Admin panel",               ["admin"]),
    ("/management",    "Management endpoint",       ["status", "info", "health"]),
    # Config / env exposure
    ("/env",           "Environment variables",     ["path=", "java_home", "node_env", "secret", "password"]),
    ("/config",        "Configuration dump",        ["database", "secret", "key", "password"]),
    # API introspection
    ("/swagger",       "Swagger UI",                ["swagger", "openapi"]),
    ("/swagger-ui",    "Swagger UI",                ["swagger", "openapi"]),
    ("/swagger.json",  "OpenAPI spec",              ["openapi", "swagger", "paths"]),
    ("/openapi.json",  "OpenAPI spec",              ["openapi", "paths"]),
    ("/docs",          "API docs (FastAPI/etc)",    ["swagger", "openapi", "redoc"]),
    ("/redoc",         "ReDoc API docs",            ["redoc", "openapi"]),
    # Werkzeug / Flask debug console
    ("/console",       "Debug console",             ["interactive", "console", "python", "werkzeug"]),
    # Laravel Telescope / Horizon
    ("/telescope",     "Laravel Telescope",         ["telescope", "requests", "queries"]),
    ("/horizon",       "Laravel Horizon",           ["horizon", "queues", "jobs"]),
]

# Statuses that indicate the path exists (vs definitely 404/closed)
_HIT_STATUSES = {200, 201, 301, 302, 401, 403}


async def check_debug_endpoints(server: MCPServer) -> Optional[Vulnerability]:
    """Probe common debug/admin paths and report any that appear active."""
    base = server.url.rstrip("/")
    found: list[tuple[str, str, int]] = []  # (path, label, status)

    for path, label, hints in _DEBUG_PATHS:
        url = base + path
        try:
            status, body, _headers = await http_get(url, timeout=4.0, verify_ssl=False)
        except (ConnectionError, TimeoutError):
            continue
        except Exception as e:
            logger.debug(f"Error probing {url}: {e}")
            continue

        if status not in _HIT_STATUSES:
            continue

        body_lower = body.lower()

        # If we have content hints, require at least one to match.
        if hints and not any(h in body_lower for h in hints):
            continue

        # 401/403 means the path exists but is access-controlled — still worth noting.
        found.append((path, label, status))

    if not found:
        return None

    # Highest severity when we got 200 on something that looks like env/admin/debug.
    has_open_sensitive = any(
        status == 200 and any(kw in label.lower() for kw in ("env", "admin", "console", "actuator"))
        for _, label, status in found
    )
    severity = Severity.HIGH if has_open_sensitive else Severity.MEDIUM

    evidence = [f"Server: {server.url}"]
    for path, label, status in found:
        evidence.append(f"HTTP {status}  {path}  ({label})")

    return Vulnerability.create(
        id="MCP-DEBUG-001",
        title=f"Debug / Admin Endpoint(s) Exposed ({len(found)} found)",
        description=(
            f"The server at {server.url} exposes {len(found)} debug or administrative "
            "endpoint(s) that should not be reachable in production. These paths can "
            "leak environment variables, configuration, internal metrics, request logs, "
            "or provide unauthenticated access to management functions."
        ),
        severity=severity,
        category="Configuration",
        remediation=(
            "Restrict or remove debug/admin endpoints in production:\n"
            "- Disable development tooling before deploying (DEBUG=False, etc.)\n"
            "- Place admin/actuator endpoints behind authentication and IP allowlists\n"
            "- Use a reverse proxy to block access to internal paths from the internet\n"
            "- Remove /swagger, /docs, and /openapi endpoints if the API is not public\n"
            "- Regularly audit exposed paths with a tool like this scanner"
        ),
        evidence=evidence,
        affected_component="Server Endpoints",
        cwe_id="CWE-489",
        cvss_score=7.5 if has_open_sensitive else 5.3,
    )
