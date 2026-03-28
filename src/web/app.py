"""
Web dashboard backend for MCP Security Scanner.

Architecture:
- FastAPI handles all routes.
- POST /api/scan starts a background asyncio task and returns a scan_id immediately.
- GET /api/scan/{scan_id}/stream is a Server-Sent Events endpoint. The background
  task puts events onto a per-scan asyncio.Queue; the SSE route drains it and
  forwards events to the browser. Events are also appended to scan_state.events so
  late-connecting or reconnecting clients can replay missed events.
- GET /api/scan/{scan_id}/report serves the generated report file for download.
- All state lives in the module-level _scans dict — no database, no cleanup needed
  for a short-lived local process.
"""

import asyncio
import json
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator, Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

# Resolve src/ on the path so we can import project modules the same way the
# CLI does, regardless of whether the package was pip-installed or run from source.
sys.path.insert(0, str(Path(__file__).parent.parent))

from compliance.frameworks import ComplianceFramework
from scanner.discovery import MCPDiscovery
from scanner.analyzer import SecurityAnalyzer
from scanner.reporter import ReportGenerator

STATIC_DIR = Path(__file__).parent / "static"

# ──────────────────────────────────────────────────────────────────────────────
# Scan state
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanState:
    scan_id: str
    target: str
    fmt: str          # "json" | "html" | "pdf" | "sarif"
    framework: str | None
    status: Literal["pending", "running", "complete", "error"] = "pending"
    # Append-only log of emitted events — used to replay on reconnect.
    events: list = field(default_factory=list)
    # Live channel between the background task and the SSE route.
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    report_path: str | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)


# Module-level store; keyed by scan_id.
_scans: dict[str, ScanState] = {}


# ──────────────────────────────────────────────────────────────────────────────
# Request / response models
# ──────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    format: str = "json"
    framework: str | None = None


# ──────────────────────────────────────────────────────────────────────────────
# Background scan task
# ──────────────────────────────────────────────────────────────────────────────

async def _run_scan(state: ScanState) -> None:
    """
    Full scan pipeline executed as a background asyncio task.

    Emits SSE events at each phase so the browser can show live progress.
    All events are both put on the queue (for the live SSE stream) and
    appended to state.events (for reconnect replay).
    """

    def emit(event: dict) -> None:
        state.events.append(event)
        state.queue.put_nowait(event)

    state.status = "running"

    try:
        # ── Phase 1: Discovery ────────────────────────────────────────────────
        emit({"type": "phase", "phase": "discovery", "message": "Probing MCP server..."})

        discovery = MCPDiscovery()
        server_info = await discovery.probe_server(state.target)

        if not server_info:
            state.status = "error"
            state.error = "Could not connect to MCP server"
            emit({
                "type": "error",
                "message": "Could not connect to MCP server",
                "detail": "Check that the server is running and the URL is correct.",
            })
            return

        emit({
            "type": "discovery_result",
            "server": {
                "name": server_info.name or "Unknown",
                "version": server_info.version or "Unknown",
                "url": server_info.url,
                "tools": server_info.tools,
                "resources": server_info.resources,
                "has_authentication": server_info.has_authentication,
                "has_encryption": server_info.has_encryption,
            },
        })

        # ── Phase 2: Analysis ─────────────────────────────────────────────────
        emit({"type": "phase", "phase": "analysis", "message": "Running security checks..."})

        # Run each check group individually so we can emit progress events
        # between them without modifying SecurityAnalyzer.scan().
        analyzer = SecurityAnalyzer()
        check_groups = [
            ("_check_authentication",   "Authentication"),
            ("_check_encryption",       "Encryption"),
            ("_check_tools_exposure",   "Tool Exposure"),
            ("_check_configuration",    "Configuration"),
            ("_check_cors",             "CORS"),
            ("_check_rate_limiting",    "Rate Limiting"),
            ("_check_injection_attacks","Injection Attacks"),
            ("_check_ai_specific",      "AI-Specific Checks"),
        ]
        total = len(check_groups)

        for i, (method_name, label) in enumerate(check_groups, start=1):
            await getattr(analyzer, method_name)(server_info)
            latest = (
                analyzer.vulnerabilities[-1].title
                if analyzer.vulnerabilities
                else None
            )
            emit({
                "type": "progress",
                "checks_done": i,
                "checks_total": total,
                "latest_check": label,
                "latest_finding": latest,
            })

        # Apply compliance mappings (same as analyzer.scan() does at the end).
        analyzer._add_compliance_mappings()
        vulnerabilities = analyzer.vulnerabilities

        # ── Phase 3: Reporting ────────────────────────────────────────────────
        emit({"type": "phase", "phase": "reporting", "message": "Generating report..."})

        tmp_dir = tempfile.mkdtemp(prefix="mcp-scan-")
        ext = {"json": "json", "html": "html", "pdf": "pdf", "sarif": "sarif"}.get(state.fmt, "json")
        report_path = str(Path(tmp_dir) / f"scan-{state.scan_id}.{ext}")

        reporter = ReportGenerator()
        await reporter.generate(
            server_info=server_info,
            vulnerabilities=vulnerabilities,
            output_path=report_path,
            format=state.fmt,
        )
        state.report_path = report_path

        # ── Complete ──────────────────────────────────────────────────────────
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulnerabilities:
            severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1

        # Risk score: weight by severity
        weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 1}
        raw = sum(weights.get(s, 0) * c for s, c in severity_counts.items())
        risk_score = min(100, raw)

        emit({
            "type": "complete",
            "scan_id": state.scan_id,
            "summary": {**severity_counts, "risk_score": risk_score},
            "vulnerabilities": [_vuln_to_dict(v) for v in vulnerabilities],
            "report_available": state.fmt != "terminal",
            "duration_seconds": (datetime.utcnow() - state.created_at).total_seconds(),
        })
        state.status = "complete"

    except Exception as exc:  # noqa: BLE001
        state.status = "error"
        state.error = str(exc)
        emit({"type": "error", "message": "Scan failed", "detail": str(exc)})


def _vuln_to_dict(v) -> dict:
    """Serialize a Vulnerability for the SSE complete event."""
    return {
        "id": v.id,
        "title": v.title,
        "description": v.description,
        "severity": v.severity.value,
        "category": v.category,
        "cwe_id": v.cwe_id,
        "cvss_score": v.cvss_score,
        "evidence": v.evidence,
        "affected_component": v.affected_component,
        "remediation": v.remediation,
        "compliance_frameworks": v.compliance_frameworks,
        "compliance_controls": v.compliance_controls,
    }


# ──────────────────────────────────────────────────────────────────────────────
# SSE generator
# ──────────────────────────────────────────────────────────────────────────────

async def _event_stream(state: ScanState) -> AsyncGenerator[str, None]:
    """
    Async generator that yields SSE-formatted strings.

    1. Replays all already-emitted events (handles late connects / reconnects).
    2. Then reads new events from the queue until a terminal event is seen.
    3. Sends a keepalive comment every 25 s to prevent proxy timeouts.
    """
    # Replay past events so reconnecting clients catch up.
    for event in list(state.events):
        yield f"data: {json.dumps(event)}\n\n"
        if event["type"] in ("complete", "error"):
            return

    # Stream new events.
    while True:
        try:
            event = await asyncio.wait_for(state.queue.get(), timeout=25.0)
        except asyncio.TimeoutError:
            yield ": keepalive\n\n"
            continue

        yield f"data: {json.dumps(event)}\n\n"

        if event["type"] in ("complete", "error"):
            return


# ──────────────────────────────────────────────────────────────────────────────
# App factory
# ──────────────────────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(title="MCP Security Scanner", docs_url=None, redoc_url=None)

    # ── Static UI ─────────────────────────────────────────────────────────────

    @app.get("/")
    async def index():
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    # ── Frameworks list ───────────────────────────────────────────────────────

    @app.get("/api/frameworks")
    async def list_frameworks():
        labels = {
            "ISO27001":    "ISO/IEC 27001:2013",
            "NIST_CSF":    "NIST Cybersecurity Framework",
            "NIST_800_53": "NIST SP 800-53 Rev. 5",
            "MITRE_ATTCK": "MITRE ATT&CK",
            "PCI_DSS":     "PCI DSS 3.2.1",
            "SOC2":        "SOC 2 Type II",
        }
        return {
            "frameworks": [
                {"id": f.value, "label": labels.get(f.value, f.value)}
                for f in ComplianceFramework
            ]
        }

    # ── Start scan ────────────────────────────────────────────────────────────

    @app.post("/api/scan", status_code=202)
    async def start_scan(req: ScanRequest):
        scan_id = str(uuid.uuid4())
        state = ScanState(
            scan_id=scan_id,
            target=req.target,
            fmt=req.format,
            framework=req.framework,
        )
        _scans[scan_id] = state
        asyncio.create_task(_run_scan(state))
        return {"scan_id": scan_id}

    # ── Stream progress ───────────────────────────────────────────────────────

    @app.get("/api/scan/{scan_id}/stream")
    async def stream_scan(scan_id: str):
        state = _scans.get(scan_id)
        if not state:
            raise HTTPException(status_code=404, detail="Scan not found")
        return StreamingResponse(
            _event_stream(state),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",  # disable nginx buffering if behind a proxy
            },
        )

    # ── Download report ───────────────────────────────────────────────────────

    @app.get("/api/scan/{scan_id}/report")
    async def download_report(scan_id: str):
        state = _scans.get(scan_id)
        if not state:
            raise HTTPException(status_code=404, detail="Scan not found")
        if state.status != "complete" or not state.report_path:
            raise HTTPException(status_code=409, detail="Report not ready")
        path = Path(state.report_path)
        if not path.exists():
            raise HTTPException(status_code=410, detail="Report file no longer available")

        ext = path.suffix.lstrip(".")
        media_types = {
            "json": "application/json",
            "html": "text/html",
            "pdf":  "application/pdf",
            "sarif": "application/json",
        }
        return FileResponse(
            path=state.report_path,
            media_type=media_types.get(ext, "application/octet-stream"),
            filename=f"mcp-scan-{scan_id[:8]}.{ext}",
        )

    return app
