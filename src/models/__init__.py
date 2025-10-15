"""Data models for MCP Security Scanner"""

from .vulnerability import Vulnerability, Severity
from .server import MCPServer
from .report import ScanReport

__all__ = [
    "Vulnerability",
    "Severity",
    "MCPServer",
    "ScanReport",
]
