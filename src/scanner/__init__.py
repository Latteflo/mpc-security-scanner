"""Scanner modules for MCP Security Scanner"""

from .discovery import MCPDiscovery
from .analyzer import SecurityAnalyzer
from .reporter import ReportGenerator

# Import new features if they exist
try:
    from .network_scanner import NetworkScanner, scan_network_for_mcp
    from .plugins import PluginManager, SecurityCheckPlugin
    __all__ = [
        "MCPDiscovery",
        "SecurityAnalyzer",
        "ReportGenerator",
        "NetworkScanner",
        "scan_network_for_mcp",
        "PluginManager",
        "SecurityCheckPlugin",
    ]
except ImportError:
    # If new modules don't exist yet, just export the original ones
    __all__ = [
        "MCPDiscovery",
        "SecurityAnalyzer",
        "ReportGenerator",
    ]
