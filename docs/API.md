# API Reference

## Models

### Vulnerability
Represents a security vulnerability.
```python
from src.models import Vulnerability, Severity

vuln = Vulnerability.create(
    id="MCP-AUTH-001",
    title="Missing Authentication",
    description="Server lacks authentication",
    severity=Severity.CRITICAL,
    category="Authentication",
    remediation="Implement API keys or OAuth"
)
```

### MCPServer
Represents an MCP server.
```python
from src.models import MCPServer

server = MCPServer(
    host="localhost",
    port=3000,
    protocol="http",
    name="Test Server"
)
```

## Scanner Components

### MCPDiscovery
Discovers and fingerprints MCP servers.
```python
from src.scanner import MCPDiscovery

discovery = MCPDiscovery()
server = await discovery.probe_server("http://localhost:3000")
```

### SecurityAnalyzer
Analyzes servers for vulnerabilities.
```python
from src.scanner import SecurityAnalyzer

analyzer = SecurityAnalyzer()
vulnerabilities = await analyzer.scan(server)
```

### ReportGenerator
Generates reports in multiple formats.
```python
from src.scanner import ReportGenerator

reporter = ReportGenerator()
await reporter.generate(
    server_info=server,
    vulnerabilities=vulnerabilities,
    output_path="report.html",
    format="html"
)
```

## Utilities

### Logger
```python
from src.utils import setup_logger

logger = setup_logger(level="DEBUG")
logger.info("Scanning started")
```

### Config
```python
from src.utils import load_config

config = load_config("config/scanner.yaml")
```

### Network
```python
from src.utils import http_get, parse_url

status, text, headers = await http_get("http://example.com")
host, port, path = parse_url("http://example.com:3000/api")
```
