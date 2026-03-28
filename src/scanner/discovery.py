"""
MCP Server Discovery Module
Finds and probes MCP servers over HTTP, HTTPS, and SSE transports.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, List
from urllib.parse import urlparse

from rich.console import Console

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import MCPServer
from utils import http_post, http_get, parse_url, scan_ports
from utils.logger import get_logger

console = Console()
logger = get_logger("discovery")


class MCPDiscovery:
    """Discovers and probes MCP servers"""

    def __init__(self, verify_ssl: bool = True):
        self.verify_ssl = verify_ssl
        self.timeout = 10.0

    async def probe_server(self, target: str) -> Optional[MCPServer]:
        """
        Probe a target to discover if it's an MCP server.

        Tries transports in this order:
          1. HTTP/HTTPS JSON-RPC (most common for self-hosted servers)
          2. SSE (Server-Sent Events) — used by Claude Desktop integrations,
             VS Code extensions, and many production deployments.
             Attempted on `<target>/sse` if the direct URL doesn't respond.

        Returns MCPServer on success, None if the target is not an MCP server.
        """
        logger.info(f"Probing target: {target}")

        if not target.startswith(("http://", "https://", "sse://")):
            target = f"http://{target}"

        # If the URL explicitly points to an SSE endpoint, go straight there
        if target.startswith("sse://") or target.endswith("/sse"):
            normalized = target.replace("sse://", "http://", 1)
            server = await self._detect_mcp_sse(normalized)
            if server:
                return server

        host, port, path = parse_url(target)

        # Primary: HTTP/HTTPS JSON-RPC probe
        server = await self._detect_mcp_http(target)
        if server:
            logger.info(f"✓ Found MCP server (HTTP) at {target}")
            return server

        # Fallback: try the /sse endpoint on the same host — many servers that
        # don't respond to bare HTTP POST do respond to SSE on /sse
        sse_url = target.rstrip("/") + "/sse"
        server = await self._detect_mcp_sse(sse_url)
        if server:
            logger.info(f"✓ Found MCP server (SSE) at {sse_url}")
            return server

        logger.warning(f"✗ No MCP server found at {target}")
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # HTTP transport
    # ──────────────────────────────────────────────────────────────────────────

    async def _detect_mcp_http(self, url: str) -> Optional[MCPServer]:
        """Probe via raw HTTP JSON-RPC (the original transport)."""
        host, port, path = parse_url(url)
        protocol = "https" if url.startswith("https") else "http"

        mcp_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-security-scanner", "version": "0.2.1"},
            },
            "id": 1,
        }

        try:
            status, response_text, headers = await http_post(
                url, mcp_request, timeout=self.timeout, verify_ssl=self.verify_ssl
            )

            if status == 200:
                try:
                    response = json.loads(response_text)
                    if "jsonrpc" in response and (
                        "result" in response or "error" in response
                    ):
                        logger.info(f"✓ MCP protocol detected (HTTP) at {url}")
                        server = MCPServer(
                            host=host,
                            port=port,
                            protocol=protocol,
                            name=self._extract_server_name(response),
                            version=self._extract_server_version(response),
                        )
                        await self._probe_capabilities_http(server)
                        return server
                except json.JSONDecodeError:
                    pass

            # Loose detection: response body mentions MCP (fallback for servers
            # that don't speak JSON-RPC to unknown clients)
            if "mcp" in response_text.lower() or "model-context-protocol" in response_text.lower():
                logger.info(f"✓ MCP mentions found in response from {url}")
                return MCPServer(host=host, port=port, protocol=protocol, name="Unknown MCP Server")

        except Exception as e:
            logger.debug(f"HTTP probe error for {url}: {e}")

        return None

    # ──────────────────────────────────────────────────────────────────────────
    # SSE transport
    # ──────────────────────────────────────────────────────────────────────────

    async def _detect_mcp_sse(self, url: str) -> Optional[MCPServer]:
        """
        Probe via Server-Sent Events transport using the MCP SDK.

        SSE is the standard transport for:
          - Claude Desktop MCP integrations
          - VS Code extension servers
          - Many production deployments behind reverse proxies

        We use the official mcp.client.sse module when available. If the SDK
        isn't installed or the version doesn't match, we gracefully return None
        rather than crashing — the HTTP probe path will have already run.
        """
        host, port, path = parse_url(url)
        protocol = "https" if url.startswith("https") else "http"

        try:
            from mcp.client.sse import sse_client
            from mcp import ClientSession

            logger.debug(f"Attempting SSE probe at {url}")

            async with sse_client(url) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    init_result = await asyncio.wait_for(
                        session.initialize(), timeout=self.timeout
                    )

                    server_info = getattr(init_result, "serverInfo", None)
                    server = MCPServer(
                        host=host,
                        port=port,
                        protocol=protocol,
                        name=getattr(server_info, "name", None) if server_info else None,
                        version=getattr(server_info, "version", None) if server_info else None,
                    )

                    await self._probe_capabilities_sdk(server, session)
                    return server

        except ImportError:
            logger.debug("mcp.client.sse not available — skipping SSE probe")
        except asyncio.TimeoutError:
            logger.debug(f"SSE probe timed out for {url}")
        except Exception as e:
            logger.debug(f"SSE probe failed for {url}: {e}")

        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Capability probing — raw HTTP version
    # ──────────────────────────────────────────────────────────────────────────

    async def _probe_capabilities_http(self, server: MCPServer):
        """
        Enumerate tools and resources via raw JSON-RPC HTTP calls.

        We store the full tool metadata (inputSchema + description) so that
        AI-specific security checks can inspect them later. Older scanners
        only kept tool names, which meant checks like tool poisoning and
        over-permissive schema couldn't run.
        """
        url = server.url

        # Tools
        try:
            tools_request = {"jsonrpc": "2.0", "method": "tools/list", "id": 2}
            status, response_text, _ = await http_post(
                url, tools_request, timeout=self.timeout, verify_ssl=self.verify_ssl
            )
            if status == 200:
                response = json.loads(response_text)
                if "result" in response and "tools" in response["result"]:
                    self._apply_tools(server, response["result"]["tools"])
        except Exception as e:
            logger.debug(f"Error listing tools for {url}: {e}")

        # Resources
        try:
            resources_request = {"jsonrpc": "2.0", "method": "resources/list", "id": 3}
            status, response_text, _ = await http_post(
                url, resources_request, timeout=self.timeout, verify_ssl=self.verify_ssl
            )
            if status == 200:
                response = json.loads(response_text)
                if "result" in response and "resources" in response["result"]:
                    server.resources = [
                        r.get("uri", "unknown") for r in response["result"]["resources"]
                    ]
                    logger.info(f"Found {len(server.resources)} resources")
        except Exception as e:
            logger.debug(f"Error listing resources for {url}: {e}")

        server.has_authentication = await self._check_authentication(server)
        server.has_encryption = url.startswith("https://")

    # ──────────────────────────────────────────────────────────────────────────
    # Capability probing — MCP SDK version (used after SSE connect)
    # ──────────────────────────────────────────────────────────────────────────

    async def _probe_capabilities_sdk(self, server: MCPServer, session):
        """
        Enumerate tools and resources via an already-established ClientSession.

        The SDK returns typed objects with proper fields — no string parsing needed.
        """
        try:
            tools_result = await session.list_tools()
            raw_tools = []
            for tool in tools_result.tools:
                # Normalise: SDK Tool objects vs raw dicts (SDK version variations)
                if hasattr(tool, "name"):
                    raw_tools.append({
                        "name": tool.name,
                        "description": getattr(tool, "description", "") or "",
                        "inputSchema": getattr(tool, "inputSchema", {}) or {},
                    })
                else:
                    raw_tools.append(tool)
            self._apply_tools(server, raw_tools)
        except Exception as e:
            logger.debug(f"SDK tools/list failed: {e}")

        try:
            resources_result = await session.list_resources()
            server.resources = [
                getattr(r, "uri", str(r)) for r in resources_result.resources
            ]
        except Exception as e:
            logger.debug(f"SDK resources/list failed: {e}")

        server.has_authentication = await self._check_authentication(server)
        server.has_encryption = server.url.startswith("https://")

    # ──────────────────────────────────────────────────────────────────────────
    # Shared helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _apply_tools(self, server: MCPServer, tools: list):
        """
        Populate server.tools, server.tool_schemas, and server.tool_descriptions
        from a list of raw tool dicts (from JSON-RPC response or SDK normalisation).

        Keeping all three in sync here means every downstream check can rely on
        them being consistent — no partial updates.
        """
        server.tools = [t.get("name", "unknown") for t in tools]
        server.tool_schemas = {
            t.get("name", "unknown"): t.get("inputSchema", {}) or {}
            for t in tools
        }
        server.tool_descriptions = {
            t.get("name", "unknown"): t.get("description", "") or ""
            for t in tools
        }
        logger.info(f"Found {len(server.tools)} tools")

    def _extract_server_name(self, response: dict) -> Optional[str]:
        try:
            return response["result"].get("serverInfo", {}).get("name")
        except (KeyError, TypeError, AttributeError):
            return None

    def _extract_server_version(self, response: dict) -> Optional[str]:
        try:
            return response["result"].get("serverInfo", {}).get("version")
        except (KeyError, TypeError, AttributeError):
            return None

    async def _check_authentication(self, server: MCPServer) -> bool:
        """
        Test whether the server requires authentication.

        We send an unauthenticated tools/list request. A 401/403 means auth
        is enforced. A 200 with valid data means anyone can connect.

        On any error we default to False (no auth detected) rather than True,
        because assuming auth when we can't verify it would suppress the
        MCP-AUTH-001 finding — a false negative is worse here than a false positive.
        """
        try:
            test_request = {"jsonrpc": "2.0", "method": "tools/list", "id": 999}
            status, response_text, headers = await http_post(
                server.url, test_request, timeout=5.0
            )

            if status in [401, 403]:
                return True

            if status == 200:
                try:
                    response = json.loads(response_text)
                    if "result" in response:
                        return False  # Got valid data with no credentials
                except json.JSONDecodeError:
                    pass

            if "www-authenticate" in str(headers).lower():
                return True

        except Exception as e:
            logger.debug(f"Auth check error for {server.url}: {e}")

        return False

    async def network_scan(
        self,
        ip_range: str,
        ports: List[int] = [3000, 3001, 8000, 8080, 5000],
    ) -> List[MCPServer]:
        """Scan a network range for MCP servers (experimental)."""
        logger.info(f"Scanning network: {ip_range} on ports {ports}")
        console.print("[yellow]⚠ Network scanning not fully implemented yet[/yellow]")
        return []
