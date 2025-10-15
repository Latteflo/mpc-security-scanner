"""
MCP Server Discovery Module
Finds and probes MCP servers
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
    
    def __init__(self):
        self.timeout = 10.0
    
    async def probe_server(self, target: str) -> Optional[MCPServer]:
        """
        Probe a target to see if it's an MCP server
        
        Args:
            target: URL or address to probe
            
        Returns:
            MCPServer object if found, None otherwise
        """
        logger.info(f"Probing target: {target}")
        
        # Parse the target
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        host, port, path = parse_url(target)
        
        # Try to detect MCP server
        server_info = await self._detect_mcp(target)
        
        if server_info:
            logger.info(f"✓ Found MCP server at {target}")
            return server_info
        
        logger.warning(f"✗ No MCP server found at {target}")
        return None
    
    async def _detect_mcp(self, url: str) -> Optional[MCPServer]:
        """
        Detect if URL is an MCP server by trying MCP protocol
        
        Args:
            url: URL to check
            
        Returns:
            MCPServer if detected, None otherwise
        """
        host, port, path = parse_url(url)
        protocol = "https" if url.startswith("https") else "http"
        
        # MCP uses JSON-RPC 2.0 protocol
        # Try to call the initialize method
        mcp_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-security-scanner",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            # Try MCP JSON-RPC endpoint
            status, response_text, headers = await http_post(
                url,
                mcp_request,
                timeout=self.timeout
            )
            
            # Check if response looks like MCP
            if status == 200:
                try:
                    response = json.loads(response_text)
                    
                    # Valid MCP response has jsonrpc and result/error
                    if "jsonrpc" in response and ("result" in response or "error" in response):
                        logger.info(f"✓ MCP protocol detected at {url}")
                        
                        # Extract server info from response
                        server = MCPServer(
                            host=host,
                            port=port,
                            protocol=protocol,
                            name=self._extract_server_name(response),
                            version=self._extract_server_version(response)
                        )
                        
                        # Try to get capabilities
                        await self._probe_capabilities(server)
                        
                        return server
                except json.JSONDecodeError:
                    pass
            
            # Try to detect from headers or response
            if "mcp" in response_text.lower() or "model-context-protocol" in response_text.lower():
                logger.info(f"✓ MCP mentions found in response from {url}")
                return MCPServer(
                    host=host,
                    port=port,
                    protocol=protocol,
                    name="Unknown MCP Server"
                )
        
        except Exception as e:
            logger.debug(f"Error probing {url}: {str(e)}")
        
        return None
    
    def _extract_server_name(self, response: dict) -> Optional[str]:
        """Extract server name from MCP response"""
        try:
            if "result" in response:
                server_info = response["result"].get("serverInfo", {})
                return server_info.get("name")
        except (KeyError, TypeError, AttributeError) as e:
            logger.debug(f"Could not extract server name: {e}")
        return None
    
    def _extract_server_version(self, response: dict) -> Optional[str]:
        """Extract server version from MCP response"""
        try:
            if "result" in response:
                server_info = response["result"].get("serverInfo", {})
                return server_info.get("version")
        except (KeyError, TypeError, AttributeError) as e:
            logger.debug(f"Could not extract server version: {e}")
        return None
    
    async def _probe_capabilities(self, server: MCPServer):
        """
        Probe server for available tools and resources
        
        Args:
            server: MCPServer to probe
        """
        url = server.url
        
        # List tools
        try:
            tools_request = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 2
            }
            
            status, response_text, _ = await http_post(
                url,
                tools_request,
                timeout=self.timeout
            )
            
            if status == 200:
                response = json.loads(response_text)
                if "result" in response and "tools" in response["result"]:
                    tools = response["result"]["tools"]
                    server.tools = [tool.get("name", "unknown") for tool in tools]
                    logger.info(f"Found {len(server.tools)} tools")
        except Exception as e:
            logger.debug(f"Error listing tools: {str(e)}")
        
        # List resources
        try:
            resources_request = {
                "jsonrpc": "2.0",
                "method": "resources/list",
                "id": 3
            }
            
            status, response_text, _ = await http_post(
                url,
                resources_request,
                timeout=self.timeout
            )
            
            if status == 200:
                response = json.loads(response_text)
                if "result" in response and "resources" in response["result"]:
                    resources = response["result"]["resources"]
                    server.resources = [res.get("uri", "unknown") for res in resources]
                    logger.info(f"Found {len(server.resources)} resources")
        except Exception as e:
            logger.debug(f"Error listing resources: {str(e)}")
        
        # Check for authentication
        server.has_authentication = await self._check_authentication(server)
        
        # Check for encryption
        server.has_encryption = url.startswith("https://")
    
    async def _check_authentication(self, server: MCPServer) -> bool:
        """
        Check if server requires authentication
        
        Args:
            server: Server to check
            
        Returns:
            True if authentication detected, False otherwise
        """
        # Try request without auth - if it works, no auth required
        try:
            test_request = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 999
            }
            
            status, response_text, headers = await http_post(
                server.url,
                test_request,
                timeout=5.0
            )
            
            # If we got a 401 or 403, authentication is required (good!)
            if status in [401, 403]:
                return True
            
            # If we got 200, check if we got actual data (bad - no auth!)
            if status == 200:
                try:
                    response = json.loads(response_text)
                    # If we got valid response without auth, no auth required
                    if "result" in response:
                        return False
                except json.JSONDecodeError as e:
                    logger.debug(f"Could not parse auth check response: {e}")
            
            # Check for auth headers
            if "www-authenticate" in str(headers).lower():
                return True
        
        except Exception as e:
            logger.debug(f"Auth check error: {str(e)}")
        
        # Default: assume no auth (vulnerability)
        return False
    
    async def network_scan(
        self,
        ip_range: str,
        ports: List[int] = [3000, 3001, 8000, 8080, 5000]
    ) -> List[MCPServer]:
        """
        Scan network range for MCP servers
        
        Args:
            ip_range: CIDR notation (e.g., "192.168.1.0/24")
            ports: List of ports to scan
            
        Returns:
            List of discovered MCP servers
        """
        logger.info(f"Scanning network: {ip_range} on ports {ports}")
        
        servers = []
        console.print("[yellow]⚠ Network scanning not fully implemented yet[/yellow]")
        console.print("[dim]This would scan the specified range for MCP servers[/dim]")
        
        return servers