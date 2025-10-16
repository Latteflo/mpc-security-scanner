"""
Enhanced Network Scanning Implementation for MCP Discovery
Scans CIDR ranges for MCP servers
"""

import asyncio
import ipaddress
import sys
from pathlib import Path
from typing import List

# Fix imports for when running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from models import MCPServer
from utils import check_port_open
from utils.logger import get_logger

logger = get_logger("network_scan")


class NetworkScanner:
    """Scans network ranges for MCP servers"""
    
    def __init__(self, timeout: float = 3.0, max_concurrent: int = 50):
        """
        Initialize network scanner
        
        Args:
            timeout: Connection timeout per port
            max_concurrent: Maximum concurrent connections
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_cidr(
        self,
        cidr: str,
        ports: List[int] = [3000, 3001, 8000, 8080, 5000, 5001]
    ) -> List[dict]:
        """
        Scan CIDR range for open ports
        
        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            ports: List of ports to scan
            
        Returns:
            List of dicts with {host, port} for open ports
        """
        logger.info(f"Scanning CIDR range: {cidr}")
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            logger.error(f"Invalid CIDR notation: {cidr}")
            return []
        
        # Calculate total scans
        total_hosts = network.num_addresses
        total_scans = total_hosts * len(ports)
        
        logger.info(f"Scanning {total_hosts} hosts on {len(ports)} ports ({total_scans} total checks)")
        
        # Create scan tasks
        tasks = []
        for host in network.hosts():
            for port in ports:
                tasks.append(self._scan_host_port(str(host), port))
        
        # Run with progress bar
        open_ports = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            
            task = progress.add_task(
                f"[cyan]Scanning {cidr}...",
                total=len(tasks)
            )
            
            # Process in batches
            batch_size = self.max_concurrent * 10
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                results = await asyncio.gather(*batch)
                
                for result in results:
                    if result:
                        open_ports.append(result)
                        logger.info(f"Found open port: {result['host']}:{result['port']}")
                
                progress.update(task, advance=len(batch))
        
        logger.info(f"Scan complete: {len(open_ports)} open ports found")
        return open_ports
    
    async def _scan_host_port(self, host: str, port: int) -> dict:
        """
        Scan a single host:port combination
        
        Args:
            host: IP address
            port: Port number
            
        Returns:
            Dict with host/port if open, None otherwise
        """
        async with self.semaphore:
            try:
                is_open = await check_port_open(host, port, self.timeout)
                if is_open:
                    return {"host": host, "port": port}
            except Exception as e:
                logger.debug(f"Error scanning {host}:{port}: {str(e)}")
        
        return None
    
    async def identify_mcp_servers(
        self,
        open_ports: List[dict],
        discovery
    ) -> List[MCPServer]:
        """
        Probe open ports to identify MCP servers
        
        Args:
            open_ports: List of {host, port} dicts
            discovery: MCPDiscovery instance for probing
            
        Returns:
            List of identified MCP servers
        """
        logger.info(f"Probing {len(open_ports)} open ports for MCP servers...")
        
        servers = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
        ) as progress:
            
            task = progress.add_task(
                "[cyan]Identifying MCP servers...",
                total=len(open_ports)
            )
            
            for open_port in open_ports:
                host = open_port["host"]
                port = open_port["port"]
                
                # Try HTTP first, then HTTPS
                for protocol in ["http", "https"]:
                    url = f"{protocol}://{host}:{port}"
                    
                    server = await discovery.probe_server(url)
                    if server:
                        servers.append(server)
                        logger.info(f"✓ MCP server found at {url}")
                        break
                
                progress.update(task, advance=1)
        
        logger.info(f"Identified {len(servers)} MCP servers")
        return servers


# Usage example
async def scan_network_for_mcp(cidr: str, ports: List[int] = None):
    """
    Convenience function to scan network for MCP servers
    
    Args:
        cidr: CIDR range to scan
        ports: Optional list of ports
        
    Returns:
        List of MCP servers found
    """
    from scanner.discovery import MCPDiscovery
    
    if ports is None:
        ports = [3000, 3001, 8000, 8080, 5000, 5001]
    
    # Phase 1: Port scan
    scanner = NetworkScanner()
    open_ports = await scanner.scan_cidr(cidr, ports)
    
    # Phase 2: MCP identification
    discovery = MCPDiscovery()
    servers = await scanner.identify_mcp_servers(open_ports, discovery)
    
    return servers
