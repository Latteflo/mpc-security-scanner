"""
Network utilities for MCP Security Scanner
HTTP requests, port scanning, and network operations
"""

import asyncio
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
from rich.console import Console

console = Console()


async def check_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    Check if a port is open on a host
    
    Args:
        host: Target hostname or IP
        port: Port number
        timeout: Connection timeout
    
    Returns:
        True if port is open, False otherwise
    """
    try:
        # Create connection with timeout
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def scan_ports(host: str, ports: List[int], timeout: float = 3.0) -> List[int]:
    """
    Scan multiple ports on a host
    
    Args:
        host: Target hostname or IP
        ports: List of ports to scan
        timeout: Connection timeout per port
    
    Returns:
        List of open ports
    """
    tasks = [check_port_open(host, port, timeout) for port in ports]
    results = await asyncio.gather(*tasks)
    
    return [port for port, is_open in zip(ports, results) if is_open]


async def http_get(
    url: str,
    timeout: float = 30.0,
    headers: Optional[dict] = None
) -> Tuple[int, str, dict]:
    """
    Perform HTTP GET request
    
    Args:
        url: Target URL
        timeout: Request timeout
        headers: Optional HTTP headers
    
    Returns:
        Tuple of (status_code, response_text, response_headers)
    """
    default_headers = {
        "User-Agent": "MCP-Security-Scanner/0.1.0"
    }
    
    if headers:
        default_headers.update(headers)
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers=default_headers,
                ssl=False  # Allow self-signed certs for scanning
            ) as response:
                text = await response.text()
                return response.status, text, dict(response.headers)
    except asyncio.TimeoutError:
        raise TimeoutError(f"Request to {url} timed out")
    except aiohttp.ClientError as e:
        raise ConnectionError(f"Failed to connect to {url}: {str(e)}")


async def http_post(
    url: str,
    data: dict,
    timeout: float = 30.0,
    headers: Optional[dict] = None
) -> Tuple[int, str, dict]:
    """
    Perform HTTP POST request
    
    Args:
        url: Target URL
        data: POST data
        timeout: Request timeout
        headers: Optional HTTP headers
    
    Returns:
        Tuple of (status_code, response_text, response_headers)
    """
    default_headers = {
        "User-Agent": "MCP-Security-Scanner/0.1.0",
        "Content-Type": "application/json"
    }
    
    if headers:
        default_headers.update(headers)
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=data,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers=default_headers,
                ssl=False
            ) as response:
                text = await response.text()
                return response.status, text, dict(response.headers)
    except asyncio.TimeoutError:
        raise TimeoutError(f"Request to {url} timed out")
    except aiohttp.ClientError as e:
        raise ConnectionError(f"Failed to connect to {url}: {str(e)}")


def parse_url(url: str) -> Tuple[str, int, str]:
    """
    Parse URL into components
    
    Args:
        url: URL to parse
    
    Returns:
        Tuple of (host, port, path)
    """
    parsed = urlparse(url)
    
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    
    return host, port, path


def is_valid_ip(ip: str) -> bool:
    """
    Check if string is a valid IP address
    
    Args:
        ip: IP address string
    
    Returns:
        True if valid IP, False otherwise
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address
    
    Args:
        hostname: Hostname to resolve
    
    Returns:
        IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
