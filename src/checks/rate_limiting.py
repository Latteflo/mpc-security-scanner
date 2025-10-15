"""
Rate Limiting and DoS Protection Checks
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("rate_limiting")


async def check_rate_limiting(server: MCPServer) -> Optional[Vulnerability]:
    """
    Check for rate limiting and DoS protection
    
    Args:
        server: MCPServer to check
        
    Returns:
        Vulnerability if rate limiting issue found, None otherwise
    """
    
    try:
        num_requests = 50
        request_data = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        }
        
        logger.debug(f"Testing rate limiting with {num_requests} requests to {server.url}")
        
        successful_requests = 0
        rate_limited = False
        
        start_time = asyncio.get_event_loop().time()
        
        for i in range(num_requests):
            try:
                status, text, headers = await http_post(
                    server.url,
                    request_data,
                    timeout=5.0
                )
                
                if status in [429, 503]:
                    rate_limited = True
                    break
                elif status == 200:
                    successful_requests += 1
                    
            except asyncio.TimeoutError:
                break
            except Exception:
                break
        
        end_time = asyncio.get_event_loop().time()
        duration = end_time - start_time
        
        if successful_requests >= 40 and not rate_limited:
            requests_per_second = successful_requests / duration if duration > 0 else 0
            
            return Vulnerability.create(
                id="MCP-RATE-001",
                title="No Rate Limiting Detected",
                description=(
                    f"The MCP server at {server.url} does not implement rate limiting. "
                    f"Successfully sent {successful_requests} requests in {duration:.2f} seconds "
                    f"({requests_per_second:.1f} req/s) without throttling. This makes the server "
                    "vulnerable to denial-of-service (DoS) attacks, brute-force attacks, and resource exhaustion."
                ),
                severity=Severity.HIGH,
                category="Rate Limiting",
                remediation=(
                    "Implement rate limiting:\n"
                    "- Use token bucket or leaky bucket algorithm\n"
                    "- Limit requests per IP address (e.g., 100 req/min)\n"
                    "- Return HTTP 429 (Too Many Requests) when limit exceeded\n"
                    "- Add Retry-After header to rate limit responses\n"
                    "- Consider adaptive rate limiting based on user behavior\n"
                    "- Implement request queuing for legitimate traffic spikes"
                ),
                evidence=[
                    f"Sent {successful_requests} requests in {duration:.2f} seconds",
                    f"Average: {requests_per_second:.1f} requests/second",
                    "No rate limiting detected",
                    "Server accepted all requests"
                ],
                affected_component="Rate Limiting",
                cwe_id="CWE-770",
                cvss_score=7.5
            )
        
        elif successful_requests >= 30 and rate_limited:
            return Vulnerability.create(
                id="MCP-RATE-002",
                title="Weak Rate Limiting Configuration",
                description=(
                    f"The MCP server at {server.url} implements rate limiting but allows "
                    f"{successful_requests} requests before throttling. This threshold may be "
                    "too permissive and could still allow abuse or resource exhaustion."
                ),
                severity=Severity.MEDIUM,
                category="Rate Limiting",
                remediation=(
                    "Strengthen rate limiting:\n"
                    "- Reduce rate limit threshold (e.g., 10-20 req/min per IP)\n"
                    "- Implement progressive delays\n"
                    "- Add CAPTCHA for suspicious behavior\n"
                    "- Monitor and adjust based on traffic patterns\n"
                    "- Consider different limits for authenticated vs anonymous users"
                ),
                evidence=[
                    f"Accepted {successful_requests} requests before rate limiting",
                    f"Duration: {duration:.2f} seconds",
                    "Threshold may be too high"
                ],
                affected_component="Rate Limiting",
                cwe_id="CWE-770"
            )
        
        if rate_limited:
            logger.info(f"Rate limiting detected at {server.url}")
        
        logger.debug(f"Rate limiting check passed for {server.url}")
        return None
        
    except Exception as e:
        logger.debug(f"Rate limiting check error for {server.url}: {str(e)}")
        return None
