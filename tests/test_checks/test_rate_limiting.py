"""
Tests for rate limiting checks
"""

import pytest
from src.models import MCPServer
from src.checks.rate_limiting import check_rate_limiting


@pytest.mark.asyncio
async def test_rate_limiting_detection():
    """Test rate limiting detection"""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http"
    )
    
    # This will try to make real HTTP requests
    # In production, mock the responses
    vuln = await check_rate_limiting(server)
    
    # Test that it doesn't crash
    assert vuln is None or vuln.id.startswith("MCP-RATE")


@pytest.mark.asyncio  
async def test_rate_limiting_with_https():
    """Test rate limiting on HTTPS server"""
    server = MCPServer(
        host="example.com",
        port=443,
        protocol="https"
    )
    
    vuln = await check_rate_limiting(server)
    assert vuln is None or vuln.id.startswith("MCP-RATE")
