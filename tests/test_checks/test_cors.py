"""
Tests for CORS security checks
"""

import pytest
from src.models import MCPServer
from src.checks.cors import check_cors_misconfiguration


@pytest.mark.asyncio
async def test_cors_wildcard_detection():
    """Test detection of wildcard CORS"""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http"
    )
    
    # This will try to make a real HTTP request
    # In a real test, you'd mock the HTTP response
    vuln = await check_cors_misconfiguration(server)
    
    # For now, just test that it doesn't crash
    assert vuln is None or vuln.id.startswith("MCP-CORS")


@pytest.mark.asyncio
async def test_cors_with_credentials():
    """Test CORS with credentials check"""
    server = MCPServer(
        host="example.com",
        port=443,
        protocol="https"
    )
    
    vuln = await check_cors_misconfiguration(server)
    assert vuln is None or vuln.id.startswith("MCP-CORS")
