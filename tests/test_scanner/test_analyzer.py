"""
Tests for SecurityAnalyzer
"""

import pytest
from src.scanner import SecurityAnalyzer
from src.models import MCPServer, Severity


@pytest.mark.asyncio
async def test_analyzer_initialization():
    """Test analyzer initialization"""
    analyzer = SecurityAnalyzer()
    assert analyzer.vulnerabilities == []


@pytest.mark.asyncio
async def test_analyze_insecure_server():
    """Test analyzing an insecure server"""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        tools=["read_file", "execute_command"],
        has_authentication=False,
        has_encryption=False
    )
    
    analyzer = SecurityAnalyzer()
    vulnerabilities = await analyzer.scan(server)
    
    # Should find multiple vulnerabilities
    assert len(vulnerabilities) > 0
    
    # Should find missing authentication
    auth_vulns = [v for v in vulnerabilities if "Authentication" in v.title]
    assert len(auth_vulns) > 0
    
    # Should find unencrypted connection
    crypto_vulns = [v for v in vulnerabilities if "Encryption" in v.title or "Unencrypted" in v.title]
    assert len(crypto_vulns) > 0


@pytest.mark.asyncio
async def test_analyze_dangerous_tools():
    """Test detection of dangerous tools"""
    server = MCPServer(
        host="localhost",
        port=3000,
        tools=["read_file", "execute_command", "sql_query"],
        has_authentication=False
    )
    
    analyzer = SecurityAnalyzer()
    vulnerabilities = await analyzer.scan(server)
    
    # Should detect dangerous tools
    tool_vulns = [v for v in vulnerabilities if "Tools" in v.title or "Authorization" in v.title]
    assert len(tool_vulns) > 0
    assert any(v.severity == Severity.CRITICAL for v in tool_vulns)


@pytest.mark.asyncio
async def test_analyze_default_port():
    """Test detection of default port"""
    server = MCPServer(
        host="localhost",
        port=3000,  # Default port
        has_authentication=True,
        has_encryption=True
    )
    
    analyzer = SecurityAnalyzer()
    vulnerabilities = await analyzer.scan(server)
    
    # Should detect default port
    port_vulns = [v for v in vulnerabilities if "Port" in v.title]
    assert len(port_vulns) > 0


@pytest.mark.asyncio
async def test_analyze_secure_server():
    """Test analyzing a more secure server"""
    server = MCPServer(
        host="secure.example.com",
        port=12345,  # Non-default port
        protocol="https",
        has_authentication=True,
        has_encryption=True,
        tools=["safe_operation"]  # No dangerous tools
    )
    
    analyzer = SecurityAnalyzer()
    vulnerabilities = await analyzer.scan(server)
    
    # Should find fewer/less severe vulnerabilities
    critical_vulns = [v for v in vulnerabilities if v.severity == Severity.CRITICAL]
    assert len(critical_vulns) == 0
