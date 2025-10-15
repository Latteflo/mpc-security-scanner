"""
Tests for injection attack checks
"""

import pytest
from src.models import MCPServer
from src.checks.injection import check_sql_injection, check_command_injection, check_path_traversal


@pytest.mark.asyncio
async def test_sql_injection_with_sql_tools():
    """Test SQL injection detection with SQL tools"""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        tools=["sql_query", "database_search"]
    )
    
    vuln = await check_sql_injection(server)
    assert vuln is None or vuln.id.startswith("MCP-INJ")


@pytest.mark.asyncio
async def test_command_injection_with_exec_tools():
    """Test command injection detection with exec tools"""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        tools=["execute_command", "shell_exec"]
    )
    
    vuln = await check_command_injection(server)
    assert vuln is not None  # Should warn about command tools
    assert vuln.id in ["MCP-INJ-003", "MCP-INJ-004"]


@pytest.mark.asyncio
async def test_path_traversal_with_file_tools():
    """Test path traversal detection with file tools"""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        tools=["read_file", "write_file"]
    )
    
    vuln = await check_path_traversal(server)
    assert vuln is not None  # Should warn about file tools
    assert vuln.id in ["MCP-INJ-005", "MCP-INJ-006"]


@pytest.mark.asyncio
async def test_injection_with_no_tools():
    """Test injection checks with no tools"""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http",
        tools=[]
    )
    
    sql_vuln = await check_sql_injection(server)
    cmd_vuln = await check_command_injection(server)
    path_vuln = await check_path_traversal(server)
    
    assert sql_vuln is None
    assert cmd_vuln is None
    assert path_vuln is None
