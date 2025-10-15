"""
Tests for MCPServer model
"""

import pytest
from src.models import MCPServer


def test_server_creation():
    """Test creating an MCP server"""
    server = MCPServer(
        host="localhost",
        port=3000,
        protocol="http"
    )
    
    assert server.host == "localhost"
    assert server.port == 3000
    assert server.protocol == "http"


def test_server_url_property():
    """Test server URL generation"""
    server = MCPServer(host="example.com", port=8080, protocol="https")
    assert server.url == "https://example.com:8080"


def test_server_from_url():
    """Test creating server from URL"""
    server = MCPServer.from_url("http://test.com:3000")
    
    assert server.host == "test.com"
    assert server.port == 3000
    assert server.protocol == "http"


def test_server_is_secure():
    """Test security check"""
    # Insecure server
    insecure = MCPServer(
        host="localhost", port=3000,
        has_authentication=False,
        has_encryption=False
    )
    assert insecure.is_secure == False
    
    # Secure server
    secure = MCPServer(
        host="localhost", port=3000,
        has_authentication=True,
        has_encryption=True
    )
    assert secure.is_secure == True


def test_server_with_tools_and_resources():
    """Test server with tools and resources"""
    server = MCPServer(
        host="localhost",
        port=3000,
        tools=["read_file", "execute_command"],
        resources=["file:///etc/passwd"]
    )
    
    assert len(server.tools) == 2
    assert len(server.resources) == 1
    assert "read_file" in server.tools


def test_server_to_dict():
    """Test converting server to dictionary"""
    server = MCPServer(
        host="test.com",
        port=5000,
        name="Test Server",
        version="1.0.0"
    )
    
    server_dict = server.to_dict()
    
    assert isinstance(server_dict, dict)
    assert server_dict["host"] == "test.com"
    assert server_dict["name"] == "Test Server"
