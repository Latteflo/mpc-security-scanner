"""
Tests for network utilities
"""

import pytest
from src.utils.network import parse_url, is_valid_ip


def test_parse_url_http():
    """Test parsing HTTP URL"""
    host, port, path = parse_url("http://example.com/api")
    
    assert host == "example.com"
    assert port == 80
    assert path == "/api"


def test_parse_url_https():
    """Test parsing HTTPS URL"""
    host, port, path = parse_url("https://secure.example.com:8443/path")
    
    assert host == "secure.example.com"
    assert port == 8443
    assert path == "/path"


def test_parse_url_with_port():
    """Test parsing URL with explicit port"""
    host, port, path = parse_url("http://localhost:3000")
    
    assert host == "localhost"
    assert port == 3000


def test_is_valid_ip():
    """Test IP address validation"""
    assert is_valid_ip("192.168.1.1") == True
    assert is_valid_ip("10.0.0.1") == True
    assert is_valid_ip("127.0.0.1") == True
    
    assert is_valid_ip("not.an.ip") == False
    assert is_valid_ip("999.999.999.999") == False
    assert is_valid_ip("example.com") == False
