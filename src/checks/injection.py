"""
Input Validation and Injection Attack Checks
Tests for SQL injection, command injection, and path traversal
"""

import sys
from pathlib import Path
from typing import Optional, List

# Fix imports
sys.path.insert(0, str(Path(__file__).parent.parent))
from models import Vulnerability, Severity, MCPServer
from utils import http_post
from utils.logger import get_logger

logger = get_logger("injection")


async def check_sql_injection(server: MCPServer) -> Optional[Vulnerability]:
    """
    Check for SQL injection vulnerabilities in MCP tools
    
    Args:
        server: MCPServer to check
        
    Returns:
        Vulnerability if SQL injection found, None otherwise
    """
    
    if not server.tools:
        return None
    
    try:
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' UNION SELECT NULL--",
            "admin'--",
            "' OR 1=1--"
        ]
        
        sql_tools = []
        
        # Check if any tools accept SQL-like parameters
        for tool in server.tools:
            tool_lower = tool.lower()
            if any(keyword in tool_lower for keyword in ["sql", "query", "database", "select", "search"]):
                sql_tools.append(tool)
        
        if sql_tools:
            # Try to test for SQL injection
            for tool in sql_tools:
                for payload in sql_payloads[:2]:  # Test first 2 payloads
                    try:
                        request_data = {
                            "jsonrpc": "2.0",
                            "method": f"tools/call",
                            "params": {
                                "name": tool,
                                "arguments": {
                                    "query": payload,
                                    "input": payload,
                                    "search": payload
                                }
                            },
                            "id": 1
                        }
                        
                        status, text, _ = await http_post(
                            server.url,
                            request_data,
                            timeout=5.0
                        )
                        
                        # Check for SQL error messages in response
                        sql_errors = [
                            "sql syntax",
                            "mysql",
                            "postgresql",
                            "sqlite",
                            "syntax error",
                            "unclosed quotation",
                            "quoted string not properly terminated"
                        ]
                        
                        if any(error in text.lower() for error in sql_errors):
                            return Vulnerability.create(
                                id="MCP-INJ-001",
                                title="SQL Injection Vulnerability Detected",
                                description=(
                                    f"The MCP server at {server.url} appears vulnerable to SQL injection "
                                    f"in the tool '{tool}'. SQL error messages were returned when testing "
                                    "with injection payloads, indicating insufficient input validation."
                                ),
                                severity=Severity.CRITICAL,
                                category="Injection",
                                remediation=(
                                    "Fix SQL injection vulnerabilities:\n"
                                    "- Use parameterized queries (prepared statements)\n"
                                    "- Never concatenate user input into SQL\n"
                                    "- Implement input validation and sanitization\n"
                                    "- Use ORM frameworks when possible\n"
                                    "- Apply principle of least privilege to database users\n"
                                    "- Use stored procedures with parameterized inputs"
                                ),
                                evidence=[
                                    f"Vulnerable tool: {tool}",
                                    f"Test payload: {payload}",
                                    "SQL error messages detected in response",
                                    f"Response indicates SQL syntax errors"
                                ],
                                affected_component=f"Tool: {tool}",
                                cwe_id="CWE-89",
                                cvss_score=9.8
                            )
                    except (ConnectionError, TimeoutError) as e:
                        logger.debug(f"Connection error testing {tool}: {e}")
                        continue
                    except Exception as e:
                        logger.debug(f"Unexpected error testing {tool}: {e}")
                        continue
            
            # If SQL tools exist but no injection found, still warn about potential
            return Vulnerability.create(
                id="MCP-INJ-002",
                title="Potential SQL Injection Risk",
                description=(
                    f"The MCP server at {server.url} exposes SQL-related tools ({', '.join(sql_tools)}) "
                    "which may be vulnerable to SQL injection if input validation is not properly implemented."
                ),
                severity=Severity.MEDIUM,
                category="Injection",
                remediation=(
                    "Ensure SQL injection protection:\n"
                    "- Review all SQL-related tools for proper input validation\n"
                    "- Use parameterized queries exclusively\n"
                    "- Implement comprehensive input sanitization\n"
                    "- Add security testing to your CI/CD pipeline"
                ),
                evidence=[
                    f"SQL-related tools found: {', '.join(sql_tools)}",
                    "Tools may accept SQL queries as input",
                    "Input validation status unknown"
                ],
                affected_component="SQL Tools",
                cwe_id="CWE-89"
            )
        
        return None
        
    except Exception as e:
        logger.debug(f"SQL injection check error for {server.url}: {str(e)}")
        return None


async def check_command_injection(server: MCPServer) -> Optional[Vulnerability]:
    """
    Check for command injection vulnerabilities
    
    Args:
        server: MCPServer to check
        
    Returns:
        Vulnerability if command injection found, None otherwise
    """
    
    if not server.tools:
        return None
    
    try:
        # Command injection payloads
        cmd_payloads = [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(uname -a)"
        ]
        
        cmd_tools = []
        
        # Check for command execution tools
        for tool in server.tools:
            tool_lower = tool.lower()
            if any(keyword in tool_lower for keyword in ["exec", "execute", "command", "shell", "run", "system"]):
                cmd_tools.append(tool)
        
        if cmd_tools:
            # Test for command injection
            for tool in cmd_tools:
                for payload in cmd_payloads[:2]:  # Test first 2 payloads
                    try:
                        request_data = {
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {
                                "name": tool,
                                "arguments": {
                                    "command": f"echo test{payload}",
                                    "cmd": f"test{payload}",
                                    "input": payload
                                }
                            },
                            "id": 1
                        }
                        
                        status, text, _ = await http_post(
                            server.url,
                            request_data,
                            timeout=5.0
                        )
                        
                        # Check for command execution indicators
                        cmd_indicators = [
                            "root:",
                            "uid=",
                            "gid=",
                            "/bin/",
                            "/usr/",
                            "Linux",
                            "Darwin"
                        ]
                        
                        if any(indicator in text for indicator in cmd_indicators):
                            return Vulnerability.create(
                                id="MCP-INJ-003",
                                title="Command Injection Vulnerability Detected",
                                description=(
                                    f"The MCP server at {server.url} is vulnerable to command injection "
                                    f"in the tool '{tool}'. Injected commands were executed successfully, "
                                    "allowing arbitrary system command execution."
                                ),
                                severity=Severity.CRITICAL,
                                category="Injection",
                                remediation=(
                                    "Fix command injection vulnerabilities:\n"
                                    "- Never pass user input directly to system commands\n"
                                    "- Use allowlists for permitted commands\n"
                                    "- Escape shell metacharacters if shell execution is required\n"
                                    "- Use language-specific APIs instead of shell commands\n"
                                    "- Implement strict input validation\n"
                                    "- Run with minimal privileges"
                                ),
                                evidence=[
                                    f"Vulnerable tool: {tool}",
                                    f"Test payload: {payload}",
                                    "Command execution indicators detected",
                                    "Arbitrary command execution possible"
                                ],
                                affected_component=f"Tool: {tool}",
                                cwe_id="CWE-78",
                                cvss_score=9.8
                            )
                    except (ConnectionError, TimeoutError) as e:
                        logger.debug(f"Connection error testing {tool}: {e}")
                        continue
                    except Exception as e:
                        logger.debug(f"Unexpected error testing {tool}: {e}")
                        continue
            
            # Warn about command execution tools
            return Vulnerability.create(
                id="MCP-INJ-004",
                title="Command Execution Tools Exposed",
                description=(
                    f"The MCP server at {server.url} exposes command execution tools "
                    f"({', '.join(cmd_tools)}). These are high-risk tools that could allow "
                    "command injection if not properly secured."
                ),
                severity=Severity.HIGH,
                category="Injection",
                remediation=(
                    "Secure command execution tools:\n"
                    "- Implement strict input validation\n"
                    "- Use allowlists for permitted commands\n"
                    "- Never execute shell commands with user input\n"
                    "- Consider removing or restricting these tools\n"
                    "- Require authentication and authorization\n"
                    "- Log all command execution attempts"
                ),
                evidence=[
                    f"Command execution tools: {', '.join(cmd_tools)}",
                    "High-risk functionality exposed",
                    "Potential for system compromise"
                ],
                affected_component="Command Execution Tools",
                cwe_id="CWE-78",
                cvss_score=8.1
            )
        
        return None
        
    except Exception as e:
        logger.debug(f"Command injection check error for {server.url}: {str(e)}")
        return None


async def check_path_traversal(server: MCPServer) -> Optional[Vulnerability]:
    """
    Check for path traversal vulnerabilities
    
    Args:
        server: MCPServer to check
        
    Returns:
        Vulnerability if path traversal found, None otherwise
    """
    
    if not server.tools:
        return None
    
    try:
        # Path traversal payloads
        path_payloads = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        file_tools = []
        
        # Check for file access tools
        for tool in server.tools:
            tool_lower = tool.lower()
            if any(keyword in tool_lower for keyword in ["file", "read", "write", "path", "document", "upload", "download"]):
                file_tools.append(tool)
        
        if file_tools:
            # Test for path traversal
            for tool in file_tools:
                for payload in path_payloads[:2]:
                    try:
                        request_data = {
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {
                                "name": tool,
                                "arguments": {
                                    "path": payload,
                                    "file": payload,
                                    "filename": payload
                                }
                            },
                            "id": 1
                        }
                        
                        status, text, _ = await http_post(
                            server.url,
                            request_data,
                            timeout=5.0
                        )
                        
                        # Check for system file content
                        system_indicators = [
                            "root:x:",
                            "/bin/bash",
                            "/bin/sh",
                            "daemon:",
                            "nobody:"
                        ]
                        
                        if any(indicator in text for indicator in system_indicators):
                            return Vulnerability.create(
                                id="MCP-INJ-005",
                                title="Path Traversal Vulnerability Detected",
                                description=(
                                    f"The MCP server at {server.url} is vulnerable to path traversal "
                                    f"in the tool '{tool}'. System files were accessed using directory "
                                    "traversal sequences, allowing unauthorized file access."
                                ),
                                severity=Severity.CRITICAL,
                                category="Injection",
                                remediation=(
                                    "Fix path traversal vulnerabilities:\n"
                                    "- Validate and sanitize all file paths\n"
                                    "- Use allowlists of permitted directories\n"
                                    "- Reject paths containing '../' or '..\\'\n"
                                    "- Use canonical path resolution\n"
                                    "- Implement proper access controls\n"
                                    "- Restrict file access to specific directories"
                                ),
                                evidence=[
                                    f"Vulnerable tool: {tool}",
                                    f"Test payload: {payload}",
                                    "System file access detected",
                                    "Path traversal successful"
                                ],
                                affected_component=f"Tool: {tool}",
                                cwe_id="CWE-22",
                                cvss_score=8.6
                            )
                    except (ConnectionError, TimeoutError) as e:
                        logger.debug(f"Connection error testing {tool}: {e}")
                        continue
                    except Exception as e:
                        logger.debug(f"Unexpected error testing {tool}: {e}")
                        continue
            
            # Warn about file access tools
            return Vulnerability.create(
                id="MCP-INJ-006",
                title="File Access Tools With Potential Path Traversal Risk",
                description=(
                    f"The MCP server at {server.url} exposes file access tools "
                    f"({', '.join(file_tools)}) that may be vulnerable to path traversal "
                    "if input validation is insufficient."
                ),
                severity=Severity.MEDIUM,
                category="Injection",
                remediation=(
                    "Secure file access tools:\n"
                    "- Implement strict path validation\n"
                    "- Use allowlists for permitted directories\n"
                    "- Canonicalize paths before access\n"
                    "- Never trust user-supplied file paths\n"
                    "- Restrict file system access scope"
                ),
                evidence=[
                    f"File access tools: {', '.join(file_tools)}",
                    "Potential path traversal risk",
                    "Input validation status unknown"
                ],
                affected_component="File Access Tools",
                cwe_id="CWE-22"
            )
        
        return None
        
    except Exception as e:
        logger.debug(f"Path traversal check error for {server.url}: {str(e)}")
        return None
