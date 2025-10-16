"""
Enhanced Security Analyzer with Compliance Mapping
"""

import asyncio
import sys
from pathlib import Path
from typing import List
from datetime import datetime

from rich.console import Console

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import MCPServer, Vulnerability, Severity
from utils.logger import get_logger
from checks.cors import check_cors_misconfiguration
from checks.rate_limiting import check_rate_limiting
from checks.injection import check_sql_injection, check_command_injection, check_path_traversal
from compliance.mapper import ComplianceMapper

console = Console()
logger = get_logger("analyzer")


class SecurityAnalyzer:
    """Analyzes MCP servers for security vulnerabilities with compliance mapping"""
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.compliance_mapper = ComplianceMapper()
    
    async def scan(self, server: MCPServer) -> List[Vulnerability]:
        """
        Perform security analysis on an MCP server with compliance mapping
        
        Args:
            server: MCPServer to analyze
            
        Returns:
            List of vulnerabilities found with compliance mappings
        """
        logger.info(f"Starting security analysis of {server.url}")
        
        self.vulnerabilities = []
        
        # Run all security checks
        await self._check_authentication(server)
        await self._check_encryption(server)
        await self._check_tools_exposure(server)
        await self._check_configuration(server)
        await self._check_cors(server)
        await self._check_rate_limiting(server)
        await self._check_injection_attacks(server)
        
        # Add compliance mappings to all vulnerabilities
        self._add_compliance_mappings()
        
        logger.info(f"Analysis complete: {len(self.vulnerabilities)} issues found")
        
        return self.vulnerabilities
    
    def _add_compliance_mappings(self):
        """Add compliance framework mappings to all vulnerabilities"""
        for vuln in self.vulnerabilities:
            frameworks = self.compliance_mapper.get_frameworks(vuln.id)
            
            for framework in frameworks:
                controls = self.compliance_mapper.get_controls(vuln.id, framework)
                control_dicts = [c.to_dict() for c in controls]
                vuln.add_compliance_mapping(framework.value, control_dicts)
        
        logger.debug(f"Added compliance mappings to {len(self.vulnerabilities)} vulnerabilities")
    
    async def _check_injection_attacks(self, server: MCPServer):
        """Check for injection vulnerabilities"""
        sql_vuln = await check_sql_injection(server)
        if sql_vuln:
            self.vulnerabilities.append(sql_vuln)
            logger.warning(f"Found: {sql_vuln.title}")
        
        cmd_vuln = await check_command_injection(server)
        if cmd_vuln:
            self.vulnerabilities.append(cmd_vuln)
            logger.warning(f"Found: {cmd_vuln.title}")
        
        path_vuln = await check_path_traversal(server)
        if path_vuln:
            self.vulnerabilities.append(path_vuln)
            logger.warning(f"Found: {path_vuln.title}")
    
    async def _check_cors(self, server: MCPServer):
        """Check for CORS misconfigurations"""
        cors_vuln = await check_cors_misconfiguration(server)
        if cors_vuln:
            self.vulnerabilities.append(cors_vuln)
            logger.warning(f"Found: {cors_vuln.title}")
    
    async def _check_rate_limiting(self, server: MCPServer):
        """Check for rate limiting and DoS protection"""
        rate_vuln = await check_rate_limiting(server)
        if rate_vuln:
            self.vulnerabilities.append(rate_vuln)
            logger.warning(f"Found: {rate_vuln.title}")
    
    async def _check_authentication(self, server: MCPServer):
        """Check for authentication issues"""
        
        if not server.has_authentication:
            vuln = Vulnerability.create(
                id="MCP-AUTH-001",
                title="Missing Authentication",
                description=(
                    f"The MCP server at {server.url} does not require authentication. "
                    "Any client can connect and access all available tools and resources."
                ),
                severity=Severity.CRITICAL,
                category="Authentication",
                remediation=(
                    "Implement authentication mechanism such as:\n"
                    "- API keys\n"
                    "- OAuth 2.0\n"
                    "- Mutual TLS (mTLS)\n"
                    "- JWT tokens"
                ),
                evidence=[
                    f"Server URL: {server.url}",
                    "Successfully connected without credentials",
                    f"Available tools: {len(server.tools)}",
                    f"Available resources: {len(server.resources)}"
                ],
                affected_component="MCP Server Authentication",
                cwe_id="CWE-306",
                cvss_score=9.8
            )
            
            self.vulnerabilities.append(vuln)
            logger.warning(f"Found: {vuln.title}")
    
    async def _check_encryption(self, server: MCPServer):
        """Check for encryption issues"""
        
        if not server.has_encryption:
            vuln = Vulnerability.create(
                id="MCP-CRYPTO-001",
                title="Unencrypted Connection",
                description=(
                    f"The MCP server at {server.url} does not use TLS/SSL encryption. "
                    "All communication is transmitted in plaintext, allowing attackers to "
                    "intercept sensitive data including credentials and API responses."
                ),
                severity=Severity.HIGH,
                category="Encryption",
                remediation=(
                    "Enable TLS/SSL encryption:\n"
                    "- Use HTTPS instead of HTTP\n"
                    "- Install valid SSL certificate\n"
                    "- Configure TLS 1.2 or higher\n"
                    "- Disable weak cipher suites"
                ),
                evidence=[
                    f"Server URL: {server.url}",
                    "Protocol: HTTP (unencrypted)",
                    "Traffic can be intercepted"
                ],
                affected_component="Transport Layer",
                cwe_id="CWE-319",
                cvss_score=7.5
            )
            
            self.vulnerabilities.append(vuln)
            logger.warning(f"Found: {vuln.title}")
    
    async def _check_tools_exposure(self, server: MCPServer):
        """Check for dangerous tool exposure"""
        
        if not server.tools:
            return
        
        dangerous_tools = []
        dangerous_patterns = [
            "execute", "exec", "shell", "command", "run",
            "read_file", "write_file", "delete",
            "sql", "database", "query"
        ]
        
        for tool in server.tools:
            tool_lower = tool.lower()
            for pattern in dangerous_patterns:
                if pattern in tool_lower:
                    dangerous_tools.append(tool)
                    break
        
        if dangerous_tools:
            vuln = Vulnerability.create(
                id="MCP-AUTHZ-001",
                title="Dangerous Tools Exposed Without Authorization",
                description=(
                    f"The MCP server exposes {len(dangerous_tools)} potentially dangerous "
                    f"tools without proper authorization controls. Combined with missing "
                    f"authentication, these tools can be abused for system compromise."
                ),
                severity=Severity.CRITICAL if not server.has_authentication else Severity.HIGH,
                category="Authorization",
                remediation=(
                    "Implement proper authorization:\n"
                    "- Role-based access control (RBAC)\n"
                    "- Principle of least privilege\n"
                    "- Input validation for all tools\n"
                    "- Audit logging for tool usage"
                ),
                evidence=[
                    f"Dangerous tools found: {', '.join(dangerous_tools)}",
                    f"Total tools exposed: {len(server.tools)}",
                    f"Authentication required: {server.has_authentication}"
                ],
                affected_component="Tool Access Control",
                cwe_id="CWE-285",
                cvss_score=9.1 if not server.has_authentication else 7.3
            )
            
            self.vulnerabilities.append(vuln)
            logger.warning(f"Found: {vuln.title}")
    
    async def _check_configuration(self, server: MCPServer):
        """Check for configuration issues"""
        
        default_ports = [3000, 8080, 5000]
        if server.port in default_ports:
            vuln = Vulnerability.create(
                id="MCP-CONFIG-001",
                title="Default Port Configuration",
                description=(
                    f"The MCP server is running on a default port ({server.port}). "
                    "This makes it easier for attackers to discover and target the server."
                ),
                severity=Severity.LOW,
                category="Configuration",
                remediation=(
                    "Change to a non-standard port:\n"
                    "- Use a random high port (>10000)\n"
                    "- Update firewall rules accordingly\n"
                    "- Document the port change"
                ),
                evidence=[
                    f"Current port: {server.port}",
                    f"Default port detected"
                ],
                affected_component="Server Configuration"
            )
            
            self.vulnerabilities.append(vuln)
            logger.info(f"Found: {vuln.title}")
        
        if server.version:
            vuln = Vulnerability.create(
                id="MCP-INFO-001",
                title="Version Information Disclosure",
                description=(
                    f"The server discloses its version ({server.version}), which can help "
                    "attackers identify known vulnerabilities in that specific version."
                ),
                severity=Severity.INFO,
                category="Information Disclosure",
                remediation=(
                    "Minimize information disclosure:\n"
                    "- Remove or obfuscate version headers\n"
                    "- Use generic error messages\n"
                    "- Keep software updated regardless"
                ),
                evidence=[
                    f"Disclosed version: {server.version}"
                ],
                affected_component="Server Headers"
            )
            
            self.vulnerabilities.append(vuln)
            logger.info(f"Found: {vuln.title}")
