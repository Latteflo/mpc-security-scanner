"""
MCP Server data model
Represents an MCP server and its metadata
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from pydantic import BaseModel, Field


class MCPServer(BaseModel):
    """Represents an MCP server"""
    
    # Connection details
    host: str = Field(description="Server hostname or IP")
    port: int = Field(description="Server port")
    protocol: str = Field(default="http", description="Protocol (http/https/stdio)")
    
    # Server information
    name: Optional[str] = Field(default=None, description="Server name")
    version: Optional[str] = Field(default=None, description="Server version")
    description: Optional[str] = Field(default=None, description="Server description")
    
    # Capabilities
    tools: List[str] = Field(default_factory=list, description="Available tools")
    resources: List[str] = Field(default_factory=list, description="Available resources")
    
    # Security posture
    has_authentication: bool = Field(default=False, description="Has authentication")
    has_encryption: bool = Field(default=False, description="Uses TLS/SSL")
    
    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.now)
    last_scanned: Optional[datetime] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @property
    def url(self) -> str:
        """Get full server URL"""
        return f"{self.protocol}://{self.host}:{self.port}"
    
    @property
    def is_secure(self) -> bool:
        """Check if server has basic security"""
        return self.has_authentication and self.has_encryption
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return self.model_dump()
    
    @classmethod
    def from_url(cls, url: str) -> "MCPServer":
        """Create server from URL"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        return cls(
            host=parsed.hostname or "localhost",
            port=parsed.port or 80,
            protocol=parsed.scheme or "http"
        )
