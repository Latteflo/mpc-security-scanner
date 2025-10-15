"""
Configuration management for MCP Security Scanner
Loads settings from files and environment variables
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field
from dotenv import load_dotenv


class ScanConfig(BaseModel):
    """Configuration for scanning operations"""
    
    timeout: int = Field(default=30, description="Request timeout in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    concurrent_scans: int = Field(default=5, description="Number of concurrent scans")
    user_agent: str = Field(
        default="MCP-Security-Scanner/0.1.0",
        description="User agent for HTTP requests"
    )


class ReportConfig(BaseModel):
    """Configuration for report generation"""
    
    output_dir: Path = Field(default=Path("reports"), description="Output directory")
    format: str = Field(default="json", description="Default report format")
    include_raw_data: bool = Field(default=False, description="Include raw scan data")


class LoggingConfig(BaseModel):
    """Configuration for logging"""
    
    level: str = Field(default="INFO", description="Logging level")
    file: Optional[Path] = Field(default=None, description="Log file path")
    console: bool = Field(default=True, description="Enable console logging")


class Config(BaseModel):
    """Main configuration class"""
    
    scan: ScanConfig = Field(default_factory=ScanConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    @classmethod
    def load(cls, config_file: Optional[Path] = None) -> "Config":
        """
        Load configuration from file and environment
        
        Args:
            config_file: Optional path to YAML config file
        
        Returns:
            Config instance
        """
        # Load environment variables
        load_dotenv()
        
        # Start with defaults
        config_data: Dict[str, Any] = {}
        
        # Load from file if provided
        if config_file and config_file.exists():
            with open(config_file, "r") as f:
                config_data = yaml.safe_load(f) or {}
        
        # Override with environment variables
        if os.getenv("SCANNER_TIMEOUT"):
            config_data.setdefault("scan", {})["timeout"] = int(os.getenv("SCANNER_TIMEOUT"))
        
        if os.getenv("LOG_LEVEL"):
            config_data.setdefault("logging", {})["level"] = os.getenv("LOG_LEVEL")
        
        if os.getenv("REPORT_FORMAT"):
            config_data.setdefault("report", {})["format"] = os.getenv("REPORT_FORMAT")
        
        return cls(**config_data)
    
    def save(self, config_file: Path):
        """
        Save configuration to YAML file
        
        Args:
            config_file: Path to save config
        """
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, "w") as f:
            yaml.dump(self.model_dump(), f, default_flow_style=False)


def load_config(config_file: Optional[Path] = None) -> Config:
    """
    Load configuration (convenience function)
    
    Args:
        config_file: Optional path to config file
    
    Returns:
        Config instance
    """
    return Config.load(config_file)
