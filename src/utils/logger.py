"""
Logging utilities for MCP Security Scanner
Provides colored console output and file logging
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

console = Console()


class ScannerLogger:
    """Custom logger for the security scanner"""
    
    def __init__(self, name: str = "mcp-scanner", level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
        
        # Rich handler for console output
        console_handler = RichHandler(
            console=console,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
        )
        console_handler.setLevel(logging.DEBUG)
        
        # Format for console
        console_format = "%(message)s"
        console_handler.setFormatter(logging.Formatter(console_format))
        
        self.logger.addHandler(console_handler)
    
    def add_file_handler(self, log_file: Path):
        """Add file handler for persistent logging"""
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Detailed format for file
        file_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        file_handler.setFormatter(logging.Formatter(file_format))
        
        self.logger.addHandler(file_handler)
    
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(message)


def setup_logger(
    name: str = "mcp-scanner",
    level: str = "INFO",
    log_file: Optional[Path] = None
) -> ScannerLogger:
    """
    Set up and return a configured logger
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for logging
    
    Returns:
        Configured ScannerLogger instance
    """
    logger = ScannerLogger(name, level)
    
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        logger.add_file_handler(log_file)
    
    return logger


# Convenience functions
def get_logger(name: str = "mcp-scanner") -> ScannerLogger:
    """Get or create a logger instance"""
    return ScannerLogger(name)
