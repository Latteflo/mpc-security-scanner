"""
Plugin System for MCP Security Scanner
Allows users to create custom security checks
"""

import importlib.util
import inspect
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Type, Dict, Any

# Fix imports for when running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from models import MCPServer, Vulnerability
from utils.logger import get_logger

logger = get_logger("plugins")


class SecurityCheckPlugin(ABC):
    """
    Base class for security check plugins
    
    All custom checks should inherit from this class
    """
    
    # Plugin metadata
    name: str = "Unnamed Plugin"
    version: str = "0.1.0"
    description: str = "No description"
    author: str = "Unknown"
    
    def __init__(self):
        """Initialize plugin"""
        self.enabled = True
    
    @abstractmethod
    async def check(self, server: MCPServer) -> Optional[Vulnerability]:
        """
        Perform security check
        
        Args:
            server: MCP server to check
            
        Returns:
            Vulnerability if found, None otherwise
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "enabled": self.enabled
        }


class PluginManager:
    """Manages security check plugins"""
    
    def __init__(self, plugin_dir: Optional[Path] = None):
        """
        Initialize plugin manager
        
        Args:
            plugin_dir: Directory containing plugin files
        """
        self.plugins: List[SecurityCheckPlugin] = []
        self.plugin_dir = plugin_dir or Path("plugins")
        self.plugin_classes: Dict[str, Type[SecurityCheckPlugin]] = {}
    
    def load_plugins(self):
        """Load all plugins from plugin directory"""
        if not self.plugin_dir.exists():
            logger.warning(f"Plugin directory not found: {self.plugin_dir}")
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            return
        
        logger.info(f"Loading plugins from {self.plugin_dir}")
        
        # Add plugin directory to path
        sys.path.insert(0, str(self.plugin_dir))
        
        # Load all .py files
        for plugin_file in self.plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            
            try:
                self._load_plugin_file(plugin_file)
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_file.name}: {str(e)}")
        
        logger.info(f"Loaded {len(self.plugins)} plugins")
    
    def _load_plugin_file(self, plugin_file: Path):
        """Load a single plugin file"""
        module_name = plugin_file.stem
        
        try:
            # Import the module
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, SecurityCheckPlugin) and 
                    obj is not SecurityCheckPlugin):
                    
                    # Instantiate plugin
                    plugin = obj()
                    self.plugins.append(plugin)
                    self.plugin_classes[plugin.name] = obj
                    
                    logger.info(f"✓ Loaded plugin: {plugin.name} v{plugin.version}")
        
        except Exception as e:
            logger.error(f"Error loading {plugin_file}: {str(e)}")
            raise
    
    async def run_all_checks(self, server: MCPServer) -> List[Vulnerability]:
        """
        Run all plugin checks on a server
        
        Args:
            server: MCP server to check
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        for plugin in self.plugins:
            if not plugin.enabled:
                continue
            
            try:
                logger.debug(f"Running plugin: {plugin.name}")
                vuln = await plugin.check(server)
                
                if vuln:
                    vulnerabilities.append(vuln)
                    logger.info(f"Plugin '{plugin.name}' found: {vuln.title}")
            
            except Exception as e:
                logger.error(f"Plugin '{plugin.name}' error: {str(e)}")
        
        return vulnerabilities
    
    def get_plugin(self, name: str) -> Optional[SecurityCheckPlugin]:
        """Get plugin by name"""
        for plugin in self.plugins:
            if plugin.name == name:
                return plugin
        return None
    
    def enable_plugin(self, name: str):
        """Enable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enabled = True
            logger.info(f"Enabled plugin: {name}")
    
    def disable_plugin(self, name: str):
        """Disable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enabled = False
            logger.info(f"Disabled plugin: {name}")
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins"""
        return [plugin.get_info() for plugin in self.plugins]
