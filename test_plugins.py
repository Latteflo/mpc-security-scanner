#!/usr/bin/env python3
"""Test plugin system"""
import asyncio
from src.scanner.plugins import PluginManager
from src.models import MCPServer

async def main():
    print("🔌 Testing Plugin System\n")
    
    # Initialize plugin manager
    manager = PluginManager()
    
    # Load all plugins
    manager.load_plugins()
    
    # List loaded plugins
    print(f"📋 Loaded Plugins:")
    for plugin_info in manager.list_plugins():
        status = "✓ Enabled" if plugin_info['enabled'] else "✗ Disabled"
        print(f"  {status} {plugin_info['name']} v{plugin_info['version']}")
        print(f"      {plugin_info['description']}")
        print(f"      Author: {plugin_info['author']}\n")
    
    # Test on a mock server
    print("\n🧪 Testing plugins on mock server...")
    server = MCPServer(
        host="example.com",
        port=3000,
        protocol="http"
    )
    
    vulnerabilities = await manager.run_all_checks(server)
    
    print(f"\n✅ Plugin checks complete!")
    print(f"Found {len(vulnerabilities)} vulnerabilities from plugins")
    
    for vuln in vulnerabilities:
        print(f"\n  [{vuln.severity.value}] {vuln.title}")
        print(f"  {vuln.description[:80]}...")

if __name__ == "__main__":
    asyncio.run(main())
