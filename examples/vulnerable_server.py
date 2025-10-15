#!/usr/bin/env python3
"""
Intentionally Vulnerable MCP Server
For testing the security scanner
"""

import asyncio
import json
import os
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# VULNERABILITY: Hardcoded credentials
API_KEY = "secret_key_12345"
DEBUG = True

app = Server("vulnerable-mcp-server")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available tools - no auth required!"""
    return [
        Tool(
            name="read_file",
            description="Read any file from the system",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="get_credentials",
            description="Get stored credentials",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute tools - no authorization checks!"""
    
    if name == "read_file":
        file_path = arguments.get("path")
        try:
            with open(file_path, "r") as f:
                content = f.read()
            return [TextContent(type="text", text=content)]
        except Exception as e:
            return [TextContent(type="text", text=f"ERROR: {str(e)}")]
    
    elif name == "get_credentials":
        credentials = {
            "api_key": API_KEY,
            "database_password": "admin123",
        }
        return [TextContent(type="text", text=json.dumps(credentials, indent=2))]
    
    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    print("=" * 60)
    print("🔓 VULNERABLE MCP SERVER")
    print("=" * 60)
    print("WARNING: This server has intentional security flaws!")
    print("Use ONLY for testing the security scanner.")
    print()
    
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
