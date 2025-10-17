#!/usr/bin/env python3
"""Test network scanner"""
import asyncio
from src.scanner.network_scanner import NetworkScanner

async def main():
    scanner = NetworkScanner(max_concurrent=10)
    
    # Scan localhost range (safe test)
    print("🔍 Testing network scanner on localhost...")
    results = await scanner.scan_cidr("127.0.0.0/29", [3000, 8000, 8080])
    
    print(f"\n✅ Scan complete!")
    print(f"Found {len(results)} open ports:")
    for r in results:
        print(f"  - {r['host']}:{r['port']}")

if __name__ == "__main__":
    asyncio.run(main())
