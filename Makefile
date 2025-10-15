.PHONY: help build run test clean

help:
	@echo "🔒 MCP Security Scanner - Docker Commands"
	@echo "=========================================="
	@echo ""
	@echo "  make build        - Build Docker image"
	@echo "  make run          - Run scanner (show help)"
	@echo "  make scan         - Run interactive scan"
	@echo "  make shell        - Open shell in container"
	@echo "  make test         - Run tests"
	@echo "  make clean        - Clean up containers"
	@echo ""

build:
	@echo "🔨 Building Docker image..."
	docker build -t mcp-security-scanner:latest .
	@echo "✅ Build complete!"

run:
	docker run --rm mcp-security-scanner:latest

scan:
	@echo "🔍 Enter target URL (e.g., http://localhost:3000):"
	@read target; \
	docker run --rm \
		-v $(PWD)/reports:/app/reports \
		mcp-security-scanner:latest \
		scan --target $$target

shell:
	@echo "🐚 Opening shell in container..."
	docker run --rm -it \
		-v $(PWD)/src:/app/src \
		-v $(PWD)/reports:/app/reports \
		mcp-security-scanner:latest \
		bash

test:
	docker run --rm \
		mcp-security-scanner:latest \
		checks

clean:
	@echo "🧹 Cleaning up..."
	docker ps -aq -f name=mcp | xargs -r docker rm -f
	@echo "✅ Cleanup complete!"
