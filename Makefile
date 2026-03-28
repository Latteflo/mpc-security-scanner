.PHONY: help build run test clean scan shell demo

IMAGE_NAME := mcp-security-scanner
VERSION := latest
REPORTS_DIR := $(PWD)/reports

help:
	@echo "🔒 MCP Security Scanner - Docker Commands"
	@echo "=========================================="
	@echo ""
	@echo "Building:"
	@echo "  make build              - Build Docker image"
	@echo "  make build-test         - Build test server image"
	@echo ""
	@echo "Running:"
	@echo "  make run                - Show help"
	@echo "  make scan               - Interactive scan"
	@echo "  make demo               - Run demo scan"
	@echo "  make shell              - Open shell in container"
	@echo ""
	@echo "Docker Compose:"
	@echo "  make up                 - Start all services"
	@echo "  make down               - Stop all services"
	@echo "  make logs               - View logs"
	@echo ""
	@echo "Testing:"
	@echo "  make test               - Run tests in Docker"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean              - Clean up containers"
	@echo "  make clean-all          - Clean everything"
	@echo ""

build:
	@echo "🔨 Building Docker image..."
	docker build -t $(IMAGE_NAME):$(VERSION) .
	@echo "✅ Build complete!"

build-test:
	@echo "🔨 Building test server image..."
	docker build -f Dockerfile.test-server -t $(IMAGE_NAME)-test:$(VERSION) .
	@echo "✅ Test server image built!"

run:
	@docker run --rm $(IMAGE_NAME):$(VERSION)

scan:
	@echo "🔍 Enter target URL (e.g., http://localhost:3000):"
	@read target; \
	echo "📋 Select format (json/html/pdf/terminal) [default: html]:"; \
	read format; \
	format=$${format:-html}; \
	docker run --rm \
		-v $(REPORTS_DIR):/app/reports \
		--network host \
		$(IMAGE_NAME):$(VERSION) \
		scan --target $$target --format $$format --output reports/scan_$$(date +%Y%m%d_%H%M%S).$$format

demo:
	@echo "🎬 Running demo scan..."
	@docker run --rm \
		-v $(REPORTS_DIR):/app/reports \
		$(IMAGE_NAME):$(VERSION) \
		python test_scanner.py
	@echo "✅ Demo complete! Check reports/demo_scan.html"

shell:
	@echo "🐚 Opening shell in container..."
	@docker run --rm -it \
		-v $(PWD)/src:/app/src \
		-v $(REPORTS_DIR):/app/reports \
		--network host \
		$(IMAGE_NAME):$(VERSION) \
		bash

up:
	@echo "🚀 Starting services..."
	@docker-compose up -d
	@echo "✅ Services started!"
	@docker-compose ps

down:
	@echo "🛑 Stopping services..."
	@docker-compose down
	@echo "✅ Services stopped!"

logs:
	@docker-compose logs -f --tail=100

test:
	@echo "🧪 Running tests in Docker..."
	@docker run --rm \
		-v $(PWD)/tests:/app/tests \
		-v $(PWD)/src:/app/src \
		$(IMAGE_NAME):$(VERSION) \
		pytest -v
	@echo "✅ Tests complete!"

clean:
	@echo "🧹 Cleaning up..."
	@docker ps -aq -f name=mcp | xargs -r docker rm -f || true
	@echo "✅ Cleanup complete!"

clean-all: clean
	@echo "🧹 Cleaning reports..."
	@rm -rf reports/*.html reports/*.json reports/*.pdf || true
	@echo "✅ All clean!"
