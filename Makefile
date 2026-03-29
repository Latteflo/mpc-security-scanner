.PHONY: help build build-test run scan demo shell up down logs test clean clean-all

IMAGE_NAME  := mcp-security-scanner
VERSION     := latest
REPORTS_DIR := $(PWD)/reports
COMPOSE     := docker-compose -f docker/docker-compose.yml

help:
	@echo "MCP Security Scanner"
	@echo "===================="
	@echo ""
	@echo "Building:"
	@echo "  make build         Build the scanner Docker image"
	@echo "  make build-test    Build the test server image"
	@echo ""
	@echo "Running:"
	@echo "  make scan          Interactive scan (prompts for target URL)"
	@echo "  make demo          Run a demo scan against the test server"
	@echo "  make shell         Open a shell in the scanner container"
	@echo ""
	@echo "Docker Compose:"
	@echo "  make up            Start scanner + test server"
	@echo "  make down          Stop all services"
	@echo "  make logs          Tail service logs"
	@echo ""
	@echo "Testing:"
	@echo "  make test          Run pytest suite in Docker"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean         Remove stopped containers"
	@echo "  make clean-all     Remove containers and generated reports"
	@echo ""

build:
	docker build -f docker/Dockerfile -t $(IMAGE_NAME):$(VERSION) .

build-test:
	docker build -f docker/Dockerfile.test-server -t $(IMAGE_NAME)-test:$(VERSION) .

run:
	docker run --rm $(IMAGE_NAME):$(VERSION)

scan:
	@echo "Enter target URL (e.g., http://localhost:3000):"
	@read target; \
	echo "Select format (json/html/pdf/terminal) [default: html]:"; \
	read format; \
	format=$${format:-html}; \
	docker run --rm \
		-v $(REPORTS_DIR):/app/reports \
		--network host \
		$(IMAGE_NAME):$(VERSION) \
		scan --target $$target --format $$format --output reports/scan_$$(date +%Y%m%d_%H%M%S).$$format

demo:
	@docker run --rm \
		-v $(REPORTS_DIR):/app/reports \
		--network host \
		$(IMAGE_NAME):$(VERSION) \
		scan --target http://localhost:3000 --format html --output reports/demo.html

shell:
	docker run --rm -it \
		-v $(PWD)/src:/app/src \
		-v $(REPORTS_DIR):/app/reports \
		--network host \
		$(IMAGE_NAME):$(VERSION) \
		bash

up:
	$(COMPOSE) up -d
	$(COMPOSE) ps

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=100

test:
	docker run --rm \
		-v $(PWD)/tests:/app/tests \
		-v $(PWD)/src:/app/src \
		$(IMAGE_NAME):$(VERSION) \
		pytest -v

clean:
	docker ps -aq -f name=mcp | xargs -r docker rm -f || true

clean-all: clean
	rm -rf reports/scans/* reports/compliance/* reports/demos/* || true
