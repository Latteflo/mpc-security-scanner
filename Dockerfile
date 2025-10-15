FROM python:3.11-slim

LABEL maintainer="your.email@example.com"
LABEL version="0.1.0"

# Create user
RUN useradd -m -u 1000 scanner && \
    mkdir -p /app /app/reports /app/config && \
    chown -R scanner:scanner /app

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python packages only (no system packages needed for now)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
    mcp>=1.17.0 \
    click>=8.1.0 \
    rich>=13.7.0 \
    pydantic>=2.5.0 \
    pyyaml>=6.0.1 \
    python-dotenv>=1.0.0 \
    aiohttp>=3.9.0 \
    httpx>=0.25.0

# Copy application
COPY --chown=scanner:scanner src/ ./src/
COPY --chown=scanner:scanner examples/ ./examples/
COPY --chown=scanner:scanner pyproject.toml .

USER scanner

VOLUME ["/app/reports", "/app/config"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

ENTRYPOINT ["python", "src/main.py"]
CMD ["--help"]
