FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .

# Create reports directory
RUN mkdir -p /app/reports

# Install the package
RUN pip install -e .

# Create non-root user for security
RUN groupadd -r sud0recon && useradd -r -g sud0recon sud0recon
RUN chown -R sud0recon:sud0recon /app
USER sud0recon

# Expose port for API
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/status || exit 1

# Default command - run API server
CMD ["uvicorn", "src.sud0recon.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Alternative: Run CLI (uncomment and comment above line to use CLI mode)
# ENTRYPOINT ["python", "-m", "src.sud0recon.cli"]
