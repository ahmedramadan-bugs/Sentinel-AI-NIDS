# Sentinel-AI NIDS — Autonomous AI-Powered Intrusion Detection System
FROM python:3.12-slim-bookworm

LABEL maintainer="Sentinel-AI NIDS Team"
LABEL description="Production-grade AI-powered NIDS with Zero-Hardware and Cisco active response."

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    NIDS_DASHBOARD_HOST=0.0.0.0 \
    NIDS_DASHBOARD_PORT=8080

WORKDIR /app

# Install system dependencies (iptables for Zero-Hardware Linux enforcement, curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Ensure runtime directory exists
RUN mkdir -p runtime /var/log/suricata

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/status || exit 1

CMD ["python", "run_nids.py"]
