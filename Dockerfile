# =============================================================================
# Automated Linux Network Intrusion Detection System (NIDS) — Dockerfile
# =============================================================================
FROM python:3.11-slim

LABEL maintainer="Automated Linux NIDS Team"
LABEL description="Production NIDS SOC Dashboard and Packet Sniffing Daemon"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies required for packet capture and firewall mitigation
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    iptables \
    iproute2 \
    net-tools \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source code and assets
COPY src/ src/
COPY data/ data/
COPY models/ models/
COPY logs/ logs/

# Expose Central SOC Web Dashboard port
EXPOSE 5000

# Health check to ensure SOC backend is operational
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/api/status || exit 1

# Launch the primary Flask SOC service
CMD ["python", "src/app.py"]
