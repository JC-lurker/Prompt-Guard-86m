FROM python:3.11-slim

WORKDIR /app

# Install necessary system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages: mitmproxy replaces asyncio/ssl/cryptography manual work
RUN pip install --no-cache-dir \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    torch transformers pyyaml mitmproxy

COPY guard.py /app/guard.py

# proxy port
EXPOSE 8080
# mitmweb UI port (optional — use mitmweb instead of mitmdump)
EXPOSE 5001

ENV PYTHONUNBUFFERED=1

# mitmproxy stores its CA in ~/mitmproxy — persist via volume
# Clients install ~/mitmproxy/mitmproxy-ca-cert.pem as trusted root
CMD ["mitmweb", "-s", "guard.py", "--listen-port", "8080", "--web-host", "0.0.0.0", "--web-port", "5001", "--set", "connection_strategy=lazy", "--set", "confdir=/root/mitmproxy"]
