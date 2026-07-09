FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="HARMATTAN" \
      org.opencontainers.image.description="Network Intelligence Suite" \
      org.opencontainers.image.version="3.0.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HARMATTAN_HOST=0.0.0.0 \
    HARMATTAN_PORT=8088 \
    HARMATTAN_DATA=/data \
    HARMATTAN_AUTO_TOKEN=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iproute2 iputils-ping traceroute \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py harmattan.sh ./
COPY core ./core
COPY modules ./modules
COPY templates ./templates
COPY static ./static

RUN mkdir -p /data /app/reports && chmod +x harmattan.sh

VOLUME ["/data"]
EXPOSE 8088

# NET_RAW needed for ARP/sniff — run with --cap-add=NET_RAW --cap-add=NET_ADMIN
CMD ["python", "app.py"]
