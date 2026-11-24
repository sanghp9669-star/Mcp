# Multi-stage hardened Python 3.12 Dockerfile
FROM python:3.12-slim AS builder

WORKDIR /build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev libssl-dev libffi-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

FROM python:3.12-slim AS runtime

RUN groupadd -r mcpuser && useradd -r -g mcpuser -u 10001 mcpuser \
    && mkdir -p /app /etc/switch_mcp && chown -R mcpuser:mcpuser /app /etc/switch_mcp

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

COPY pyproject.toml .
COPY src ./src
RUN pip install --no-cache-dir --no-deps .

USER mcpuser
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/liveness')" || exit 1

CMD ["uvicorn", "switch_mcp.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
