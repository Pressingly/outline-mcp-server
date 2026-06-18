# TODO(prod): pin by digest once a release cadence is established
FROM python:3.11-slim

WORKDIR /app

# curl is used by the HEALTHCHECK
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml ./
COPY uv.lock* ./
COPY outline_mcp/ ./outline_mcp/

RUN uv pip install --system --no-cache .

# Non-root runtime user
RUN groupadd --system --gid 10001 mcp \
    && useradd --system --uid 10001 --gid mcp --home-dir /app --no-create-home mcp \
    && chown -R mcp:mcp /app
USER mcp

EXPOSE 8213
ENV MCP_HTTP_PORT=8213

ENTRYPOINT ["python", "-m", "outline_mcp"]
CMD ["http"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=10 \
    CMD curl -fsS "http://127.0.0.1:${MCP_HTTP_PORT:-8213}/healthz" || exit 1
