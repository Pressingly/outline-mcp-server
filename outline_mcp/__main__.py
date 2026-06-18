"""Entry point for the Outline MCP Server.

Usage::

    outline-mcp-server stdio   # local, OUTLINE_API_KEY (default)
    outline-mcp-server http    # streamable-HTTP, x-outline-api-key header

The Pressingly ``moneta`` fork adds a hook here: when ``COGNITO_USER_POOL_ID``
is set, http mode is handled by ``moneta.http.run()`` (AWS Cognito / mPass)
instead of the header-auth path below.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from enum import Enum

import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from outline_mcp.server import get_http_mcp, get_stdio_mcp

DEFAULT_HTTP_PORT = 8213


class ServerMode(Enum):
    STDIO = "stdio"
    HTTP = "http"


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter (one object per line)."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["error"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        return json.dumps(entry)


_VALID_LOG_LEVELS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

logger = logging.getLogger("fastmcp.outline_mcp")


def resolve_log_level() -> int:
    """Resolve log level from ``MCP_LOG_LEVEL``, else ``MCP_ENV`` default."""
    raw = os.getenv("MCP_LOG_LEVEL", "").strip().upper()
    if raw and raw in _VALID_LOG_LEVELS:
        return _VALID_LOG_LEVELS[raw]
    env = os.getenv("MCP_ENV", "development").strip().lower()
    return logging.INFO if env == "production" else logging.DEBUG


def configure_json_logging(level: int | None = None) -> None:
    """Attach a JSON handler to the ``fastmcp`` logger (called from main)."""
    if level is None:
        level = resolve_log_level()
    fastmcp_logger = logging.getLogger("fastmcp")
    for handler in fastmcp_logger.handlers[:]:
        fastmcp_logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter())
    fastmcp_logger.addHandler(handler)
    fastmcp_logger.setLevel(level)
    fastmcp_logger.propagate = False


def resolve_http_port() -> int:
    """Resolve the HTTP listener port from ``MCP_HTTP_PORT`` (default 8213)."""
    raw = os.getenv("MCP_HTTP_PORT", "").strip()
    if not raw:
        return DEFAULT_HTTP_PORT
    try:
        port = int(raw)
    except ValueError:
        logger.warning("MCP_HTTP_PORT=%r is not an integer; using default %d", raw, DEFAULT_HTTP_PORT)
        return DEFAULT_HTTP_PORT
    if not (1 <= port <= 65535):
        logger.warning("MCP_HTTP_PORT=%d is out of range; using default %d", port, DEFAULT_HTTP_PORT)
        return DEFAULT_HTTP_PORT
    return port


def resolve_cors_origins() -> list[str]:
    """Parse ``MCP_ALLOWED_ORIGINS`` (comma-separated); default ``['*']``."""
    raw = os.getenv("MCP_ALLOWED_ORIGINS", "").strip()
    if raw:
        origins = [o.strip() for o in raw.split(",") if o.strip()]
        if origins:
            return origins
    return ["*"]


async def healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def main() -> None:
    """Run the Outline MCP server."""
    configure_json_logging()

    server_mode = ServerMode.STDIO
    if len(sys.argv) > 1:
        server_mode = ServerMode(sys.argv[1])

    if server_mode == ServerMode.STDIO:
        get_stdio_mcp().run()
        return

    if server_mode == ServerMode.HTTP:
        cors = [
            Middleware(
                CORSMiddleware,
                allow_origins=resolve_cors_origins(),
                allow_credentials=False,
                allow_methods=["*"],
                allow_headers=[
                    "mcp-protocol-version",
                    "mcp-session-id",
                    "Authorization",
                    "Content-Type",
                    "x-outline-api-key",
                ],
                expose_headers=["mcp-session-id"],
            )
        ]
        http_app = get_http_mcp().http_app(middleware=cors, stateless_http=True)
        app = Starlette(
            routes=[
                Route("/healthz", healthz, methods=["GET"]),
                Mount("/", app=http_app),
            ],
            lifespan=http_app.lifespan,
        )
        level = resolve_log_level()
        port = resolve_http_port()
        logger.info("Starting Outline MCP HTTP server on :%d", port)
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=port,
            log_level=logging.getLevelName(level).lower(),
            access_log=False,
        )
        return


if __name__ == "__main__":
    main()
