"""Cognito HTTP server for the devstack (Moneta fork).

``outline_mcp.__main__``'s http mode delegates here when :func:`enabled` is true
(``COGNITO_USER_POOL_ID`` set). FastMCP's ``AWSCognitoProvider`` is the sole auth
layer: it turns the service into a full OAuth 2.0 authorization server (DCR shim +
RFC 8414/9728 discovery + ``/authorize`` / ``/auth/callback`` / ``/token`` proxied
to Cognito), so MCP clients (Claude Desktop, Cursor) OAuth automatically. The
validated Cognito access token is JWKS-verified per request; the captured
**id_token** is used to mint a per-user Outline API key (see
:mod:`outline_mcp.moneta.apitoken`).

The ``/mcp`` router carries ``strip-auth-headers,security-headers`` only — NOT
mpass-auth — so this provider, not oauth2-proxy, authenticates the inbound leg.

JSON logging is duplicated here (not imported from ``outline_mcp.__main__``) on
purpose: keeping the fork self-contained avoids import cycles and recurring merge
conflicts on the upstream entrypoint.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.middleware.logging import StructuredLoggingMiddleware
from mcp.types import Icon
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from outline_mcp.moneta.cognito import OutlineCognitoProvider
from outline_mcp.moneta.storage import build_oauth_storage
from outline_mcp.server import get_http_mcp
from outline_mcp.tools import register_tools

logger = logging.getLogger("fastmcp.outline_mcp.moneta")

_DEFAULT_HTTP_PORT = 8213

# Default redirect URIs cover Claude Desktop, Cursor, and MCP Inspector on a
# developer laptop. Non-localhost MCP clients must be listed via
# MCP_ALLOWED_CLIENT_REDIRECT_URIS to register at /register (the DCR shim).
_DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS: tuple[str, ...] = (
    "http://localhost:*/*",
    "http://127.0.0.1:*/*",
)


def enabled() -> bool:
    """True when the Cognito HTTP path should handle ``http`` mode."""
    on = bool(os.getenv("COGNITO_USER_POOL_ID", "").strip())
    logger.debug(
        "Cognito http mode %s (COGNITO_USER_POOL_ID %s)",
        "enabled" if on else "disabled",
        "set" if on else "unset",
    )
    return on


def _allowed_client_redirect_uris() -> list[str]:
    """Parse MCP_ALLOWED_CLIENT_REDIRECT_URIS (comma-separated; fnmatch wildcards).

    Unset/empty → localhost defaults. Do not allow arbitrary redirect URIs — they
    let an attacker DCR-register a malicious client and exfiltrate user tokens.
    """
    raw = os.getenv("MCP_ALLOWED_CLIENT_REDIRECT_URIS", "").strip()
    if not raw:
        return list(_DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS)
    allowed = [uri.strip() for uri in raw.split(",") if uri.strip()]
    return allowed or list(_DEFAULT_ALLOWED_CLIENT_REDIRECT_URIS)


def _required_scopes() -> list[str]:
    """OAuth scopes requested upstream from Cognito (space- or comma-separated).

    Default is ``openid`` only — Cognito puts ``email`` / ``cognito:username`` in
    the id_token of the auth-code flow with just ``openid``, which is all the
    Outline identity relay needs. Requesting ``email`` / ``profile`` against a
    client that doesn't enable them fails with ``invalid_scope``. Opt in via
    MCP_OIDC_SCOPES.
    """
    raw = os.getenv("MCP_OIDC_SCOPES", "").strip()
    if not raw:
        return ["openid"]
    scopes = [s.strip() for s in raw.replace(",", " ").split() if s.strip()]
    return scopes or ["openid"]


def get_cognito_http_mcp() -> FastMCP:
    """Build the FastMCP instance whose sole auth layer is the Cognito provider."""
    client_secret = os.getenv("OIDC_CLIENT_SECRET", "")
    jwt_signing_key = os.getenv("MCP_JWT_SIGNING_KEY") or None

    provider = OutlineCognitoProvider(
        user_pool_id=os.environ["COGNITO_USER_POOL_ID"],
        aws_region=os.environ["COGNITO_AWS_REGION"],
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=client_secret,
        base_url=os.environ["MCP_BASE_URL"],
        redirect_path="/auth/callback",
        required_scopes=_required_scopes(),
        allowed_client_redirect_uris=_allowed_client_redirect_uris(),
        # Cognito User Pools don't honor RFC 8707 Resource Indicators; forwarding
        # `resource` on /authorize without it echoed on /token makes Cognito return
        # invalid_grant. MCP clients still send it to FastMCP; we don't pass it on.
        forward_resource=False,
        # None → FastMCP keeps its encrypted-file default (see moneta.storage).
        client_storage=build_oauth_storage(),
        jwt_signing_key=jwt_signing_key,
    )
    logger.info(
        "Cognito provider: pool=%s region=%s client_id=%s base_url=%s scopes=%s secret=%s signing_key=%s "
        "storage=%s outline_public=%s outline_internal=%s",
        os.environ["COGNITO_USER_POOL_ID"],
        os.environ["COGNITO_AWS_REGION"],
        os.environ["OIDC_CLIENT_ID"],
        os.environ["MCP_BASE_URL"],
        _required_scopes(),
        "set" if client_secret else "unset",
        "set" if jwt_signing_key else "unset",
        "valkey" if os.getenv("MCP_OAUTH_STORAGE_URL", "").strip() else "file",
        os.getenv("OUTLINE_API_URL", "<unset>"),
        os.getenv("OUTLINE_INTERNAL_BASE_URL", "<unset>"),
    )

    mcp = FastMCP(
        "Outline MCP Server (Cognito http)",
        icons=[Icon(src="https://www.getoutline.com/favicon.ico", alt="Outline MCP Server")],
        website_url="https://www.getoutline.com",
        auth=provider,
    )
    mcp.add_middleware(StructuredLoggingMiddleware(include_payloads=False))
    register_tools(mcp)
    return mcp


class _JSONFormatter(logging.Formatter):
    """JSON log formatter (duplicated from upstream __main__ to avoid coupling)."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["error"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        return json.dumps(log_entry)


_VALID_LOG_LEVELS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def _resolve_log_level() -> int:
    raw = os.getenv("MCP_LOG_LEVEL", "").strip().upper()
    return _VALID_LOG_LEVELS.get(raw, logging.INFO)


def _configure_logging() -> None:
    level = _resolve_log_level()
    for name in ("fastmcp", "uvicorn", "uvicorn.error"):
        target = logging.getLogger(name)
        for handler in target.handlers[:]:
            target.removeHandler(handler)
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JSONFormatter())
        target.addHandler(handler)
        target.setLevel(level)
        target.propagate = False


def _resolve_http_port() -> int:
    raw = os.getenv("MCP_HTTP_PORT", "").strip()
    if not raw:
        return _DEFAULT_HTTP_PORT
    try:
        port = int(raw)
    except ValueError:
        logger.warning("MCP_HTTP_PORT=%r is not an integer; using default %d", raw, _DEFAULT_HTTP_PORT)
        return _DEFAULT_HTTP_PORT
    if not (1 <= port <= 65535):
        logger.warning("MCP_HTTP_PORT=%d is out of range; using default %d", port, _DEFAULT_HTTP_PORT)
        return _DEFAULT_HTTP_PORT
    return port


def _resolve_cors_origins() -> list[str]:
    raw = os.getenv("MCP_ALLOWED_ORIGINS", "").strip()
    if raw:
        origins = [o.strip() for o in raw.split(",") if o.strip()]
        if origins:
            return origins
    return ["*"]


def validate_env() -> None:
    """Fail fast if the Cognito HTTP env contract isn't satisfied."""
    required = (
        "MCP_BASE_URL",
        "COGNITO_USER_POOL_ID",
        "COGNITO_AWS_REGION",
        "OIDC_CLIENT_ID",
        "OUTLINE_INTERNAL_BASE_URL",
    )
    missing = [name for name in required if not os.getenv(name, "").strip()]
    if missing:
        raise ValueError("Cognito http mode is missing required env vars: " + ", ".join(missing))
    # AWSCognitoProvider needs entropy for FastMCP-issued JWTs: a confidential
    # client supplies OIDC_CLIENT_SECRET (FastMCP derives the key from it); a
    # public/PKCE client must supply MCP_JWT_SIGNING_KEY explicitly.
    if not os.getenv("OIDC_CLIENT_SECRET", "").strip() and not os.getenv("MCP_JWT_SIGNING_KEY", "").strip():
        raise ValueError(
            "Cognito http mode requires OIDC_CLIENT_SECRET (confidential client) "
            "or MCP_JWT_SIGNING_KEY (public/PKCE client)."
        )
    if os.getenv("MCP_ENV", "").strip().lower() == "production" and not os.getenv("MCP_OAUTH_STORAGE_URL", "").strip():
        logger.warning(
            "MCP_OAUTH_STORAGE_URL is unset in production — OAuth state lives on "
            "the container filesystem and is lost on recreation. Point it at a "
            "Valkey/Redis URL (e.g. redis://valkey:6379/14)."
        )


async def healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def run() -> None:
    """Validate env, build the Starlette app, and serve it with uvicorn."""
    validate_env()

    cognito_app = get_cognito_http_mcp().http_app(stateless_http=True)
    header_app = get_http_mcp().http_app(stateless_http=True)

    @asynccontextmanager
    async def lifespan(app):
        async with cognito_app.lifespan(cognito_app):
            async with header_app.lifespan(header_app):
                yield

    app = Starlette(
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            # Per-request x-outline-api-key mode stays available alongside Cognito.
            Mount("/http/api-key", app=header_app),
            # AWSCognitoProvider publishes /.well-known/* on the mounted app.
            Mount("/", app=cognito_app),
        ],
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_resolve_cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _configure_logging()
    port = _resolve_http_port()
    logger.info("Starting Cognito HTTP server on :%d (/mcp, /http/api-key/mcp, GET /healthz)", port)
    logger.info(
        "Cognito: register this callback URL in the Cognito app client: %s/auth/callback",
        os.environ["MCP_BASE_URL"].strip().rstrip("/"),
    )
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info", access_log=False)
