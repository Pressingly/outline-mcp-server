"""Auth seam for Outline API access.

Tools never construct an :class:`OutlineClient` directly — they call
:func:`get_outline_client`, which resolves the credential for the current
request. This is the single place where authentication is decided, so the
Pressingly ``moneta`` fork can override credential resolution (Cognito / mPass
id-token relay + minted Outline API key) without touching any tool module.

Credential precedence in this (upstream) base:

1. ``x-outline-api-key`` HTTP header — per-request key for multi-user HTTP mode.
2. ``OUTLINE_API_KEY`` environment variable — single-user / stdio mode.

The fork replaces :func:`get_outline_client` to mint and cache a per-user
``ol_api_`` key from the relayed Cognito identity instead.
"""

from __future__ import annotations

import os

from outline_mcp.outline_client import OutlineClient, OutlineError, _sanitize_value


class OutlineClientError(Exception):
    """Raised when an Outline client cannot be created for the request."""


def _get_header_api_key() -> str | None:
    """Return the ``x-outline-api-key`` header value for the current request.

    Reads the incoming HTTP request headers exposed by FastMCP's dependency
    helper. Returns ``None`` outside a request context (stdio, startup, tests)
    or when the header is absent.
    """
    try:
        from fastmcp.server.dependencies import get_http_headers

        headers = get_http_headers()
        if headers:
            return _sanitize_value(headers.get("x-outline-api-key"))
    except (RuntimeError, ImportError, LookupError, AttributeError):
        pass
    return None


def get_resolved_api_key() -> str:
    """Return the API key for the current request.

    Priority: ``x-outline-api-key`` header > ``OUTLINE_API_KEY`` env var.
    Returns an empty string when neither is set.
    """
    return _get_header_api_key() or os.getenv("OUTLINE_API_KEY", "")


async def get_outline_client() -> OutlineClient:
    """Return an :class:`OutlineClient` authenticated for the current request.

    Raises:
        OutlineClientError: If no credential is available or the client cannot
            be constructed.
    """
    try:
        api_key = get_resolved_api_key() or None
        api_url = os.getenv("OUTLINE_API_URL")
        return OutlineClient(api_key=api_key, api_url=api_url)
    except OutlineError as exc:
        raise OutlineClientError(f"Outline client error: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — surface any init failure uniformly
        raise OutlineClientError(f"Unexpected error: {exc}") from exc
