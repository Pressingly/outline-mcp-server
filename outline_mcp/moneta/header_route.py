"""The per-request ``x-outline-api-key`` route, ``/http/api-key`` (Moneta fork).

Callers inside the bundle (the access-agent) hold a user's own Outline API key
and reach Outline without the mPass edge, so header mode talks to the URL in
``OUTLINE_HEADER_INTERNAL_BASE_URL`` (e.g. ``http://outline:3000``). It is
opt-in, because a deployment must stop routing ``/http/api-key`` publicly
before a key alone is enough to reach Outline. Unset, header mode keeps
``OUTLINE_API_URL``. Public document links still come from ``OUTLINE_API_URL``.

The route has no OAuth layer, and every tool turns an Outline error into
ordinary text, so a deleted key would otherwise look like a successful call.
:class:`HeaderKeyGate` checks the key with ``auth.info`` first and answers
HTTP 401 when Outline rejects it.
"""

from __future__ import annotations

import enum
import logging
import os

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from outline_mcp.moneta.apitoken import steady_state_http_client
from outline_mcp.moneta.client import stored_access_token
from outline_mcp.outline_client import OutlineClient, OutlineError, _sanitize_value

logger = logging.getLogger("fastmcp.outline_mcp.moneta.header_route")

HEADER_API_URL_ENV = "OUTLINE_HEADER_INTERNAL_BASE_URL"
API_KEY_HEADER = "x-outline-api-key"


class KeyCheck(enum.Enum):
    VALID = "valid"
    MISSING = "missing"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


def header_api_url() -> str:
    return os.getenv(HEADER_API_URL_ENV, "").strip() or os.getenv("OUTLINE_API_URL", "").strip()


def _key_client(api_key: str) -> OutlineClient:
    return OutlineClient(api_key=api_key, api_url=header_api_url(), http_client=steady_state_http_client())


def header_client(api_key: str | None) -> OutlineClient | None:
    """A client for a header-supplied key on the header-mode URL, or ``None``.

    ``None`` without a key, and on an OAuth-authenticated request: only the
    header route, which has no OAuth layer, may reach the internal URL with a
    key alone. It uses the cookie-refusing steady-state client, so one
    caller's Outline session cookie is never replayed for another caller's key.
    """
    if not api_key or stored_access_token() is not None:
        return None
    return _key_client(api_key)


def _key_check_for(error: OutlineError) -> KeyCheck:
    if error.status_code == 401:
        return KeyCheck.REJECTED
    if error.status_code == 403:
        return KeyCheck.VALID
    return KeyCheck.UNAVAILABLE


async def check_key(api_key: str | None) -> KeyCheck:
    """Ask Outline whether ``api_key`` authenticates.

    A 403 means the key is valid but scoped away from ``auth.info``, so the
    tools decide what it may do.
    """
    if not api_key:
        return KeyCheck.MISSING
    try:
        await _key_client(api_key).get_auth_info()
    except OutlineError as error:
        return _key_check_for(error)
    except Exception:  # noqa: BLE001 — e.g. a non-JSON 200 from a login page; fail closed
        logger.exception("header route: the Outline key check failed unexpectedly")
        return KeyCheck.UNAVAILABLE
    return KeyCheck.VALID


_REFUSALS: dict[KeyCheck, tuple[int, str, str]] = {
    KeyCheck.MISSING: (401, "invalid_request", f"The {API_KEY_HEADER} header is required."),
    KeyCheck.REJECTED: (401, "invalid_token", "Outline rejected the API key: it is invalid, expired or deleted."),
    KeyCheck.UNAVAILABLE: (503, "temporarily_unavailable", "Outline could not be reached to check the API key."),
}


def _refusal(check: KeyCheck) -> JSONResponse:
    status, error, description = _REFUSALS[check]
    headers = {"WWW-Authenticate": f'Bearer error="{error}"'} if status == 401 else None
    return JSONResponse({"error": error, "error_description": description}, status_code=status, headers=headers)


class HeaderKeyGate:
    """ASGI middleware that refuses header-route requests whose key Outline does not accept."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        api_key = _sanitize_value(Headers(scope=scope).get(API_KEY_HEADER))
        check = await check_key(api_key)
        if check is KeyCheck.VALID:
            await self.app(scope, receive, send)
            return
        logger.warning("header route refused the request: key %s", check.value)
        await _refusal(check)(scope, receive, send)
