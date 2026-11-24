"""The per-request ``x-outline-api-key`` route, ``/http/api-key`` (Moneta fork).

Callers inside the bundle (the access-agent) hold a user's own Outline API key
and reach Outline without the mPass edge, so header mode talks to the URL in
``OUTLINE_HEADER_INTERNAL_BASE_URL`` (e.g. ``http://outline:3000``). It is
opt-in, because a deployment must stop routing ``/http/api-key`` publicly
before a key alone is enough to reach Outline. Unset, header mode keeps
``OUTLINE_API_URL``. Public document links still come from ``OUTLINE_API_URL``.

The route has no OAuth layer, and every tool turns an Outline error into
ordinary text, so a deleted key would otherwise look like a successful call.
:class:`HeaderKeyGate` checks the key with one ``auth.info`` call first and
answers HTTP 401 when Outline rejects it. While the internal URL is set, it
also refuses any request that came through a proxy: Traefik adds
``X-Forwarded-For`` and ``X-Forwarded-Host`` to everything it forwards, and the
access-agent calls the container directly without either, so the server does
not rely on the edge router alone to keep the route private.
"""

from __future__ import annotations

import enum
import logging
import os
from contextvars import ContextVar

import httpx
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from outline_mcp.moneta.apitoken import steady_state_http_client
from outline_mcp.outline_client import OutlineClient, _sanitize_value

logger = logging.getLogger("fastmcp.outline_mcp.moneta.header_route")

HEADER_API_URL_ENV = "OUTLINE_HEADER_INTERNAL_BASE_URL"
API_KEY_HEADER = "x-outline-api-key"
FORWARDED_HEADERS = ("x-forwarded-for", "x-forwarded-host")
KEY_CHECK_TIMEOUT_SECONDS = 5.0
SCOPE_REFUSAL_ERROR = "authorization_error"

_passed_gate: ContextVar[bool] = ContextVar("outline_header_route_passed_gate", default=False)


class KeyCheck(enum.Enum):
    VALID = "valid"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"
    PROXIED = "proxied"


def header_api_url() -> str:
    return os.getenv(HEADER_API_URL_ENV, "").strip() or os.getenv("OUTLINE_API_URL", "").strip()


def internal_route_enabled() -> bool:
    return bool(os.getenv(HEADER_API_URL_ENV, "").strip())


def _key_client(api_key: str) -> OutlineClient:
    return OutlineClient(api_key=api_key, api_url=header_api_url(), http_client=steady_state_http_client())


def header_client(api_key: str | None) -> OutlineClient | None:
    """A client for a header-supplied key on the header-mode URL, or ``None``.

    Only a request that passed :class:`HeaderKeyGate` gets one: the Cognito
    ``/mcp``, and upstream's ungated http mode (no ``COGNITO_USER_POOL_ID``),
    keep the public ``OUTLINE_API_URL``. It uses the cookie-refusing
    steady-state client, so one caller's Outline session cookie is never
    replayed for another caller's key.
    """
    if not api_key or not _passed_gate.get():
        return None
    return _key_client(api_key)


def _is_sendable(api_key: str) -> bool:
    return api_key.isascii() and api_key.isprintable()


def _error_id(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None
    return body.get("error") if isinstance(body, dict) else None


def _is_json(response: httpx.Response) -> bool:
    try:
        response.json()
    except ValueError:
        return False
    return True


def _key_check_for(response: httpx.Response) -> KeyCheck:
    """Map Outline's ``auth.info`` answer.

    A 403 passes only as a scope refusal (a valid key scoped away from
    ``auth.info``); any other 403, such as ``user_suspended`` for a leaver,
    rejects the key. A 200 that is not JSON came from something other than
    the Outline API, such as a sign-in page.
    """
    status = response.status_code
    if status == 200:
        return KeyCheck.VALID if _is_json(response) else KeyCheck.UNAVAILABLE
    if status == 401:
        return KeyCheck.REJECTED
    if status == 403:
        return KeyCheck.VALID if _error_id(response) == SCOPE_REFUSAL_ERROR else KeyCheck.REJECTED
    return KeyCheck.UNAVAILABLE


async def check_key(api_key: str) -> KeyCheck:
    """Ask Outline once whether ``api_key`` authenticates: no retries, a short timeout."""
    if not _is_sendable(api_key):
        return KeyCheck.REJECTED
    try:
        response = await steady_state_http_client().post(
            f"{_key_client(api_key).api_url}/auth.info",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            json={},
            timeout=KEY_CHECK_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as error:
        logger.warning("header route: the Outline key check failed: %s", type(error).__name__)
        return KeyCheck.UNAVAILABLE
    return _key_check_for(response)


async def check_request(headers: Headers) -> KeyCheck:
    if internal_route_enabled() and any(name in headers for name in FORWARDED_HEADERS):
        return KeyCheck.PROXIED
    keys = headers.getlist(API_KEY_HEADER)
    if len(keys) > 1:
        return KeyCheck.AMBIGUOUS
    api_key = _sanitize_value(keys[0]) if keys else None
    if not api_key:
        return KeyCheck.MISSING
    return await check_key(api_key)


_REFUSALS: dict[KeyCheck, tuple[int, str, str]] = {
    KeyCheck.MISSING: (401, "invalid_request", f"The {API_KEY_HEADER} header is required."),
    KeyCheck.AMBIGUOUS: (401, "invalid_request", f"Send exactly one {API_KEY_HEADER} header."),
    KeyCheck.REJECTED: (401, "invalid_token", "Outline rejected the API key: it is invalid, expired or deleted."),
    KeyCheck.UNAVAILABLE: (503, "temporarily_unavailable", "Outline could not be reached to check the API key."),
    KeyCheck.PROXIED: (403, "forbidden", "The API-key route is internal to the bundle."),
}


def _refusal(check: KeyCheck) -> JSONResponse:
    status, error, description = _REFUSALS[check]
    headers = {"WWW-Authenticate": f'Bearer error="{error}"'} if status == 401 else None
    return JSONResponse({"error": error, "error_description": description}, status_code=status, headers=headers)


class HeaderKeyGate:
    """ASGI middleware that refuses header-route requests Outline would not accept, or that came through a proxy."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        check = await check_request(Headers(scope=scope))
        if check is KeyCheck.VALID:
            passed = _passed_gate.set(True)
            try:
                await self.app(scope, receive, send)
            finally:
                _passed_gate.reset(passed)
            return
        logger.warning("header route refused the request: %s", check.value)
        await _refusal(check)(scope, receive, send)
