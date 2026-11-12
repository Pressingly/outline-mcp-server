"""The mPass edge secret Outline requires before it trusts ``X-Auth-Request-*``.

Outline (FOSS-777) ignores the SSO identity headers unless the request also
carries ``X-Mpass-Edge-Secret`` equal to its ``MPASS_EDGE_SECRET``. The key
bootstrap in :mod:`outline_mcp.moneta.apitoken` is the only request this server
sends with identity headers, so it is the only one that carries the secret.
Every other request goes through :func:`guarded_http_client`, which refuses to
send either.

The secret is read from ``OUTLINE_EDGE_SECRET`` and never logged: problems are
reported by name only.
"""

from __future__ import annotations

import os

import httpx

EDGE_SECRET_ENV = "OUTLINE_EDGE_SECRET"
EDGE_SECRET_HEADER = "X-Mpass-Edge-Secret"
IDENTITY_HEADER_PREFIX = "x-auth-request-"
MIN_EDGE_SECRET_LENGTH = 32
EDGE_SECRET_PLACEHOLDER_PREFIX = "CHANGE_ME_"


class TrustHeaderError(RuntimeError):
    """A steady-state request tried to send an identity header or the edge secret."""


def configured_edge_secret() -> str:
    return os.getenv(EDGE_SECRET_ENV, "").strip()


def edge_secret_problem(secret: str) -> str | None:
    """Why Outline would not trust ``secret``; ``None`` when it is usable."""
    if not secret:
        return "unset"
    if secret.startswith(EDGE_SECRET_PLACEHOLDER_PREFIX):
        return "a placeholder"
    if not (secret.isascii() and secret.isprintable()):
        return "not printable ASCII"
    if len(secret) < MIN_EDGE_SECRET_LENGTH:
        return f"shorter than {MIN_EDGE_SECRET_LENGTH} characters"
    return None


def usable_edge_secret() -> str | None:
    """The configured secret when Outline would accept it; any other value is left out rather than rejected."""
    secret = configured_edge_secret()
    return secret if edge_secret_problem(secret) is None else None


def edge_headers() -> dict[str, str]:
    secret = usable_edge_secret()
    return {EDGE_SECRET_HEADER: secret} if secret else {}


def edge_secret_startup_error() -> str | None:
    """The operator-facing startup error for an unusable secret, without its value."""
    problem = edge_secret_problem(configured_edge_secret())
    if problem is None:
        return None
    return (
        f"{EDGE_SECRET_ENV} is {problem}: the Outline API-key mint is sent without it, and an Outline that "
        "checks its MPASS_EDGE_SECRET ignores the SSO identity headers, so no new Outline API key can be "
        "minted (cached keys keep working until they expire); set it to the value Outline uses "
        f"(printable ASCII, at least {MIN_EDGE_SECRET_LENGTH} characters)"
    )


def is_trust_header(name: str) -> bool:
    """An identity header, or the edge secret that makes Outline trust one."""
    normalised = name.lower().replace("_", "-")
    return normalised.startswith(IDENTITY_HEADER_PREFIX) or normalised == EDGE_SECRET_HEADER.lower()


async def reject_trust_headers(request: httpx.Request) -> None:
    leaked = sorted(name for name in request.headers if is_trust_header(name))
    if leaked:
        raise TrustHeaderError(f"refusing to send {', '.join(leaked)} on a steady-state Outline request")


def guarded_http_client(**kwargs) -> httpx.AsyncClient:
    """An httpx client that can never send identity headers or the edge secret, redirects included."""
    hooks = kwargs.pop("event_hooks", {}) or {}
    request_hooks = [*hooks.get("request", []), reject_trust_headers]
    return httpx.AsyncClient(**kwargs, event_hooks={**hooks, "request": request_hooks})
