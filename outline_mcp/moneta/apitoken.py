"""Outline API-key bridge for the Cognito path (Moneta fork) — minted-key hybrid.

Why a minted key (not pure header-injection, not the Cognito Bearer)
-------------------------------------------------------------------
Outline's API authenticates ``Authorization: Bearer <token>`` where the token is
an **Outline-issued** credential (``ol_api_`` key, ``ol_at_`` OAuth token, or a
per-user session JWT). It will not accept an external Cognito JWT, and oauth2-proxy
only skip-validates *JWT* bearers — so neither the Cognito token nor a key can
clear mPass on the public route. The robust, network-position-independent identity
is therefore a real Outline credential: a per-user ``ol_api_`` key.

Two legs, both on the **internal** docker/cluster URL (``OUTLINE_INTERNAL_BASE_URL``,
e.g. ``http://outline:3000``) — bypassing Traefik/mPass:

1. **Bootstrap (once per user):** ``apiKeys.create`` requires
   ``AuthenticationType.APP``, granted only on Outline's ``fwd:<email>`` header
   path. So we mint by calling ``apiKeys.create`` with an injected
   ``X-Auth-Request-Email`` (the identity captured from the validated Cognito
   id_token) and **no** ``Authorization`` header — reaching the ``fwd:`` path that
   authorises the mint. The request also carries ``X-Mpass-Edge-Secret``
   (``OUTLINE_EDGE_SECRET``), without which Outline ignores those headers; see
   :mod:`outline_mcp.moneta.edge`. Minted keys self-expire, nothing is revoked.
2. **Steady state:** every tool call uses ``Authorization: Bearer <ol_api_…>``.
   Identity is now proven by *key possession*, not by trusting whatever sets a
   header — the property that makes this safe across separate K8s pods.

The key is cached (Fernet-encrypted in Valkey when ``MCP_OAUTH_STORAGE_URL`` is set,
else in-process) keyed by the Cognito identity, so the bootstrap mint runs at most
once per user per cache lifetime. The raw key is returned by Outline only at create
time (``presentApiKey`` → ``data.value``), so it must be cached, not re-fetched.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.utilities.logging import get_logger

from outline_mcp.client import OutlineClientError
from outline_mcp.moneta.client import identity_email_for, stored_access_token, upstream_access_token_for
from outline_mcp.moneta.edge import (
    EDGE_SECRET_ENV,
    MIN_EDGE_SECRET_LENGTH,
    edge_headers,
    guarded_http_client,
)
from outline_mcp.outline_client import OutlineClient, OutlineError

logger = get_logger(__name__)

# Name stamped on keys we mint.
_KEY_NAME = "moneta-mcp"
_CACHE_PREFIX = "outline-mcp:api-key:"
# Cache lifetime. Minted keys self-expire (_KEY_TTL_DAYS) a margin LATER than this,
# so a cached key is always re-minted before the underlying Outline key expires.
_CACHE_TTL_SECONDS = 7 * 24 * 3600
# Minted keys carry an expiresAt so they self-clean — we do NOT delete keys (a
# revoke-on-mint races concurrent/cross-pod mints and can invalidate an in-flight
# key). Must exceed the cache TTL above.
_KEY_TTL_DAYS = 8
# Distinct from storage.py's OAuth-state salt so the two key spaces never collide.
_KEY_SALT = "outline-mcp-api-key-cache"

# Fallback when MCP_OAUTH_STORAGE_URL is unset. Process-local; lost on restart,
# which only forces a re-mint.
_memory_cache: dict[str, str] = {}

# Per-identity locks serialize minting within this process so parallel tool calls
# for the same user don't stampede apiKeys.create (the second waits, then
# cache-hits). Created lazily; the get-or-create is await-free, so it's atomic on
# the single-threaded asyncio loop. (Cross-pod, each process mints its own
# self-expiring key — bounded and race-free, since we never delete.)
_locks: dict[str, asyncio.Lock] = {}

# Outline's messages for a 401 on the fwd: path. The error id is
# "authentication_required" for all of them, so the message tells them apart.
_HEADERS_IGNORED_MESSAGE = "authentication required"
_CORPORATE_GATE_MESSAGE = "access denied"


class EdgeSecretMissingError(OutlineClientError):
    def __init__(self) -> None:
        super().__init__(
            "Outline ignored the SSO sign-in headers on the API-key mint because this server sent no edge "
            f"secret: {EDGE_SECRET_ENV} is unset, a placeholder, not printable ASCII or shorter than "
            f"{MIN_EDGE_SECRET_LENGTH} characters. An operator must set it to Outline's MPASS_EDGE_SECRET."
        )


class EdgeSecretRejectedError(OutlineClientError):
    def __init__(self) -> None:
        super().__init__(
            "Outline ignored the SSO sign-in headers on the API-key mint although this server sent its edge "
            f"secret. An operator must check that {EDGE_SECRET_ENV} matches Outline's MPASS_EDGE_SECRET, that "
            "MPASS_EDGE_SECRET is set (32+ characters), and that Outline runs with AUTH_TYPE=sso."
        )


class CorporateGateError(OutlineClientError):
    def __init__(self) -> None:
        super().__init__(
            "Outline's corporate-ID gate refused the API-key mint: the forwarded mPass token is missing, "
            "expired, issued to another client (MPASS_OIDC_CLIENT_ID), or not from this organisation."
        )


def _lock_for(identity: str) -> asyncio.Lock:
    lock = _locks.get(identity)
    if lock is None:
        lock = asyncio.Lock()
        _locks[identity] = lock
    return lock


def internal_api_url() -> str:
    """Outline base URL for the Cognito path — the internal docker/cluster URL.

    Falls back to ``OUTLINE_API_URL`` only when the internal URL is unset (e.g. a
    non-devstack deploy with a non-mPass route). ``OutlineClient`` appends ``/api``
    itself, so the bare host (``http://outline:3000``) is fine.
    """
    return os.getenv("OUTLINE_INTERNAL_BASE_URL", "").strip() or os.getenv("OUTLINE_API_URL", "").strip()


# --- per-user key cache ----------------------------------------------------


def _redis_client() -> Any | None:
    """Sync redis client for ``MCP_OAUTH_STORAGE_URL``, or ``None`` for memory cache."""
    url = os.getenv("MCP_OAUTH_STORAGE_URL", "").strip()
    if not url or urlparse(url).scheme not in {"redis", "rediss", "valkey", "valkeys"}:
        return None
    import redis  # local: only when a redis URL is configured

    # redis-py understands redis(s):// only; normalise the valkey aliases.
    normalised = url.replace("valkeys://", "rediss://", 1).replace("valkey://", "redis://", 1)
    return redis.Redis.from_url(normalised)


def _fernet() -> Fernet | None:
    """Fernet built from the same key material as the OAuth-state store, or ``None``."""
    key_material = os.getenv("OIDC_CLIENT_SECRET", "").strip() or os.getenv("MCP_JWT_SIGNING_KEY", "").strip()
    if not key_material:
        return None
    return Fernet(key=derive_jwt_key(high_entropy_material=key_material, salt=_KEY_SALT))


def _cache_get(identity: str) -> str | None:
    client = _redis_client()
    if client is None:
        return _memory_cache.get(identity)
    try:
        raw = client.get(_CACHE_PREFIX + identity)
    except Exception as exc:  # noqa: BLE001 — cache is best-effort
        logger.warning("api-key cache read failed (%s); will mint", exc)
        return None
    if not raw:
        return None
    fernet = _fernet()
    if fernet is None:
        return raw.decode() if isinstance(raw, bytes) else str(raw)
    try:
        return fernet.decrypt(raw).decode()
    except Exception as exc:  # noqa: BLE001 — stale/rotated key → re-mint
        logger.warning("api-key cache decrypt failed (%s); will re-mint", exc)
        return None


def _cache_set(identity: str, key: str) -> None:
    client = _redis_client()
    if client is None:
        _memory_cache[identity] = key
        return
    fernet = _fernet()
    value: bytes = fernet.encrypt(key.encode()) if fernet else key.encode()
    try:
        client.set(_CACHE_PREFIX + identity, value, ex=_CACHE_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001 — fall back to memory
        logger.warning("api-key cache write failed (%s); caching in-process", exc)
        _memory_cache[identity] = key


# --- mint (bootstrap via header-injection on the internal URL) -------------


def _verify_ssl() -> bool:
    return os.getenv("OUTLINE_VERIFY_SSL", "true").lower() not in ("false", "0", "no")


def _timeout() -> httpx.Timeout:
    return httpx.Timeout(
        connect=float(os.getenv("OUTLINE_CONNECT_TIMEOUT", "5.0")),
        read=float(os.getenv("OUTLINE_TIMEOUT", "30.0")),
        write=float(os.getenv("OUTLINE_WRITE_TIMEOUT", "30.0")),
        pool=5.0,
    )


def _isolated_http_client(transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    """A fresh httpx client with its OWN empty cookie jar, for the mint only.

    The mint MUST NOT use ``OutlineClient``'s process-wide shared pool. On the
    ``fwd:`` path Outline issues an ``accessToken`` cookie (ForwardAuth session
    JWT); a shared jar would store it and replay it on the next request. Outline's
    ``parseAuthentication`` reads that cookie *before* the ``X-Auth-Request-Email``
    header, so the transport becomes ``cookie`` — which (a) bypasses the intended
    ``fwd:`` mint path and (b) trips CSRF protection (the MCP never holds a CSRF
    cookie), yielding ``403 csrf_error``. A throwaway per-mint client keeps each
    mint cookie-isolated. Mints are rare (once per user per cache lifetime), so
    forgoing the connection pool here is cheap.
    """
    # follow_redirects=False: a mint is a single POST that never legitimately
    # redirects. Following one could replay a just-set accessToken cookie, or
    # carry the edge secret and identity headers to another host.
    return httpx.AsyncClient(timeout=_timeout(), follow_redirects=False, verify=_verify_ssl(), transport=transport)


class _RefuseAllCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request) -> bool:  # noqa: ANN001 — stdlib signature
        return False


_steady_state_client: httpx.AsyncClient | None = None


def steady_state_http_client() -> httpx.AsyncClient:
    """The process-wide client for minted-key (Bearer) calls.

    It refuses cookies, so no Outline session can leak between users, and its
    request hook refuses ``X-Auth-Request-*`` and ``X-Mpass-Edge-Secret``: only
    the mint may send those. The refusing jar is passed as is, since wrapping
    it in ``httpx.Cookies()`` would copy it into a jar with the default policy.
    """
    global _steady_state_client
    if _steady_state_client is None or _steady_state_client.is_closed:
        _steady_state_client = guarded_http_client(
            timeout=_timeout(),
            limits=httpx.Limits(
                max_connections=int(os.getenv("OUTLINE_MAX_CONNECTIONS", "100")),
                max_keepalive_connections=int(os.getenv("OUTLINE_MAX_KEEPALIVE", "20")),
                keepalive_expiry=30.0,
            ),
            follow_redirects=True,
            verify=_verify_ssl(),
            cookies=CookieJar(policy=_RefuseAllCookies()),
        )
    return _steady_state_client


async def close_steady_state_client() -> None:
    global _steady_state_client
    if _steady_state_client is not None:
        await _steady_state_client.aclose()
        _steady_state_client = None


def _identity_client(
    email: str,
    internal_url: str,
    http_client: httpx.AsyncClient,
    access_token: str | None = None,
) -> OutlineClient:
    """An OutlineClient that authenticates by injecting ``X-Auth-Request-Email``.

    It also carries the edge secret when one is usable (see
    :func:`outline_mcp.moneta.edge.edge_headers`); an unusable one is left out
    so an Outline without the edge check keeps working.

    Used only to bootstrap the key (``apiKeys.create``) on Outline's ``fwd:`` APP
    path. No ``Authorization`` header — see the module docstring for why that
    matters. ``http_client`` is a caller-owned, cookie-isolated client (see
    :func:`_isolated_http_client`), never the shared pool.

    When ``access_token`` is set, it is forwarded as ``X-Auth-Request-Access-Token``
    — the header Outline's ``fwd:`` corporate-ID gate (``SMB_CORPORATE_ID``) reads
    to verify ``custom:corporate_id``/``custom:is_corporate``, exactly as
    oauth2-proxy forwards it on the browser path. Omitting it makes the mint 401
    ("Access denied: missing access token") on corporate-gated deployments.
    """
    headers = {**edge_headers(), "X-Auth-Request-Email": email}
    if access_token:
        headers["X-Auth-Request-Access-Token"] = access_token
    return OutlineClient(
        api_url=internal_url,
        auth_headers=headers,
        http_client=http_client,
    )


def _error_message(exc: OutlineError) -> str:
    response = getattr(exc.__cause__, "response", None)
    if response is None:
        return ""
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        return ""
    message = body.get("message") if isinstance(body, dict) else None
    return message.strip().lower() if isinstance(message, str) else ""


def _mint_refusal(exc: OutlineError, *, edge_secret_sent: bool) -> OutlineClientError | None:
    """The operator-facing error for a 401 Outline gives only to the fwd: path, or ``None``."""
    if exc.status_code != 401:
        return None
    message = _error_message(exc)
    if message == _HEADERS_IGNORED_MESSAGE:
        return EdgeSecretRejectedError() if edge_secret_sent else EdgeSecretMissingError()
    if message == _CORPORATE_GATE_MESSAGE:
        return CorporateGateError()
    return None


async def _mint(
    email: str,
    internal_url: str,
    access_token: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str | None:
    """Mint a self-expiring ``ol_api_`` key for the SSO user via the ``fwd:`` APP path.

    Returns the raw key (``data.value``, populated only at create time), or ``None``
    on failure. The key carries ``expiresAt`` so it self-cleans — we never delete
    keys (a revoke-on-mint would race concurrent/cross-pod mints). ``access_token``
    is forwarded to clear Outline's corporate-ID gate (see :func:`_identity_client`).

    Raises :class:`EdgeSecretMissingError`, :class:`EdgeSecretRejectedError`
    or :class:`CorporateGateError` when Outline's 401 names one of those causes.
    """
    expires_at = (datetime.now(timezone.utc) + timedelta(days=_KEY_TTL_DAYS)).isoformat()
    edge_secret_sent = bool(edge_headers())
    try:
        # A fresh cookie-isolated client per mint — see _isolated_http_client.
        async with _isolated_http_client(transport) as http_client:
            resp = await _identity_client(email, internal_url, http_client, access_token).post(
                "apiKeys.create", {"name": _KEY_NAME, "expiresAt": expires_at}
            )
    except OutlineError as exc:
        refusal = _mint_refusal(exc, edge_secret_sent=edge_secret_sent)
        if refusal is not None:
            logger.warning("api-key mint refused: %s", refusal)
            raise refusal from None
        logger.warning("api-key mint failed: %s", exc)
        return None
    value = (resp.get("data") or {}).get("value")
    if not isinstance(value, str) or not value:
        logger.warning("api-key mint response had no usable 'data.value' field")
        return None
    logger.debug("api-key mint: created new Outline API key (len=%d, expires=%s)", len(value), expires_at)
    return value


async def _get_or_mint(identity: str, internal_url: str, access_token: str | None = None) -> str | None:
    """Return the cached ``ol_api_`` key for ``identity``, minting + caching if absent.

    A per-identity lock serializes the cache-miss path so parallel tool calls for
    the same user mint at most once (the rest cache-hit on the double-check).
    ``access_token`` is used only on the mint (cache-miss) path — it is NOT part
    of the cache key (the minted key belongs to the identity, and the access token
    rotates hourly).
    """
    cached = _cache_get(identity)
    if cached:
        logger.debug("api-key: cache hit for identity=%s", identity)
        return cached
    async with _lock_for(identity):
        cached = _cache_get(identity)  # double-check: another task may have minted
        if cached:
            return cached
        key = await _mint(identity, internal_url, access_token)
        if key:
            _cache_set(identity, key)
            logger.debug("api-key: minted + cached for identity=%s", identity)
        return key


async def build_outline_client() -> OutlineClient | None:
    """Return an :class:`OutlineClient` for the Cognito path, or ``None`` otherwise.

    ``None`` means the request is *not* on the Cognito path (stdio / header key) —
    upstream env/header resolution handles it. On the Cognito path, returns a
    client authenticated with the user's minted ``ol_api_`` key (``Authorization:
    Bearer``) against the internal Outline URL. Fails closed
    (:class:`OutlineClientError`) if the internal URL is unset or minting fails,
    rather than fall back to a wrong/absent credential.
    """
    stored = stored_access_token()
    if stored is None:
        return None
    # identity_email_for returns the email (or cognito:username) from the id_token;
    # we use it both as the X-Auth-Request-Email for the mint and as the cache key.
    identity = identity_email_for(stored.claims)
    if identity is None:
        return None

    url = internal_api_url()
    if not url:
        raise OutlineClientError(
            "Cognito path requires OUTLINE_INTERNAL_BASE_URL (e.g. http://outline:3000) "
            "to mint and use the per-user Outline API key."
        )

    # Forwarded as X-Auth-Request-Access-Token so the mint clears Outline's
    # corporate-ID gate (SMB_CORPORATE_ID). Only consumed on a cache-miss mint.
    access_token = upstream_access_token_for(stored.claims)
    key = await _get_or_mint(identity, url, access_token)
    if not key:
        # A corporate-gated Outline (SMB_CORPORATE_ID) rejects the mint when no
        # access token is forwarded; surface that likely cause rather than a bare
        # failure (the real reason is also in the mint's warning log).
        if access_token is None:
            raise OutlineClientError(
                "Failed to mint an Outline API key for the SSO user: no upstream access "
                "token was available to forward. If this Outline enforces SMB_CORPORATE_ID, "
                "the mint cannot clear its corporate-ID gate without one."
            )
        raise OutlineClientError("Failed to mint an Outline API key for the SSO user")

    logger.debug("build_outline_client: Cognito path — using minted key for identity=%s", identity)
    return OutlineClient(api_key=key, api_url=url, http_client=steady_state_http_client())
