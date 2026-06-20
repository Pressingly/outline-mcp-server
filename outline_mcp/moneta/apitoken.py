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
   authorises the mint. Prior ``moneta-mcp``-named keys are revoked first so they
   don't accumulate.
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
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.utilities.logging import get_logger

from outline_mcp.client import OutlineClientError
from outline_mcp.moneta.client import identity_email_for, stored_access_token
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


def _identity_client(email: str, internal_url: str) -> OutlineClient:
    """An OutlineClient that authenticates by injecting ``X-Auth-Request-Email``.

    Used only to bootstrap the key (``apiKeys.create``) on Outline's ``fwd:`` APP
    path. No ``Authorization`` header — see the module docstring for why that matters.
    """
    return OutlineClient(api_url=internal_url, auth_headers={"X-Auth-Request-Email": email})


async def _mint(email: str, internal_url: str) -> str | None:
    """Mint a self-expiring ``ol_api_`` key for the SSO user via the ``fwd:`` APP path.

    Returns the raw key (``data.value``, populated only at create time), or ``None``
    on failure. The key carries ``expiresAt`` so it self-cleans — we never delete
    keys (a revoke-on-mint would race concurrent/cross-pod mints).
    """
    expires_at = (datetime.now(timezone.utc) + timedelta(days=_KEY_TTL_DAYS)).isoformat()
    try:
        resp = await _identity_client(email, internal_url).post(
            "apiKeys.create", {"name": _KEY_NAME, "expiresAt": expires_at}
        )
    except OutlineError as exc:
        logger.warning("api-key mint failed: %s", exc)
        return None
    value = (resp.get("data") or {}).get("value")
    if not isinstance(value, str) or not value:
        logger.warning("api-key mint response had no usable 'data.value' field")
        return None
    logger.debug("api-key mint: created new Outline API key (len=%d, expires=%s)", len(value), expires_at)
    return value


async def _get_or_mint(identity: str, internal_url: str) -> str | None:
    """Return the cached ``ol_api_`` key for ``identity``, minting + caching if absent.

    A per-identity lock serializes the cache-miss path so parallel tool calls for
    the same user mint at most once (the rest cache-hit on the double-check).
    """
    cached = _cache_get(identity)
    if cached:
        logger.debug("api-key: cache hit for identity=%s", identity)
        return cached
    async with _lock_for(identity):
        cached = _cache_get(identity)  # double-check: another task may have minted
        if cached:
            return cached
        key = await _mint(identity, internal_url)
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

    key = await _get_or_mint(identity, url)
    if not key:
        raise OutlineClientError("Failed to mint an Outline API key for the SSO user")

    logger.debug("build_outline_client: Cognito path — using minted key for identity=%s", identity)
    return OutlineClient(api_key=key, api_url=url)
