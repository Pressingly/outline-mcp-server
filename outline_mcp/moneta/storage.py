"""HTTP-mode OAuth state storage selection.

FastMCP's :class:`AWSCognitoProvider` (via ``OAuthProxy``) keeps six
collections of OAuth state — DCR client registrations, in-flight authorize
transactions, authorization codes, upstream Cognito access/refresh tokens,
JTI mappings, and refresh-token metadata. By default these live in an
encrypted file tree inside the container, which means

- ``docker compose down && up`` wipes refresh tokens (every MCP client
  re-OAuths on next call), and
- horizontal scaling is impossible (state is per-container).

Setting ``MCP_OAUTH_STORAGE_URL`` swaps the file store for a Redis/Valkey
backend, Fernet-wrapped with a key derived from ``OIDC_CLIENT_SECRET``
(confidential clients — preferred when present) or ``MCP_JWT_SIGNING_KEY``
(public/PKCE clients) so the on-disk RDB never holds plaintext tokens.
Unset → fall through to FastMCP's default file store (back-compat for
users running the image outside the devstack).

The Redis client is built explicitly via ``redis.asyncio.Redis.from_url``
rather than ``RedisStore(url=...)``: the latter's URL helper (py-key-value-aio
0.4.x) keeps only host/port/db/user/password and silently drops the scheme
and every query parameter, so ``rediss://`` and ``?ssl_cert_reqs=none`` would
be discarded and the connection would fall back to plaintext. ``from_url`` is
redis-py's real parser — it honours ``rediss://`` (TLS on) and
``ssl_cert_reqs=none`` (skip cert verification), which is what the GKE TLS-only
Memorystore requires, while still accepting plain ``redis://`` for the
in-cluster Valkey on the Docker Compose deployments.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from cryptography.fernet import Fernet
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.utilities.logging import get_logger
from key_value.aio.protocols.key_value import AsyncKeyValue
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

logger = get_logger(__name__)

# Same salt FastMCP uses for the file-store encryption key
# (fastmcp/server/auth/oauth_proxy/proxy.py:458). Sharing the salt means
# rotating the chosen entropy source invalidates state in either backend
# consistently — no surprise where one store keeps decrypting while the
# other doesn't.
_STORAGE_KEY_SALT = "fastmcp-storage-encryption-key"

# redis-py's ``from_url`` only understands ``redis``/``rediss``; the
# ``valkey``/``valkeys`` aliases are normalised to those before parsing.
_SCHEME_ALIASES = {"valkey": "redis", "valkeys": "rediss"}
_ACCEPTED_SCHEMES = {"redis", "rediss", "valkey", "valkeys"}


@dataclass(frozen=True)
class RedisConfig:
    """A validated storage URL, normalised to a redis-py-compatible scheme.

    ``url`` is fed verbatim to :func:`redis.asyncio.Redis.from_url`, so it
    preserves the query string (e.g. ``?ssl_cert_reqs=none``). ``host``,
    ``port`` and ``db`` are retained for logging only.
    """

    url: str
    host: str
    port: int
    db: int


def parse_storage_url(raw: str) -> RedisConfig:
    """Parse and validate a ``redis(s)://`` / ``valkey(s)://`` storage URL.

    Pure-Python; no I/O, no client imports — separated from
    :func:`build_oauth_storage` so tests can verify URL handling without
    requiring the Redis client to be installed. ``valkey``/``valkeys``
    schemes are normalised to ``redis``/``rediss`` (redis-py does not
    recognise the Valkey aliases) while the rest of the URL — including any
    query parameters such as ``ssl_cert_reqs=none`` — is preserved.
    """
    parsed = urlparse(raw)
    if parsed.scheme not in _ACCEPTED_SCHEMES:
        raise ValueError(
            f"MCP_OAUTH_STORAGE_URL scheme must be redis://, rediss://, valkey:// or valkeys://, got {parsed.scheme!r}"
        )
    if not parsed.hostname:
        raise ValueError("MCP_OAUTH_STORAGE_URL is missing a hostname")

    db = 0
    if parsed.path and parsed.path != "/":
        try:
            db = int(parsed.path.lstrip("/"))
        except ValueError as exc:
            raise ValueError(f"MCP_OAUTH_STORAGE_URL path must be a numeric DB index, got {parsed.path!r}") from exc

    scheme = _SCHEME_ALIASES.get(parsed.scheme, parsed.scheme)
    normalised = urlunparse(parsed._replace(scheme=scheme)) if scheme != parsed.scheme else raw

    return RedisConfig(
        url=normalised,
        host=parsed.hostname,
        port=parsed.port or 6379,
        db=db,
    )


def build_oauth_storage() -> AsyncKeyValue | None:
    """Return the OAuth-state store for ``AWSCognitoProvider``.

    Returns ``None`` when ``MCP_OAUTH_STORAGE_URL`` is unset, signalling
    FastMCP to keep its default encrypted file store. When set to a
    ``redis(s)://`` or ``valkey(s)://`` URL, returns a :class:`RedisStore`
    wrapped in :class:`FernetEncryptionWrapper`.

    Raises ``ValueError`` when the URL is malformed or neither
    ``MCP_JWT_SIGNING_KEY`` nor ``OIDC_CLIENT_SECRET`` is set (without
    one of them the Fernet key cannot be derived deterministically).
    """
    raw = os.getenv("MCP_OAUTH_STORAGE_URL", "").strip()
    if not raw:
        return None

    config = parse_storage_url(raw)

    # Prefer the upstream client secret when present (confidential Cognito
    # client — the typical prod setup). Fall back to MCP_JWT_SIGNING_KEY
    # for public/PKCE clients (sandbox / no-secret deployments).
    key_material = os.getenv("OIDC_CLIENT_SECRET", "").strip() or os.getenv("MCP_JWT_SIGNING_KEY", "").strip()
    if not key_material:
        raise ValueError(
            "MCP_OAUTH_STORAGE_URL is set but neither MCP_JWT_SIGNING_KEY "
            "nor OIDC_CLIENT_SECRET is set; the Fernet encryption key "
            "cannot be derived without one of them."
        )

    # Imported lazily so unit tests for ``parse_storage_url`` and the
    # missing-key-material guard don't require the Redis client.
    from key_value.aio.stores.redis import RedisStore
    from redis.asyncio import Redis

    # Build the client explicitly so the scheme (``rediss://`` → TLS) and
    # query params (``ssl_cert_reqs=none``) survive — RedisStore(url=...)
    # would discard them. ``decode_responses=True`` matches the library's
    # default so the Fernet wrapper sees the str shape it expects.
    client = Redis.from_url(config.url, decode_responses=True)
    redis_store = RedisStore(client=client)
    encryption_key = derive_jwt_key(
        high_entropy_material=key_material,
        salt=_STORAGE_KEY_SALT,
    )
    logger.info(
        "OAuth state stored in redis://%s:%d/%d (Fernet-encrypted at rest)",
        config.host,
        config.port,
        config.db,
    )
    return FernetEncryptionWrapper(
        key_value=redis_store,
        fernet=Fernet(key=encryption_key),
        raise_on_decryption_error=False,
    )
