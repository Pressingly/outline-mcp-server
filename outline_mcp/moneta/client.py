"""Identity resolution for the Cognito path (Moneta fork).

Resolves the SSO identity (email, or ``cognito:username``) captured from the
user's Cognito **id_token** by
:class:`outline_mcp.moneta.cognito.OutlineCognitoProvider`.
:mod:`outline_mcp.moneta.apitoken` uses that identity two ways: as the
``X-Auth-Request-Email`` injected to bootstrap a per-user ``ol_api_`` key on
Outline's ``fwd:`` APP path, and as the cache key for that minted key.

Why not the id_token Bearer: Outline's ``parseAuthentication``
(``server/middlewares/authentication.ts``) extracts ``Authorization: Bearer``
*before* it consults ``X-Auth-Request-Email``, and an external Cognito JWT fails
Outline's token checks → 401. The mint call therefore sends only the identity
header (no Authorization) to reach the ``fwd:<email>`` path; steady-state calls
then use the minted key as a Bearer.
"""

from __future__ import annotations

from typing import Any

from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from fastmcp.utilities.logging import get_logger

from outline_mcp.moneta.cognito import (
    COGNITO_USERNAME_CLAIM,
    EMAIL_CLAIM,
    ID_TOKEN_KEY,
    UPSTREAM_CLAIMS_KEY,
)

logger = get_logger(__name__)


def stored_access_token() -> AccessToken | None:
    """Validated token for the in-flight HTTP request, or ``None`` in stdio mode.

    ``get_access_token()`` raises ``RuntimeError`` outside an HTTP request scope.
    """
    try:
        return get_access_token()
    except RuntimeError:
        return None


def identity_email_for(claims: dict[str, Any] | None) -> str | None:
    """Return the SSO identity to inject as ``X-Auth-Request-Email``, or ``None``.

    ``None`` means this is *not* the Cognito path (no upstream id_token) — the
    stdio / ``x-outline-api-key`` header modes keep their own credential.

    Prefers a real, email-shaped ``email`` claim; federated users often carry a
    placeholder or absent email, so falls back to ``cognito:username`` (Outline
    appends ``@DEFAULT_EMAIL_DOMAIN`` to non-email-shaped values, matching what
    oauth2-proxy would forward).
    """
    if not claims:
        return None
    upstream = claims.get(UPSTREAM_CLAIMS_KEY)
    if not isinstance(upstream, dict):
        return None
    if not isinstance(upstream.get(ID_TOKEN_KEY), str) or not upstream.get(ID_TOKEN_KEY):
        return None
    email = upstream.get(EMAIL_CLAIM)
    if isinstance(email, str) and "@" in email:
        return email
    username = upstream.get(COGNITO_USERNAME_CLAIM)
    if isinstance(username, str) and username:
        return username
    return None
