"""Cognito provider that surfaces id-token identity to the Outline API relay.

Why this exists
---------------
FastMCP's stock ``AWSCognitoProvider`` validates the inbound Cognito **access
token** and filters its claims down to ``{sub, username, cognito:groups}``. Two
facts about Cognito access tokens make that insufficient for reaching the same
Outline user as the browser/cookie login:

* they carry **no ``email`` claim** at all, and
* for users federated from an external IdP, ``username`` is an opaque Cognito
  UUID rather than the ``cognito:username`` that oauth2-proxy (mPass) keys on.

``OAuthProxy`` exposes the right seam: :meth:`_extract_upstream_claims` is called
with the full Cognito token response (access_token + id_token + …) at exchange
*and* refresh time, and whatever it returns is sealed inside the FastMCP-signed
reference JWT and handed back at request time as
``AccessToken.claims["upstream_claims"]``. We decode the id_token there and stash
``email``, ``cognito:username``, and the raw id_token string;
:mod:`outline_mcp.moneta.client` then forwards that id_token to Outline as the
Bearer token, so Outline's Traefik + mPass chain provisions the same user as the
web login (and authorizes minting an API key).

Trust note
----------
The id_token is decoded **without signature verification**, which is safe here:

* it arrives directly from Cognito's token endpoint over the provider's own
  server-to-server TLS call — never from the MCP client, and
* the extracted values are re-sealed inside the FastMCP JWT whose signature *is*
  verified on every request before ``upstream_claims`` is read.

The inbound access token is still independently JWKS-verified on every request by
the stock verifier, so this adds no auth-bypass surface — it only enriches the
identity forwarded downstream.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import jwt
from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.providers.aws import AWSCognitoProvider
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

# Key under which FastMCP's OAuthProxy embeds whatever _extract_upstream_claims
# returns inside the signed reference JWT (read back in outline_mcp.moneta.client).
UPSTREAM_CLAIMS_KEY = "upstream_claims"
# Sub-keys inside that dict.
ID_TOKEN_KEY = "id_token"
EMAIL_CLAIM = "email"
COGNITO_USERNAME_CLAIM = "cognito:username"

# Floor for a corrected `expires_in`, so a token that is already at (or past) its
# `exp` still yields a positive lifetime instead of a negative one. A non-positive
# value would collapse the JTI-mapping TTL and drop the session's access-token
# reference (the upstream store floors its own TTL). The trade is a deliberate ≤60s window — for a token that arrives
# already expired, refresh stays gated while JWKS validation already fails —
# after which the refresh grant recovers the session.
MIN_EXPIRES_IN_SECONDS = 60

# `_true_expires_in` truncates fractional seconds, so a lifetime the upstream
# already reported honestly comes back one second short. Treat that as a match
# and hand the original response straight through.
EXPIRES_IN_DRIFT_TOLERANCE_SECONDS = 1


def _true_expires_in(token_response: dict[str, Any]) -> int | None:
    """Real remaining lifetime of the upstream access token, from its own ``exp``.

    ``mpass-auth-proxy`` reports ``SESSION_COOKIE_MAX_AGE_SECONDS`` (7 days) as
    ``expires_in`` because oauth2-proxy — the session authority for the browser
    flow — trusts that value for its cookie lifetime. The Cognito access token
    underneath still expires in one hour.

    On the MCP path the session authority is FastMCP's ``OAuthProxy``, which keys
    renewal off ``expires_in``: it stores ``expires_at = now + expires_in`` and
    stamps the token it issues to the MCP client with the same lifetime. With the
    7-day value the stored expiry is a week out, so at the one-hour mark JWKS
    validation of the real token fails while the refresh gate stays shut — the
    request 401s and the MCP client is forced through a full interactive
    re-authorization. Deriving the value from the token's own ``exp`` restores the
    invariant: the client's token now expires when the upstream one does, and it
    renews through the refresh grant (which ``mpass-auth-proxy`` relays to Cognito)
    rather than re-authorizing. Note this makes the client-facing token hourly too
    — decoupling the two needs ``fastmcp_access_token_expiry_seconds``, absent from
    the fastmcp 3.2.x line the sibling MCP servers pin, so it is not used here.

    Returns ``None`` when the lifetime can't be determined, leaving the upstream
    value untouched.
    """
    access_token = token_response.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return None
    try:
        # Unverified by design, as elsewhere in this module: the response comes
        # from the provider's own server-to-server call, never from the client,
        # and this only reads a lifetime hint — the token is still JWKS-verified
        # on every request by the stock verifier.
        exp = jwt.decode(access_token, options={"verify_signature": False}).get("exp")
    except jwt.PyJWTError as exc:
        logger.warning("Could not decode upstream access_token to read exp: %s", exc)
        return None
    if not isinstance(exp, (int, float)):
        return None
    return max(int(exp - time.time()), MIN_EXPIRES_IN_SECONDS)


def _already_truthful(reported: Any, corrected: int) -> bool:
    """True when the upstream already reported the token's real lifetime."""
    if isinstance(reported, bool) or not isinstance(reported, (int, float)):
        return False
    return abs(reported - corrected) <= EXPIRES_IN_DRIFT_TOLERANCE_SECONDS


def _correct_expires_in(response: httpx.Response) -> httpx.Response:
    """authlib compliance hook rewriting ``expires_in`` to the token's real value.

    Registered for both the ``access_token_response`` and ``refresh_token_response``
    hooks: correcting only the first would let the refresh path re-store the
    inflated lifetime and wedge the session again an hour later.
    """
    if response.status_code != 200:
        return response
    try:
        body = response.json()
    except ValueError:
        return response
    if not isinstance(body, dict):
        return response

    corrected = _true_expires_in(body)
    if corrected is None or _already_truthful(body.get("expires_in"), corrected):
        return response

    logger.debug(
        "Corrected upstream expires_in %s → %d (from access_token exp)",
        body.get("expires_in"),
        corrected,
    )
    body["expires_in"] = corrected
    return httpx.Response(
        status_code=response.status_code,
        json=body,
        request=response.request,
    )


class OutlineCognitoProvider(AWSCognitoProvider):
    """``AWSCognitoProvider`` that forwards the upstream id_token's identity.

    Three overrides cooperate:

    * :meth:`_create_upstream_oauth_client` corrects the upstream ``expires_in``
      so the session renews instead of forcing an hourly re-authorization
      (see :func:`_true_expires_in`).
    * :meth:`_extract_upstream_claims` decodes the id_token at token-exchange
      time and returns ``{id_token, email, cognito:username}``.
    * :meth:`load_access_token` re-attaches that on **every inbound request**.
      This is required because fastmcp's ``OAuthProxy.load_access_token`` is a
      token-swap that returns the *upstream Cognito access token's* validation
      result — it discards the ``upstream_claims`` embedded in the issued JWT, so
      they never reach ``get_access_token().claims``. Without this override the
      relay would fall back to the access token (no ``email``; opaque UUID ``sub``
      for federated users) and Outline would provision the wrong account.
    """

    def _create_upstream_oauth_client(self) -> AsyncOAuth2Client:
        """Attach the ``expires_in`` correction to every upstream token call.

        This is ``OAuthProxy``'s single factory for the authlib client used by
        both the authorization-code exchange and the refresh grant, so one
        registration covers every path that stores an upstream token lifetime.
        See :func:`_true_expires_in` for why the correction is needed.
        """
        client = super()._create_upstream_oauth_client()
        client.register_compliance_hook("access_token_response", _correct_expires_in)
        client.register_compliance_hook("refresh_token_response", _correct_expires_in)
        return client

    async def _extract_upstream_claims(self, idp_tokens: dict[str, Any]) -> dict[str, Any] | None:
        id_token = idp_tokens.get(ID_TOKEN_KEY)
        if not isinstance(id_token, str) or not id_token:
            logger.warning(
                "Cognito token response has no id_token — Outline identity will fall "
                "back to the access token and may resolve the wrong user."
            )
            return None

        try:
            # Unverified by design (see module docstring): fresh from Cognito's
            # token endpoint, and re-sealed in the FastMCP-signed JWT.
            claims = jwt.decode(id_token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            logger.warning("Failed to decode Cognito id_token: %s", exc)
            return None

        extracted: dict[str, Any] = {ID_TOKEN_KEY: id_token}
        email = claims.get(EMAIL_CLAIM)
        if isinstance(email, str) and email:
            extracted[EMAIL_CLAIM] = email
        cognito_username = claims.get(COGNITO_USERNAME_CLAIM)
        if isinstance(cognito_username, str) and cognito_username:
            extracted[COGNITO_USERNAME_CLAIM] = cognito_username
        logger.debug(
            "extract_upstream_claims: id_token_len=%d email=%s cognito:username=%s",
            len(id_token),
            extracted.get(EMAIL_CLAIM),
            extracted.get(COGNITO_USERNAME_CLAIM),
        )
        return extracted

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Re-attach the upstream id_token to the validated access token.

        ``super().load_access_token`` (the token-swap) returns an ``AccessToken``
        built from the upstream Cognito *access* token, so we re-resolve the
        id_token from the stored token set and stash it under
        ``claims["upstream_claims"]`` where :mod:`outline_mcp.moneta.client` reads it.

        Fail-closed: if the id_token can't be resolved we return ``None`` (the
        request 401s) rather than let the caller forward the Cognito access token,
        whose ``sub``/``username`` is an opaque UUID for federated users and would
        provision the wrong Outline account.
        """
        validated = await super().load_access_token(token)
        if validated is None:
            logger.debug("load_access_token: upstream validation returned None (token invalid/expired)")
            return None

        upstream = await self._resolve_upstream_claims(token)
        if not upstream or not upstream.get(ID_TOKEN_KEY):
            logger.warning(
                "Cognito: could not resolve the upstream id_token for this session; "
                "refusing to forward the access token (would resolve the wrong Outline user). "
                "access-token sub=%s username=%s",
                (validated.claims or {}).get("sub"),
                (validated.claims or {}).get("username"),
            )
            return None

        new_claims = dict(validated.claims or {})
        new_claims[UPSTREAM_CLAIMS_KEY] = upstream
        logger.debug(
            "load_access_token: attached id_token identity (email=%s cognito:username=%s) over access-token sub=%s",
            upstream.get(EMAIL_CLAIM),
            upstream.get(COGNITO_USERNAME_CLAIM),
            new_claims.get("sub"),
        )
        return validated.model_copy(update={"claims": new_claims})

    async def _resolve_upstream_claims(self, token: str) -> dict[str, Any] | None:
        """Resolve the stored Cognito token response for an issued FastMCP JWT.

        Mirrors ``OAuthProxy.load_access_token``'s JTI → upstream-token-store
        lookup, then runs :meth:`_extract_upstream_claims` over the raw token
        response (which carries the id_token). Returns ``None`` on any miss so the
        caller can fail closed.
        """
        try:
            payload = self.jwt_issuer.verify_token(token)
            jti = payload.get("jti") if isinstance(payload, dict) else getattr(payload, "jti", None)
            if not jti:
                logger.debug("resolve_upstream_claims: verified token has no jti")
                return None
            jti_mapping = await self._jti_mapping_store.get(key=jti)
            if not jti_mapping:
                logger.debug("resolve_upstream_claims: no JTI mapping for jti=%s (expired?)", str(jti)[:8])
                return None
            upstream_id = getattr(jti_mapping, "upstream_token_id", None)
            if upstream_id is None and isinstance(jti_mapping, dict):
                upstream_id = jti_mapping.get("upstream_token_id")
            if not upstream_id:
                logger.debug("resolve_upstream_claims: JTI mapping has no upstream_token_id (jti=%s)", str(jti)[:8])
                return None
            token_set = await self._upstream_token_store.get(key=upstream_id)
            raw = getattr(token_set, "raw_token_data", None) if token_set else None
            if raw is None and isinstance(token_set, dict):
                raw = token_set.get("raw_token_data")
            if not isinstance(raw, dict):
                logger.debug(
                    "resolve_upstream_claims: no raw_token_data on upstream token set (upstream_id=%s)",
                    upstream_id,
                )
                return None
            logger.debug(
                "resolve_upstream_claims: jti=%s upstream_id=%s id_token_present=%s",
                str(jti)[:8],
                upstream_id,
                bool(raw.get("id_token")),
            )
            return await self._extract_upstream_claims(raw)
        except Exception as exc:  # noqa: BLE001 — fail closed on any resolution error
            logger.warning("Cognito: failed to resolve upstream id_token: %s", exc)
            return None
