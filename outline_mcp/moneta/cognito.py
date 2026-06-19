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

from typing import Any

import jwt
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


class OutlineCognitoProvider(AWSCognitoProvider):
    """``AWSCognitoProvider`` that forwards the upstream id_token's identity.

    Two overrides cooperate:

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
