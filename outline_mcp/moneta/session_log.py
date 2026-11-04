"""One-line, token-free context for an MCP session whose upstream refresh failed.

FastMCP logs refresh failures without saying whose session died, so a dead
session could only be matched to a user by timing. These helpers render the
stored upstream token set as ``key=value`` fields: the user from the stored
id_token's claims, the MCP client, the session age and an 8-char sha256 prefix of
the upstream token id for correlation. No token value is ever rendered.

Session age is measured from ``UpstreamTokenSet.created_at``, which FastMCP sets
at the authorization-code exchange and leaves untouched on every refresh, so it
is the time since the user's original login.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from typing import Any

import jwt
from fastmcp.server.auth.oauth_proxy.models import UpstreamTokenSet

UNKNOWN = "-"
DETAIL_MAX_CHARS = 200
SECONDS_PER_DAY = 86400
SECONDS_PER_HOUR = 3600
SECONDS_PER_MINUTE = 60


def fingerprint(value: str) -> str:
    """Correlation id for a secret-adjacent value: the first 8 hex chars of its sha256."""
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def format_age(seconds: float) -> str:
    """Render a duration as ``<d>d<hh>h<mm>m<ss>s`` so multi-day sessions read at a glance."""
    days, rest = divmod(max(int(seconds), 0), SECONDS_PER_DAY)
    hours, rest = divmod(rest, SECONDS_PER_HOUR)
    minutes, secs = divmod(rest, SECONDS_PER_MINUTE)
    return f"{days}d{hours:02d}h{minutes:02d}m{secs:02d}s"


def id_token_claims(raw_token_data: Mapping[str, Any]) -> dict[str, Any]:
    """Claims of the stored id_token, or ``{}`` when there is none or it cannot be decoded.

    Unverified on purpose: the id_token came from the provider's own call to the
    token endpoint and is only read here to name the user in a log line.
    """
    id_token = raw_token_data.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        return {}
    try:
        return jwt.decode(id_token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}


def identity_fields(token_data: Mapping[str, Any]) -> dict[str, Any]:
    claims = id_token_claims(token_data)
    return {"sub": claims.get("sub"), "email": claims.get("email"), "username": claims.get("cognito:username")}


def session_fields(
    token_set: UpstreamTokenSet | None,
    *,
    client_id: str | None = None,
    sealed_claims: Mapping[str, Any] | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Who owns the session and how old it is.

    Without a stored token set, the identity comes from ``sealed_claims`` (the
    ``upstream_claims`` sealed in the verified FastMCP token) and ``client_id``
    from the caller; age and correlation id are then unknown.
    """
    if token_set is None:
        return {
            **identity_fields(sealed_claims or {}),
            "client_id": client_id,
            "session_age": None,
            "upstream_token": None,
        }
    current = time.time() if now is None else now
    return {
        **identity_fields(token_set.raw_token_data or {}),
        "client_id": token_set.client_id or client_id,
        "session_age": format_age(current - token_set.created_at),
        "upstream_token": fingerprint(token_set.upstream_token_id),
    }


def error_fields(exc: BaseException) -> dict[str, Any]:
    """What upstream said: exception class, HTTP status (5xx) and OAuth error code (4xx)."""
    return {
        "error": type(exc).__name__,
        "status": getattr(getattr(exc, "response", None), "status_code", None),
        "oauth_error": getattr(exc, "error", None),
        "detail": _first_line(_error_text(exc)),
    }


def render(fields: Mapping[str, Any]) -> str:
    """``key=value`` pairs on one line; missing values print as ``-``, spaced values are quoted."""
    return " ".join(f"{key}={_render_value(value)}" for key, value in fields.items())


def describe_failure(
    token_set: UpstreamTokenSet | None,
    exc: BaseException,
    *,
    client_id: str | None = None,
    sealed_claims: Mapping[str, Any] | None = None,
    now: float | None = None,
) -> str:
    session = session_fields(token_set, client_id=client_id, sealed_claims=sealed_claims, now=now)
    return render({**session, **error_fields(exc)})


def describe_session(token_set: UpstreamTokenSet, *, now: float | None = None) -> str:
    refresh_token = "present" if token_set.refresh_token else "absent"
    return render({**session_fields(token_set, now=now), "refresh_token": refresh_token})


def _error_text(exc: BaseException) -> str:
    return getattr(exc, "error_description", None) or getattr(exc, "description", None) or str(exc)


def _first_line(text: str) -> str | None:
    lines = text.strip().splitlines()
    return lines[0][:DETAIL_MAX_CHARS] if lines else None


def _render_value(value: Any) -> str:
    if value is None or value == "":
        return UNKNOWN
    text = str(value)
    needs_quotes = any(char.isspace() or char in '"=' for char in text)
    return json.dumps(text) if needs_quotes else text
