"""Tests for the Moneta fork (Cognito / mPass) auth module — minted-key hybrid.

Covers identity resolution, the per-user key cache, and the mint/build
orchestration (Outline calls mocked). The full live flow (Cognito OAuth →
internal-URL apiKeys.create via fwd: → Bearer key calls) is a Phase-3 devstack
gate (see the plan's verification section).
"""

from __future__ import annotations

import asyncio

import pytest

from outline_mcp.client import OutlineClientError
from outline_mcp.moneta import apitoken
from outline_mcp.moneta.client import identity_email_for
from outline_mcp.moneta.cognito import ID_TOKEN_KEY, UPSTREAM_CLAIMS_KEY
from outline_mcp.outline_client import OutlineClient


def _claims(id_token: str = "idtok", email: str | None = "u@example.com", username: str | None = None) -> dict:
    upstream: dict = {ID_TOKEN_KEY: id_token}
    if email is not None:
        upstream["email"] = email
    if username is not None:
        upstream["cognito:username"] = username
    return {UPSTREAM_CLAIMS_KEY: upstream}


class _Tok:
    def __init__(self, claims: dict) -> None:
        self.claims = claims


# --- identity resolution ---------------------------------------------------


def test_identity_email_prefers_email() -> None:
    assert identity_email_for(_claims(email="a@b.com", username="bob")) == "a@b.com"


def test_identity_email_falls_back_to_username() -> None:
    assert identity_email_for(_claims(email=None, username="1020010")) == "1020010"


def test_identity_email_none_without_id_token() -> None:
    assert identity_email_for({UPSTREAM_CLAIMS_KEY: {"email": "a@b.com"}}) is None
    assert identity_email_for({}) is None
    assert identity_email_for(None) is None


# --- key cache -------------------------------------------------------------


def test_memory_cache_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_OAUTH_STORAGE_URL", raising=False)
    apitoken._memory_cache.clear()
    assert apitoken._cache_get("ident") is None
    apitoken._cache_set("ident", "ol_api_secret")
    assert apitoken._cache_get("ident") == "ol_api_secret"


# --- internal url ----------------------------------------------------------


def test_internal_api_url_prefers_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", "http://outline:3000")
    monkeypatch.setenv("OUTLINE_API_URL", "https://docs.example.com/api")
    assert apitoken.internal_api_url() == "http://outline:3000"


# --- build_outline_client orchestration ------------------------------------


async def test_build_none_without_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Outside an HTTP request (stdio), the moneta path is inert."""
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: None)
    assert await apitoken.build_outline_client() is None


async def test_build_none_for_non_cognito(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: _Tok({}))
    assert await apitoken.build_outline_client() is None


async def test_build_requires_internal_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: _Tok(_claims(email="u@example.com")))
    monkeypatch.delenv("OUTLINE_INTERNAL_BASE_URL", raising=False)
    monkeypatch.delenv("OUTLINE_API_URL", raising=False)
    with pytest.raises(OutlineClientError):
        await apitoken.build_outline_client()


async def test_build_uses_cached_key_without_minting(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cached key short-circuits minting; the client uses it as a Bearer."""
    monkeypatch.delenv("MCP_OAUTH_STORAGE_URL", raising=False)
    apitoken._memory_cache.clear()
    apitoken._cache_set("u@example.com", "ol_api_cached")
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: _Tok(_claims(email="u@example.com")))
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", "http://outline:3000")

    async def _boom(*_a, **_k):
        raise AssertionError("should not mint when cached")

    monkeypatch.setattr(apitoken, "_mint", _boom)

    client = await apitoken.build_outline_client()
    assert isinstance(client, OutlineClient)
    assert client._auth_header_dict() == {"Authorization": "Bearer ol_api_cached"}
    assert client.api_url == "http://outline:3000/api"


async def test_build_mints_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    """No cached key → mint once, cache it, return a Bearer client."""
    monkeypatch.delenv("MCP_OAUTH_STORAGE_URL", raising=False)
    apitoken._memory_cache.clear()
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: _Tok(_claims(email="new@example.com")))
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", "http://outline:3000")

    minted: list[tuple[str, str]] = []

    async def _fake_mint(email: str, url: str) -> str:
        minted.append((email, url))
        return "ol_api_minted"

    monkeypatch.setattr(apitoken, "_mint", _fake_mint)

    client = await apitoken.build_outline_client()
    assert client._auth_header_dict() == {"Authorization": "Bearer ol_api_minted"}
    assert minted == [("new@example.com", "http://outline:3000")]
    # cached for next time
    assert apitoken._cache_get("new@example.com") == "ol_api_minted"


async def test_build_fails_closed_when_mint_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_OAUTH_STORAGE_URL", raising=False)
    apitoken._memory_cache.clear()
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: _Tok(_claims(email="fail@example.com")))
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", "http://outline:3000")

    async def _fail_mint(*_a, **_k):
        return None

    monkeypatch.setattr(apitoken, "_mint", _fail_mint)
    with pytest.raises(OutlineClientError):
        await apitoken.build_outline_client()


async def test_mint_creates_self_expiring_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """_mint injects identity and creates a single self-expiring key (no delete)."""
    calls: list[tuple[str, dict]] = []

    class _FakeClient:
        def __init__(self, api_url, auth_headers=None):
            self.api_url = api_url
            self.auth_headers = auth_headers

        async def post(self, endpoint, data=None):
            calls.append((endpoint, data or {}))
            assert endpoint == "apiKeys.create"  # no list/delete — we never revoke
            return {"data": {"id": "new1", "value": "ol_api_fresh"}}

    monkeypatch.setattr(apitoken, "OutlineClient", _FakeClient)
    value = await apitoken._mint("user@example.com", "http://outline:3000")
    assert value == "ol_api_fresh"
    assert [c[0] for c in calls] == ["apiKeys.create"]
    body = calls[0][1]
    assert body["name"] == "moneta-mcp"
    assert "expiresAt" in body and body["expiresAt"]  # self-cleaning


async def test_concurrent_get_or_mint_mints_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Parallel same-user cache misses mint exactly once (lock + double-check)."""
    monkeypatch.delenv("MCP_OAUTH_STORAGE_URL", raising=False)
    apitoken._memory_cache.clear()
    apitoken._locks.clear()
    mint_count = 0

    async def _slow_mint(email: str, url: str) -> str:
        nonlocal mint_count
        mint_count += 1
        await asyncio.sleep(0.01)  # widen the race window
        return "ol_api_once"

    monkeypatch.setattr(apitoken, "_mint", _slow_mint)
    results = await asyncio.gather(*[apitoken._get_or_mint("same@user.com", "http://outline:3000") for _ in range(8)])
    assert results == ["ol_api_once"] * 8
    assert mint_count == 1  # the 7 others cache-hit on the double-check


def test_outline_client_auth_headers_override() -> None:
    """The base client honours pluggable auth headers (no api_key required)."""
    client = OutlineClient(api_url="http://outline:3000", auth_headers={"X-Auth-Request-Email": "x@y.com"})
    assert client._auth_header_dict() == {"X-Auth-Request-Email": "x@y.com"}
