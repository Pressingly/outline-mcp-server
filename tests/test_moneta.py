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

    async def _fake_mint(email: str, url: str, access_token: str | None = None) -> str:
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
        def __init__(self, api_url, auth_headers=None, http_client=None):
            self.api_url = api_url
            self.auth_headers = auth_headers
            # The mint must pass a dedicated cookie-isolated client, never the pool.
            assert http_client is not None

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

    async def _slow_mint(email: str, url: str, access_token: str | None = None) -> str:
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


# --- mint cookie-isolation (CSRF regression) --------------------------------
# Outline stamps an accessToken cookie on the fwd: response. If the mint reused
# a shared cookie jar, a later mint would replay that cookie, flip Outline's auth
# transport to `cookie`, and 403 with csrf_error. Each mint must use a fresh,
# cookie-isolated client.


async def test_isolated_http_client_is_fresh_each_call() -> None:
    """_isolated_http_client hands out a distinct client with an empty jar,
    and never the shared pool."""
    import httpx

    c1 = apitoken._isolated_http_client()
    c2 = apitoken._isolated_http_client()
    try:
        assert c1 is not c2
        assert c1 is not OutlineClient._client_pool
        assert len(c1.cookies.jar) == 0
        assert isinstance(c1, httpx.AsyncClient)
    finally:
        await c1.aclose()
        await c2.aclose()


async def test_mint_does_not_replay_accesstoken_cookie_across_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a mint retry must not replay Outline's accessToken cookie.

    Exercises the REAL post() retry loop through a MockTransport. Outline stamps
    Set-Cookie: accessToken on the fwd: response (here on both the 429 and the
    200). Without the per-attempt jar clear, the retry after the 429 would send
    that cookie back — flipping Outline's transport to `cookie` and producing the
    prod `403 csrf_error`. The clear keeps every attempt cookie-free.
    """
    import httpx

    seen_cookies: list[str | None] = []
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookies.append(request.headers.get("cookie"))
        calls["n"] += 1
        if calls["n"] == 1:
            # Rate-limited, with an accessToken cookie riding along. Retry-After
            # "0" keeps the test's backoff sleep instant.
            return httpx.Response(
                429,
                json={"ok": False},
                headers={"Retry-After": "0", "set-cookie": "accessToken=poison; Path=/"},
            )
        return httpx.Response(
            200,
            json={"data": {"value": "ol_api_minted"}},
            headers={"set-cookie": "accessToken=poison; Path=/"},
        )

    # Inject only the transport; the real _isolated_http_client's follow_redirects
    # and the real post() retry/clear logic are what we're testing.
    def _mock_isolated() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)

    monkeypatch.setattr(apitoken, "_isolated_http_client", _mock_isolated)

    key = await apitoken._mint("u@example.com", "http://outline:3000")

    assert key == "ol_api_minted"
    assert calls["n"] == 2  # retried once after the 429
    # Crucially, the retry (2nd request) carried NO cookie despite the 429's
    # Set-Cookie — proving the per-attempt jar clear defeats intra-mint replay.
    assert seen_cookies == [None, None]


# --- corporate-ID gate: forward the access token (1b) -----------------------


def test_upstream_access_token_for_reads_claim() -> None:
    """The access token is read from upstream claims when present, else None."""
    from outline_mcp.moneta.client import upstream_access_token_for
    from outline_mcp.moneta.cognito import ACCESS_TOKEN_CLAIM

    claims = _claims(email="u@example.com")
    assert upstream_access_token_for(claims) is None  # absent by default
    claims[UPSTREAM_CLAIMS_KEY][ACCESS_TOKEN_CLAIM] = "acc.tok.jwt"
    assert upstream_access_token_for(claims) == "acc.tok.jwt"
    assert upstream_access_token_for(None) is None
    assert upstream_access_token_for({}) is None


async def _capture_mint_headers(monkeypatch: pytest.MonkeyPatch, access_token: str | None) -> dict[str, str]:
    """Run _mint through a MockTransport and return the request headers seen."""
    import httpx

    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(request.headers)
        return httpx.Response(200, json={"data": {"value": "ol_api_minted"}})

    monkeypatch.setattr(
        apitoken,
        "_isolated_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    key = await apitoken._mint("u@example.com", "http://outline:3000", access_token)
    assert key == "ol_api_minted"
    return captured


async def test_mint_forwards_access_token_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression (1b): the mint forwards X-Auth-Request-Access-Token so Outline's
    corporate-ID gate accepts it, alongside the identity header."""
    headers = await _capture_mint_headers(monkeypatch, "acc.tok.jwt")
    assert headers.get("x-auth-request-email") == "u@example.com"
    assert headers.get("x-auth-request-access-token") == "acc.tok.jwt"


async def test_mint_omits_access_token_header_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """No access token → no X-Auth-Request-Access-Token header (non-corporate or
    non-Cognito deployments are unaffected)."""
    headers = await _capture_mint_headers(monkeypatch, None)
    assert headers.get("x-auth-request-email") == "u@example.com"
    assert "x-auth-request-access-token" not in headers


async def test_build_threads_access_token_to_mint(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_outline_client resolves the access token from claims and passes it
    to the mint (not into the cache key)."""
    from outline_mcp.moneta.cognito import ACCESS_TOKEN_CLAIM

    monkeypatch.delenv("MCP_OAUTH_STORAGE_URL", raising=False)
    apitoken._memory_cache.clear()
    claims = _claims(email="corp@example.com")
    claims[UPSTREAM_CLAIMS_KEY][ACCESS_TOKEN_CLAIM] = "acc.tok.jwt"
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: _Tok(claims))
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", "http://outline:3000")

    seen: dict[str, str | None] = {}

    async def _fake_mint(email: str, url: str, access_token: str | None = None) -> str:
        seen["access_token"] = access_token
        return "ol_api_minted"

    monkeypatch.setattr(apitoken, "_mint", _fake_mint)
    client = await apitoken.build_outline_client()
    assert client._auth_header_dict() == {"Authorization": "Bearer ol_api_minted"}
    assert seen["access_token"] == "acc.tok.jwt"


async def test_extract_upstream_claims_gates_the_access_token() -> None:
    """The access token rides only the resolve path (include_access_token=True),
    never the exchange-time seal — so the client-facing reference JWT stays lean
    while the mint still gets the token it needs for the corporate-ID gate."""
    import jwt

    from outline_mcp.moneta.cognito import ACCESS_TOKEN_CLAIM, OutlineCognitoProvider

    provider = object.__new__(OutlineCognitoProvider)  # bypass live-OIDC __init__
    id_token = jwt.encode({"email": "u@example.com"}, "k" * 32)
    idp_tokens = {ID_TOKEN_KEY: id_token, "access_token": "acc.tok.jwt"}

    exchange = await provider._extract_upstream_claims(idp_tokens)
    assert ACCESS_TOKEN_CLAIM not in exchange  # no bloat at exchange time
    assert exchange["email"] == "u@example.com"

    resolve = await provider._extract_upstream_claims(idp_tokens, include_access_token=True)
    assert resolve[ACCESS_TOKEN_CLAIM] == "acc.tok.jwt"  # available at mint time


# --- client access-token TTL (Issue 2 hardening) ---------------------------


def test_client_access_token_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default 24h; positive int honored; junk/non-positive falls back to default."""
    from outline_mcp.moneta.http import _client_access_token_ttl

    monkeypatch.delenv("MCP_ACCESS_TOKEN_TTL_SECONDS", raising=False)
    assert _client_access_token_ttl() == 86400
    monkeypatch.setenv("MCP_ACCESS_TOKEN_TTL_SECONDS", "3600")
    assert _client_access_token_ttl() == 3600
    for bad in ("not-int", "0", "-5", ""):
        monkeypatch.setenv("MCP_ACCESS_TOKEN_TTL_SECONDS", bad)
        assert _client_access_token_ttl() == 86400
