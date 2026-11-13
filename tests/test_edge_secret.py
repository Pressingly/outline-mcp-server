"""The mPass edge secret on the Outline API-key mint (FOSS-777)."""

from __future__ import annotations

import logging

import httpx
import pytest

from outline_mcp.moneta import apitoken, http
from outline_mcp.moneta.edge import (
    EDGE_SECRET_HEADER,
    TrustHeaderError,
    edge_secret_problem,
    guarded_http_client,
    reject_trust_headers,
    usable_edge_secret,
)
from tests.test_moneta import _claims, _Tok

SECRET = "s" * 40
INTERNAL_URL = "http://outline:3000"


def _outline_error(status: int, message: str) -> httpx.Response:
    return httpx.Response(
        status, json={"ok": False, "error": "authentication_required", "status": status, "message": message}
    )


def _minted() -> httpx.Response:
    return httpx.Response(200, json={"data": {"id": "k1", "value": "ol_api_fresh"}})


class _Recorder:
    def __init__(self, *responses: httpx.Response) -> None:
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responses.pop(0)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OUTLINE_EDGE_SECRET", raising=False)
    monkeypatch.delenv("MCP_OAUTH_STORAGE_URL", raising=False)
    apitoken._memory_cache.clear()
    apitoken._locks.clear()


@pytest.mark.parametrize(
    ("secret", "problem"),
    [
        ("", "unset"),
        ("CHANGE_ME_" + "x" * 40, "a placeholder"),
        ("é" * 40, "not printable ASCII"),
        ("a\tb" + "x" * 40, "not printable ASCII"),
        ("x" * 31, "shorter than 32 characters"),
        ("x" * 32, None),
    ],
)
def test_edge_secret_problem(secret: str, problem: str | None) -> None:
    assert edge_secret_problem(secret) == problem


def test_usable_edge_secret_is_trimmed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_EDGE_SECRET", f"  {SECRET}\n")
    assert usable_edge_secret() == SECRET


async def test_mint_sends_the_trimmed_edge_secret_with_the_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_EDGE_SECRET", f" {SECRET} ")
    outline = _Recorder(_minted())

    key = await apitoken._mint("u@example.com", INTERNAL_URL, "cognito-at", transport=outline.transport)

    assert key == "ol_api_fresh"
    [request] = outline.requests
    assert request.url == "http://outline:3000/api/apiKeys.create"
    assert request.headers[EDGE_SECRET_HEADER] == SECRET
    assert request.headers["X-Auth-Request-Email"] == "u@example.com"
    assert request.headers["X-Auth-Request-Access-Token"] == "cognito-at"
    assert "authorization" not in request.headers


@pytest.mark.parametrize("secret", ["", "CHANGE_ME_edge_secret_padding_padding", "too-short"])
async def test_mint_leaves_an_unusable_secret_out(monkeypatch: pytest.MonkeyPatch, secret: str) -> None:
    monkeypatch.setenv("OUTLINE_EDGE_SECRET", secret)
    outline = _Recorder(_minted())

    assert await apitoken._mint("u@example.com", INTERNAL_URL, transport=outline.transport) == "ol_api_fresh"
    assert EDGE_SECRET_HEADER not in outline.requests[0].headers


async def test_ignored_headers_without_a_secret_name_the_missing_secret() -> None:
    outline = _Recorder(_outline_error(401, "Authentication required"))

    with pytest.raises(apitoken.EdgeSecretMissingError, match="OUTLINE_EDGE_SECRET is unset.*AUTH_TYPE=sso"):
        await apitoken._mint("u@example.com", INTERNAL_URL, transport=outline.transport)


async def test_ignored_headers_with_a_secret_name_the_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_EDGE_SECRET", SECRET)
    outline = _Recorder(_outline_error(401, "Authentication required"))

    with pytest.raises(apitoken.EdgeSecretRejectedError, match="matches Outline's MPASS_EDGE_SECRET") as raised:
        await apitoken._mint("u@example.com", INTERNAL_URL, transport=outline.transport)
    assert SECRET not in str(raised.value)


async def test_corporate_gate_refusal_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_EDGE_SECRET", SECRET)
    outline = _Recorder(_outline_error(401, "Access denied"))

    with pytest.raises(apitoken.CorporateGateError, match="corporate-ID gate"):
        await apitoken._mint("u@example.com", INTERNAL_URL, "cognito-at", transport=outline.transport)


@pytest.mark.parametrize(
    "response",
    [
        _outline_error(401, "Invalid forwarded email: missing local part"),
        httpx.Response(401, text="not json"),
        httpx.Response(500, json={"message": "Authentication required"}),
    ],
)
async def test_other_mint_failures_stay_generic(response: httpx.Response) -> None:
    outline = _Recorder(response)

    assert await apitoken._mint("u@example.com", INTERNAL_URL, transport=outline.transport) is None


async def test_mint_never_follows_a_redirect_with_the_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_EDGE_SECRET", SECRET)
    outline = _Recorder(httpx.Response(307, headers={"Location": "https://elsewhere.example/api/apiKeys.create"}))

    assert await apitoken._mint("u@example.com", INTERNAL_URL, transport=outline.transport) is None
    assert [request.url.host for request in outline.requests] == ["outline"]


async def test_edge_refusal_keeps_cached_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", INTERNAL_URL)
    apitoken._cache_set("other@example.com", "ol_api_other")
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: _Tok(_claims(email="new@example.com")))

    async def _refused(*_args, **_kwargs):
        raise apitoken.EdgeSecretMissingError()

    monkeypatch.setattr(apitoken, "_mint", _refused)

    with pytest.raises(apitoken.EdgeSecretMissingError):
        await apitoken.build_outline_client()
    assert apitoken._cache_get("other@example.com") == "ol_api_other"
    assert apitoken._cache_get("new@example.com") is None


async def test_steady_state_client_uses_the_guarded_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", INTERNAL_URL)
    apitoken._cache_set("u@example.com", "ol_api_cached")
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: _Tok(_claims(email="u@example.com")))

    client = await apitoken.build_outline_client()

    assert client._request_client() is apitoken.steady_state_http_client()
    assert reject_trust_headers in client._request_client().event_hooks["request"]
    await apitoken.close_steady_state_client()


@pytest.mark.parametrize(
    "header", [EDGE_SECRET_HEADER, "x-mpass-edge-secret", "X_Mpass_Edge_Secret", "X-Auth-Request-Email"]
)
async def test_guarded_client_refuses_trust_headers(header: str) -> None:
    outline = _Recorder(httpx.Response(200, json={}))

    async with guarded_http_client(transport=outline.transport) as client:
        with pytest.raises(TrustHeaderError):
            await client.post("http://outline:3000/api/auth.info", headers={header: SECRET})

    assert outline.requests == []


async def test_guarded_client_sends_a_bearer_call() -> None:
    outline = _Recorder(httpx.Response(200, json={"data": {}}))

    async with guarded_http_client(transport=outline.transport) as client:
        response = await client.post("http://outline:3000/api/auth.info", headers={"Authorization": "Bearer ol_api_x"})

    assert response.status_code == 200
    assert len(outline.requests) == 1


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture
def cognito_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {
        "MCP_BASE_URL": "https://docs-mcp.example",
        "COGNITO_USER_POOL_ID": "pool",
        "COGNITO_AWS_REGION": "us-east-1",
        "OIDC_CLIENT_ID": "client",
        "OIDC_CLIENT_SECRET": "client-secret",
        "OUTLINE_INTERNAL_BASE_URL": INTERNAL_URL,
    }.items():
        monkeypatch.setenv(name, value)


def _startup_messages(capture: _Capture) -> list[str]:
    http.logger.addHandler(capture)
    try:
        http.validate_env()
    finally:
        http.logger.removeHandler(capture)
    return capture.messages


def test_startup_names_an_unusable_secret_without_its_value(monkeypatch: pytest.MonkeyPatch, cognito_env: None) -> None:
    short = "edge-secret-value-too-short"
    monkeypatch.setenv("OUTLINE_EDGE_SECRET", short)

    messages = _startup_messages(_Capture())

    [error] = [message for message in messages if "OUTLINE_EDGE_SECRET" in message]
    assert "shorter than 32 characters" in error
    assert all(short not in message for message in messages)


def test_startup_is_quiet_with_a_usable_secret(monkeypatch: pytest.MonkeyPatch, cognito_env: None) -> None:
    monkeypatch.setenv("OUTLINE_EDGE_SECRET", SECRET)

    assert not any("OUTLINE_EDGE_SECRET" in message for message in _startup_messages(_Capture()))
