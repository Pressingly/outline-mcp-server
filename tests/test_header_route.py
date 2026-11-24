"""The /http/api-key route: internal Outline URL and the key gate (FOSS-642)."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route

from outline_mcp import client as client_module
from outline_mcp.document_links import document_link
from outline_mcp.moneta import apitoken, header_route
from outline_mcp.moneta import http as moneta_http
from outline_mcp.moneta.header_route import HeaderKeyGate, KeyCheck, check_key, header_api_url
from outline_mcp.moneta.http import build_app
from outline_mcp.server import get_http_mcp

PUBLIC_API_URL = "https://docs.example.com/api"
INTERNAL_URL = "http://outline:3000"
KEY = "ol_api_user_key"


class _Outline:
    """A stand-in Outline answering every request with one response (or raising one error)."""

    def __init__(self) -> None:
        self.answer: httpx.Response | Exception = httpx.Response(200, json={"data": {"user": {}}})
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _outline_error(status: int, error: str = "authentication_required") -> httpx.Response:
    return httpx.Response(status, json={"ok": False, "error": error, "status": status, "message": "nope"})


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_API_URL", PUBLIC_API_URL)
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", INTERNAL_URL)
    monkeypatch.setenv(header_route.HEADER_API_URL_ENV, INTERNAL_URL)
    monkeypatch.delenv("OUTLINE_API_KEY", raising=False)


@pytest.fixture(autouse=True)
async def outline(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[_Outline]:
    fake = _Outline()
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    monkeypatch.setattr(header_route, "steady_state_http_client", lambda: http_client)
    yield fake
    await http_client.aclose()


def test_header_api_url_prefers_the_header_setting() -> None:
    assert header_api_url() == INTERNAL_URL


def test_header_api_url_falls_back_to_outline_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(header_route.HEADER_API_URL_ENV)
    assert header_api_url() == PUBLIC_API_URL


@pytest.fixture
def through_gate() -> Iterator[None]:
    passed = header_route._passed_gate.set(True)
    yield
    header_route._passed_gate.reset(passed)


@pytest.mark.usefixtures("through_gate")
async def test_header_key_client_targets_the_internal_api(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "_get_header_api_key", lambda: KEY)
    outline_client = await client_module.get_outline_client()
    assert outline_client.api_url == f"{INTERNAL_URL}/api"
    assert outline_client.api_key == KEY
    assert outline_client._http_client is header_route.steady_state_http_client()


async def test_env_key_keeps_outline_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "_get_header_api_key", lambda: None)
    monkeypatch.setenv("OUTLINE_API_KEY", "ol_api_env")
    outline_client = await client_module.get_outline_client()
    assert outline_client.api_url == PUBLIC_API_URL
    assert outline_client.api_key == "ol_api_env"


async def test_key_header_outside_the_gate_keeps_the_public_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "_get_header_api_key", lambda: KEY)
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: None)
    outline_client = await client_module.get_outline_client()
    assert outline_client.api_url == PUBLIC_API_URL
    assert outline_client._http_client is None


def test_document_links_stay_public() -> None:
    assert document_link("/doc/plan-abc123") == "https://docs.example.com/doc/plan-abc123"


async def test_check_key_asks_outline_once_with_the_key_as_bearer(outline: _Outline) -> None:
    assert await check_key(KEY) is KeyCheck.VALID
    (request,) = outline.requests
    assert str(request.url) == f"{INTERNAL_URL}/api/auth.info"
    assert request.headers["Authorization"] == f"Bearer {KEY}"
    assert request.extensions["timeout"]["read"] == header_route.KEY_CHECK_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (_outline_error(401), KeyCheck.REJECTED),
        (_outline_error(403, "user_suspended"), KeyCheck.REJECTED),
        (_outline_error(403, "authorization_error"), KeyCheck.VALID),
        (httpx.Response(403, text="forbidden"), KeyCheck.REJECTED),
        (_outline_error(429, "rate_limit_exceeded"), KeyCheck.UNAVAILABLE),
        (_outline_error(500, "internal_error"), KeyCheck.UNAVAILABLE),
        (httpx.Response(200, text="<html>sign in</html>"), KeyCheck.UNAVAILABLE),
        (httpx.ConnectError("refused"), KeyCheck.UNAVAILABLE),
        (httpx.ReadTimeout("slow"), KeyCheck.UNAVAILABLE),
    ],
    ids=[
        "deleted",
        "suspended",
        "scoped",
        "bare-403",
        "rate-limited",
        "server-error",
        "html",
        "unreachable",
        "timeout",
    ],
)
async def test_check_key_maps_outline_answers(
    outline: _Outline, answer: httpx.Response | Exception, expected: KeyCheck
) -> None:
    outline.answer = answer
    assert await check_key(KEY) is expected
    assert len(outline.requests) == 1


@pytest.mark.parametrize("bad_key", ["ol_api_kéy", "ol_api_\x01key"], ids=["non-ascii", "control-char"])
async def test_unsendable_key_is_rejected_without_a_call(outline: _Outline, bad_key: str) -> None:
    assert await check_key(bad_key) is KeyCheck.REJECTED
    assert outline.requests == []


async def _reached(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("reached")


def _gated_app() -> Starlette:
    inner = Starlette(routes=[Route("/mcp", _reached, methods=["POST"])])
    return Starlette(routes=[Mount("/http/api-key", app=HeaderKeyGate(inner))])


async def _post(app: Starlette, headers: list[tuple[str, str]], payload: dict | None = None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://outline-mcp:8213") as caller:
        return await caller.post("/http/api-key/mcp", headers=headers, json=payload or {})


async def test_gate_passes_an_accepted_key() -> None:
    response = await _post(_gated_app(), [("x-outline-api-key", KEY)])
    assert response.status_code == 200
    assert response.text == "reached"


async def test_gate_answers_401_for_a_deleted_key(outline: _Outline) -> None:
    outline.answer = _outline_error(401)
    response = await _post(_gated_app(), [("x-outline-api-key", KEY)])
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'


async def test_gate_answers_401_for_a_suspended_user(outline: _Outline) -> None:
    outline.answer = _outline_error(403, "user_suspended")
    response = await _post(_gated_app(), [("x-outline-api-key", KEY)])
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


async def test_gate_answers_401_without_a_key(outline: _Outline) -> None:
    response = await _post(_gated_app(), [])
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"
    assert outline.requests == []


async def test_gate_answers_401_for_two_keys(outline: _Outline) -> None:
    response = await _post(_gated_app(), [("x-outline-api-key", KEY), ("x-outline-api-key", "ol_api_other")])
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"
    assert outline.requests == []


async def test_gate_answers_503_when_outline_is_down(outline: _Outline) -> None:
    outline.answer = httpx.ConnectError("refused")
    response = await _post(_gated_app(), [("x-outline-api-key", KEY)])
    assert response.status_code == 503
    assert "WWW-Authenticate" not in response.headers


@pytest.mark.parametrize("forwarded", ["X-Forwarded-For", "X-Forwarded-Host"])
async def test_gate_refuses_proxied_callers_when_the_route_is_internal(outline: _Outline, forwarded: str) -> None:
    response = await _post(_gated_app(), [("x-outline-api-key", KEY), (forwarded, "203.0.113.7")])
    assert response.status_code == 403
    assert response.json()["error"] == "forbidden"
    assert outline.requests == []


async def test_gate_lets_proxied_callers_through_while_the_route_uses_the_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(header_route.HEADER_API_URL_ENV)
    response = await _post(_gated_app(), [("x-outline-api-key", KEY), ("X-Forwarded-For", "203.0.113.7")])
    assert response.text == "reached"


async def test_served_app_gates_the_real_header_route(outline: _Outline) -> None:
    outline.answer = _outline_error(401)
    app = build_app(cognito_app=Starlette(), header_app=get_http_mcp().http_app(stateless_http=True))
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
    }
    response = await _post(
        app, [("x-outline-api-key", KEY), ("Accept", "application/json, text/event-stream")], initialize
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"


TOOL_CALL = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "list_collections", "arguments": {}},
}
MCP_ACCEPT = ("Accept", "application/json, text/event-stream")


def _outline_calls(outline: _Outline) -> list[str]:
    return [str(request.url) for request in outline.requests if not request.url.path.endswith("/auth.info")]


async def _call_tool(app: Starlette, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://outline-mcp:8213") as caller:
            return await caller.post(path, headers=[("x-outline-api-key", KEY), MCP_ACCEPT], json=TOOL_CALL)


async def test_gated_tool_call_reaches_the_internal_url(outline: _Outline, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "_get_header_api_key", lambda: KEY)
    outline.answer = httpx.Response(200, json={"data": []})
    header_app = get_http_mcp().http_app(stateless_http=True)
    app = build_app(cognito_app=get_http_mcp().http_app(stateless_http=True), header_app=header_app)
    response = await _call_tool(app, "/http/api-key/mcp")
    assert response.status_code == 200
    assert _outline_calls(outline) == [f"{INTERNAL_URL}/api/collections.list"]


async def test_ungated_http_mode_keeps_the_public_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Upstream's http mode (COGNITO_USER_POOL_ID empty) serves the header app at / with no gate."""
    monkeypatch.setenv("COGNITO_USER_POOL_ID", "")
    monkeypatch.setattr(client_module, "_get_header_api_key", lambda: KEY)
    public_calls: list[str] = []

    async def record_public_call(self, endpoint: str, data: dict | None = None) -> dict:
        public_calls.append(f"{self.api_url}/{endpoint}")
        return {"data": []}

    monkeypatch.setattr(client_module.OutlineClient, "post", record_public_call)
    http_app = get_http_mcp().http_app(stateless_http=True)
    app = Starlette(routes=[Mount("/", app=http_app)], lifespan=http_app.lifespan)
    assert moneta_http.enabled() is False
    response = await _call_tool(app, "/mcp")
    assert response.status_code == 200
    assert public_calls == [f"{PUBLIC_API_URL}/collections.list"]


def test_startup_warns_when_the_internal_url_cannot_be_used(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("COGNITO_USER_POOL_ID", "")
    monkeypatch.setattr(moneta_http.logger, "propagate", True)
    with caplog.at_level("WARNING", logger=moneta_http.logger.name):
        assert moneta_http.enabled() is False
    assert header_route.HEADER_API_URL_ENV in caplog.text
