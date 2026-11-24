"""The /http/api-key route: internal Outline URL and the key gate (FOSS-642)."""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route

from outline_mcp import client as client_module
from outline_mcp.document_links import document_link
from outline_mcp.moneta import apitoken, header_route
from outline_mcp.moneta.header_route import HeaderKeyGate, KeyCheck, check_key, header_api_url

PUBLIC_API_URL = "https://docs.example.com/api"
INTERNAL_URL = "http://outline:3000"
KEY = "ol_api_user_key"


class _Outline:
    def __init__(self, response: httpx.Response | Exception) -> None:
        self._response = response
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _outline_error(status: int) -> httpx.Response:
    return httpx.Response(status, json={"ok": False, "status": status, "message": "nope"})


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_API_URL", PUBLIC_API_URL)
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", INTERNAL_URL)
    monkeypatch.setenv(header_route.HEADER_API_URL_ENV, INTERNAL_URL)
    monkeypatch.delenv("OUTLINE_API_KEY", raising=False)


def _use_outline(monkeypatch: pytest.MonkeyPatch, response: httpx.Response | Exception) -> _Outline:
    outline = _Outline(response)
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(outline))
    monkeypatch.setattr(header_route, "steady_state_http_client", lambda: http_client)
    return outline


def test_header_api_url_prefers_the_header_setting() -> None:
    assert header_api_url() == INTERNAL_URL


def test_header_api_url_falls_back_to_outline_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(header_route.HEADER_API_URL_ENV)
    assert header_api_url() == PUBLIC_API_URL


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


async def test_oauth_request_with_a_key_header_never_gets_the_internal_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "_get_header_api_key", lambda: KEY)
    monkeypatch.setattr(header_route, "stored_access_token", lambda: object())
    monkeypatch.setattr(apitoken, "stored_access_token", lambda: None)
    outline_client = await client_module.get_outline_client()
    assert outline_client.api_url == PUBLIC_API_URL
    assert outline_client._http_client is None


def test_document_links_stay_public() -> None:
    assert document_link("/doc/plan-abc123") == "https://docs.example.com/doc/plan-abc123"


async def test_check_key_asks_outline_with_the_key_as_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    outline = _use_outline(monkeypatch, httpx.Response(200, json={"data": {"user": {}}}))
    assert await check_key(KEY) is KeyCheck.VALID
    (request,) = outline.requests
    assert str(request.url) == f"{INTERNAL_URL}/api/auth.info"
    assert request.headers["Authorization"] == f"Bearer {KEY}"


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_outline_error(401), KeyCheck.REJECTED),
        (_outline_error(403), KeyCheck.VALID),
        (_outline_error(500), KeyCheck.UNAVAILABLE),
        (httpx.ConnectError("refused"), KeyCheck.UNAVAILABLE),
        (httpx.Response(200, text="<html>sign in</html>"), KeyCheck.UNAVAILABLE),
    ],
)
async def test_check_key_maps_outline_answers(
    monkeypatch: pytest.MonkeyPatch, response: httpx.Response | Exception, expected: KeyCheck
) -> None:
    _use_outline(monkeypatch, response)
    assert await check_key(KEY) is expected


async def test_check_key_without_a_key_never_calls_outline(monkeypatch: pytest.MonkeyPatch) -> None:
    outline = _use_outline(monkeypatch, httpx.Response(200, json={}))
    assert await check_key(None) is KeyCheck.MISSING
    assert outline.requests == []


async def _reached(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("reached")


def _gated_app() -> Starlette:
    inner = Starlette(routes=[Route("/mcp", _reached, methods=["POST"])])
    return Starlette(routes=[Mount("/http/api-key", app=HeaderKeyGate(inner))])


async def _post(headers: dict[str, str]) -> httpx.Response:
    transport = httpx.ASGITransport(app=_gated_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://outline-mcp:8213") as caller:
        return await caller.post("/http/api-key/mcp", headers=headers, json={})


async def test_gate_passes_an_accepted_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_outline(monkeypatch, httpx.Response(200, json={"data": {}}))
    response = await _post({"x-outline-api-key": KEY})
    assert response.status_code == 200
    assert response.text == "reached"


async def test_gate_answers_401_for_a_deleted_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_outline(monkeypatch, _outline_error(401))
    response = await _post({"x-outline-api-key": KEY})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_token"
    assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'


async def test_gate_answers_401_without_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_outline(monkeypatch, httpx.Response(200, json={}))
    response = await _post({})
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_request"


async def test_gate_answers_503_when_outline_is_down(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_outline(monkeypatch, httpx.ConnectError("refused"))
    response = await _post({"x-outline-api-key": KEY})
    assert response.status_code == 503
    assert "WWW-Authenticate" not in response.headers
