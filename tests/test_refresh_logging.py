"""Refresh failures are logged at WARNING with the user, client and session age, never a token."""

from __future__ import annotations

import hashlib
import logging
import time

import httpx
import jwt
import pytest
from authlib.integrations.httpx_client import AsyncOAuth2Client, OAuthError
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.oauth_proxy.models import JTIMapping, UpstreamTokenSet
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy
from fastmcp.server.auth.providers.aws import AWSCognitoProvider
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.provider import RefreshToken, TokenError
from mcp.shared.auth import OAuthClientInformationFull

from outline_mcp.moneta import session_log
from outline_mcp.moneta.cognito import OutlineCognitoProvider

TOKEN_ENDPOINT = "https://auth.example.test/token"
CLIENT_ID = "mcp-client-abc"
UPSTREAM_TOKEN_ID = "upstream-token-id-1"
SUB = "4f1c2d3e-sub"
EMAIL = "jane@example.com"
USERNAME = "mpass_jane"
REFRESH_SECRET = "upstream-refresh-secret"
ACCESS_SECRET = "upstream-access-secret"
FIVE_DAYS = 5 * 86400
LOGGER_NAME = "fastmcp.outline_mcp.moneta.cognito"


@pytest.fixture
def warnings_log(caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch) -> pytest.LogCaptureFixture:
    monkeypatch.setattr(logging.getLogger("fastmcp"), "propagate", True)
    caplog.set_level(logging.DEBUG, logger=LOGGER_NAME)
    return caplog


def _id_token() -> str:
    return jwt.encode({"sub": SUB, "email": EMAIL, "cognito:username": USERNAME}, "k" * 32)


def _token_set(*, created_ago: float = FIVE_DAYS, refresh_token: str | None = REFRESH_SECRET) -> UpstreamTokenSet:
    now = time.time()
    return UpstreamTokenSet(
        upstream_token_id=UPSTREAM_TOKEN_ID,
        access_token=ACCESS_SECRET,
        refresh_token=refresh_token,
        refresh_token_expires_at=None,
        expires_at=now - 10,
        token_type="Bearer",
        scope="openid",
        client_id=CLIENT_ID,
        created_at=now - created_ago,
        raw_token_data={"id_token": _id_token(), "access_token": ACCESS_SECRET, "refresh_token": REFRESH_SECRET},
    )


def _upstream_client(response: httpx.Response):
    def build(_self: AWSCognitoProvider) -> AsyncOAuth2Client:
        transport = httpx.MockTransport(lambda request: response)
        return AsyncOAuth2Client(client_id="stub", transport=transport)

    return build


class _RejectingVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        return None


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> OutlineCognitoProvider:
    monkeypatch.setattr(
        OIDCProxy,
        "get_oidc_configuration",
        lambda self, *args: OIDCConfiguration(
            strict=False,
            issuer="https://cognito.example.test",
            authorization_endpoint="https://auth.example.test/authorize",
            token_endpoint=TOKEN_ENDPOINT,
            jwks_uri="https://cognito.example.test/jwks",
        ),
    )
    built = OutlineCognitoProvider(
        user_pool_id="eu-west-1_pool",
        aws_region="eu-west-1",
        client_id="cognito-client",
        client_secret="cognito-secret",
        base_url="https://docs-mcp.example.test",
        client_storage=MemoryStore(),
        jwt_signing_key="s" * 32,
    )
    built.set_mcp_path("/mcp")
    built._token_validator = _RejectingVerifier()
    return built


async def _seed(provider: OutlineCognitoProvider, token_set: UpstreamTokenSet, *, refresh: bool = False) -> str:
    jti = "jti-refresh" if refresh else "jti-access"
    issue = provider.jwt_issuer.issue_refresh_token if refresh else provider.jwt_issuer.issue_access_token
    token = issue(client_id=CLIENT_ID, scopes=["openid"], jti=jti, expires_in=3600)
    await provider._upstream_token_store.put(key=token_set.upstream_token_id, value=token_set)
    await provider._jti_mapping_store.put(
        key=jti, value=JTIMapping(jti=jti, upstream_token_id=token_set.upstream_token_id, created_at=time.time())
    )
    return token


def _bad_gateway() -> httpx.Response:
    return httpx.Response(502, text="<html>Bad Gateway</html>", request=httpx.Request("POST", TOKEN_ENDPOINT))


def _invalid_grant() -> httpx.Response:
    body = {"error": "invalid_grant", "error_description": "Refresh Token has expired"}
    return httpx.Response(400, json=body, request=httpx.Request("POST", TOKEN_ENDPOINT))


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME and r.levelno == logging.WARNING]


def _assert_no_secrets(caplog: pytest.LogCaptureFixture, *tokens: str) -> None:
    for secret in (REFRESH_SECRET, ACCESS_SECRET, _id_token(), UPSTREAM_TOKEN_ID, *tokens):
        assert secret not in caplog.text


def _fingerprint() -> str:
    return hashlib.sha256(UPSTREAM_TOKEN_ID.encode()).hexdigest()[:8]


async def test_transparent_refresh_failure_names_the_session(provider, warnings_log, monkeypatch):
    monkeypatch.setattr(AWSCognitoProvider, "_create_upstream_oauth_client", _upstream_client(_bad_gateway()))
    token = await _seed(provider, _token_set())

    assert await provider.load_access_token(token) is None

    transparent, rejected = _warnings(warnings_log)
    assert transparent.startswith("Transparent upstream refresh failed: ")
    for field in (
        f"sub={SUB}",
        f"email={EMAIL}",
        f"username={USERNAME}",
        f"client_id={CLIENT_ID}",
        "session_age=5d00h00m",
        f"upstream_token={_fingerprint()}",
        "error=HTTPStatusError",
        "status=502",
        "oauth_error=-",
    ):
        assert field in transparent
    assert rejected.startswith("Upstream token validation failed, returning 401: ")
    assert f"sub={SUB}" in rejected
    assert "refresh_token=present" in rejected
    _assert_no_secrets(warnings_log, token)


async def test_transparent_refresh_failure_reports_the_oauth_error(provider, warnings_log, monkeypatch):
    monkeypatch.setattr(AWSCognitoProvider, "_create_upstream_oauth_client", _upstream_client(_invalid_grant()))
    token = await _seed(provider, _token_set())

    assert await provider.load_access_token(token) is None

    transparent = _warnings(warnings_log)[0]
    assert "error=OAuthError" in transparent
    assert "status=-" in transparent
    assert "oauth_error=invalid_grant" in transparent
    assert 'detail="Refresh Token has expired"' in transparent


async def test_transparent_refresh_reraises_the_upstream_error(provider, monkeypatch):
    monkeypatch.setattr(AWSCognitoProvider, "_create_upstream_oauth_client", _upstream_client(_invalid_grant()))

    with pytest.raises(OAuthError):
        await provider._try_transparent_refresh(_token_set())


async def test_invalid_client_token_stays_quiet(provider, warnings_log):
    assert await provider.load_access_token("not-a-fastmcp-token") is None

    assert _warnings(warnings_log) == []


async def test_client_refresh_failure_names_the_session(provider, warnings_log, monkeypatch):
    monkeypatch.setattr(AWSCognitoProvider, "_create_upstream_oauth_client", _upstream_client(_bad_gateway()))
    refresh_jwt = await _seed(provider, _token_set(), refresh=True)
    client = OAuthClientInformationFull(client_id=CLIENT_ID, redirect_uris=["http://localhost:3000/callback"])
    refresh = RefreshToken(token=refresh_jwt, client_id=CLIENT_ID, scopes=["openid"])

    with pytest.raises(TokenError) as raised:
        await provider.exchange_refresh_token(client, refresh, ["openid"])

    assert raised.value.error == "invalid_grant"
    assert raised.value.error_description.startswith("Upstream refresh failed: Server error '502 Bad Gateway'")
    (line,) = _warnings(warnings_log)
    assert line.startswith("Upstream token refresh failed: ")
    for field in (
        f"sub={SUB}",
        f"email={EMAIL}",
        f"client_id={CLIENT_ID}",
        "session_age=5d00h00m",
        f"upstream_token={_fingerprint()}",
        "error=HTTPStatusError",
        "status=502",
    ):
        assert field in line
    _assert_no_secrets(warnings_log, refresh_jwt)


async def test_client_refresh_failure_without_a_mapping_names_the_user_from_the_sealed_claims(provider, warnings_log):
    refresh_jwt = provider.jwt_issuer.issue_refresh_token(
        client_id=CLIENT_ID,
        scopes=["openid"],
        jti="jti-gone",
        expires_in=3600,
        upstream_claims={"id_token": _id_token(), "email": EMAIL},
    )
    client = OAuthClientInformationFull(client_id=CLIENT_ID, redirect_uris=["http://localhost:3000/callback"])
    refresh = RefreshToken(token=refresh_jwt, client_id=CLIENT_ID, scopes=["openid"])

    with pytest.raises(TokenError):
        await provider.exchange_refresh_token(client, refresh, ["openid"])

    (line,) = _warnings(warnings_log)
    assert f"client_id={CLIENT_ID}" in line
    assert f"sub={SUB}" in line
    assert "session_age=-" in line
    assert "oauth_error=invalid_grant" in line
    assert 'detail="Refresh token mapping not found"' in line
    _assert_no_secrets(warnings_log, refresh_jwt)


def test_format_age_spans_days():
    assert session_log.format_age(5 * 86400 + 2 * 3600 + 13 * 60 + 7) == "5d02h13m07s"
    assert session_log.format_age(-3) == "0d00h00m00s"


def test_session_fields_survive_a_missing_id_token():
    token_set = _token_set().model_copy(update={"raw_token_data": {}})

    fields = session_log.session_fields(token_set, now=token_set.created_at + 61)

    assert fields["sub"] is None
    assert fields["client_id"] == CLIENT_ID
    assert fields["session_age"] == "0d00h01m01s"


def test_render_quotes_spaced_values_and_marks_missing_ones():
    assert session_log.render({"a": None, "b": "x y", "c": 3}) == 'a=- b="x y" c=3'
