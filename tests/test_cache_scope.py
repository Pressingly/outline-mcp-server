"""The document cache is scoped to the request's credential, never shared.

Covers ``outline_mcp.client.cache_scope`` and its use by the reading and
editing tools: SSO identities get separate entries, staged edits stay with
their author, a request without an identity bypasses the cache, and the
header / env API-key modes keep caching per key.
"""

from __future__ import annotations

import hashlib

import pytest

from outline_mcp import client as client_mod
from outline_mcp.document_cache import get_document_cache, reset_document_cache
from outline_mcp.models import DocumentEdit
from outline_mcp.moneta import client as moneta_client
from outline_mcp.moneta.cognito import ID_TOKEN_KEY, UPSTREAM_CLAIMS_KEY
from outline_mcp.tools import document_editing, document_reading

DOC_ID = "doc-1"


class _Tok:
    def __init__(self, email: str) -> None:
        self.claims = {UPSTREAM_CLAIMS_KEY: {ID_TOKEN_KEY: "idtok", "email": email}}


class _FakeOutline:
    """Counts fetches and returns a document stamped with the caller."""

    def __init__(self, caller: str) -> None:
        self.caller = caller
        self.fetches = 0

    async def get_document(self, document_id: str) -> dict:
        self.fetches += 1
        return {"title": "Doc", "text": f"secret of {self.caller}", "url": f"/doc/{document_id}"}


class _ToolCapture:
    """Minimal stand-in for FastMCP that keeps the registered coroutines."""

    def __init__(self) -> None:
        self.tools: dict = {}

    def tool(self, **_kwargs):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn

        return register


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OUTLINE_CACHE_TTL", "300")
    monkeypatch.delenv("OUTLINE_API_KEY", raising=False)
    monkeypatch.setattr(client_mod, "_get_header_api_key", lambda: None)
    monkeypatch.setattr(moneta_client, "stored_access_token", lambda: None)
    reset_document_cache()
    yield
    reset_document_cache()


class _Session:
    """Switches the in-flight request between SSO users and their Outline view."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._monkeypatch = monkeypatch
        self.outlines: dict[str, _FakeOutline] = {}

    def act_as(self, email: str | None) -> _FakeOutline:
        caller = email or "anonymous"
        outline = self.outlines.setdefault(caller, _FakeOutline(caller))
        token = _Tok(email) if email else None
        self._monkeypatch.setattr(moneta_client, "stored_access_token", lambda: token)

        async def _client():
            return outline

        self._monkeypatch.setattr(document_reading, "get_outline_client", _client)
        return outline


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> _Session:
    return _Session(monkeypatch)


def _edit_tool():
    capture = _ToolCapture()
    document_editing.register_tools(capture)
    return capture.tools["edit_document"]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# --- scope resolution ------------------------------------------------------


def test_sso_scope_is_hashed_identity(session: _Session) -> None:
    session.act_as("alice@example.com")
    scope = client_mod.cache_scope()
    assert scope == f"sso:{_sha('alice@example.com')}"
    assert "alice" not in scope


def test_sso_identity_takes_precedence_over_env_key(session: _Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_API_KEY", "ol_api_shared")
    session.act_as("alice@example.com")
    assert client_mod.cache_scope() == f"sso:{_sha('alice@example.com')}"


def test_token_without_identity_falls_back_to_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    class _NoIdentity:
        claims: dict = {}

    monkeypatch.setattr(moneta_client, "stored_access_token", lambda: _NoIdentity())
    monkeypatch.setenv("OUTLINE_API_KEY", "ol_api_env")
    assert client_mod.cache_scope() == f"key:{_sha('ol_api_env')}"


def test_env_key_scope_is_hashed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_API_KEY", "ol_api_env")
    assert client_mod.cache_scope() == f"key:{_sha('ol_api_env')}"


def test_header_key_scope_is_hashed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_mod, "_get_header_api_key", lambda: "ol_api_hdr")
    assert client_mod.cache_scope() == f"key:{_sha('ol_api_hdr')}"


def test_no_identity_has_no_scope() -> None:
    assert client_mod.cache_scope() is None


# --- reads -----------------------------------------------------------------


async def test_sso_users_do_not_share_cached_documents(session: _Session) -> None:
    alice = session.act_as("alice@example.com")
    first = await document_reading.get_cached_or_fetch(DOC_ID)
    again = await document_reading.get_cached_or_fetch(DOC_ID)
    assert alice.fetches == 1
    assert again is first

    bob = session.act_as("bob@example.com")
    bobs = await document_reading.get_cached_or_fetch(DOC_ID)
    assert bob.fetches == 1
    assert bobs.text == "secret of bob@example.com"


async def test_no_identity_bypasses_the_cache(session: _Session) -> None:
    anonymous = session.act_as(None)
    await document_reading.get_cached_or_fetch(DOC_ID)
    await document_reading.get_cached_or_fetch(DOC_ID)
    assert anonymous.fetches == 2
    assert len(get_document_cache()._store) == 0


async def test_api_key_mode_still_caches(session: _Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_API_KEY", "ol_api_env")
    outline = session.act_as(None)
    await document_reading.get_cached_or_fetch(DOC_ID)
    await document_reading.get_cached_or_fetch(DOC_ID)
    assert outline.fetches == 1
    assert list(get_document_cache()._store) == [(f"key:{_sha('ol_api_env')}", DOC_ID)]


async def test_distinct_header_keys_do_not_share(session: _Session, monkeypatch: pytest.MonkeyPatch) -> None:
    outline = session.act_as(None)
    monkeypatch.setattr(client_mod, "_get_header_api_key", lambda: "ol_api_one")
    await document_reading.get_cached_or_fetch(DOC_ID)
    monkeypatch.setattr(client_mod, "_get_header_api_key", lambda: "ol_api_two")
    await document_reading.get_cached_or_fetch(DOC_ID)
    assert outline.fetches == 2


# --- staged edits ----------------------------------------------------------


async def test_staged_edits_belong_to_their_author(session: _Session) -> None:
    edit_document = _edit_tool()
    session.act_as("alice@example.com")
    result = await edit_document(DOC_ID, [DocumentEdit(old_string="secret", new_string="draft")], save=False)
    assert "unsaved changes" in result
    alices = await document_reading.get_cached_or_fetch(DOC_ID)
    assert alices.dirty and alices.text == "draft of alice@example.com"

    session.act_as("bob@example.com")
    bobs = await document_reading.get_cached_or_fetch(DOC_ID)
    assert not bobs.dirty
    assert bobs.text == "secret of bob@example.com"


async def test_no_identity_refuses_to_stage(session: _Session) -> None:
    edit_document = _edit_tool()
    session.act_as(None)
    result = await edit_document(DOC_ID, [DocumentEdit(old_string="secret", new_string="draft")], save=False)
    assert result.startswith("Edit failed:")
    assert "No edits were applied" in result
    assert len(get_document_cache()._store) == 0


async def test_cache_methods_ignore_a_none_scope() -> None:
    cache = get_document_cache()
    await cache.put("sso:alice", DOC_ID, {"text": "clean"})
    doc = await cache.put(None, DOC_ID, {"text": "transient"})
    assert doc.text == "transient"
    assert await cache.get(None, DOC_ID) is None
    await cache.evict(None, DOC_ID)
    assert list(cache._store) == [("sso:alice", DOC_ID)]
    with pytest.raises(ValueError):
        await cache.stage_text(None, DOC_ID, doc, "draft")


async def test_anonymous_write_still_evicts_clean_copies() -> None:
    cache = get_document_cache()
    clean = await cache.put("sso:alice", DOC_ID, {"text": "clean"})
    await cache.stage_text("sso:bob", DOC_ID, clean, "bob draft")
    await cache.invalidate_for_write(None, DOC_ID)
    assert list(cache._store) == [("sso:bob", DOC_ID)]
