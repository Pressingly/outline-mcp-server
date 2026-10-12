"""Document links returned to the model are absolute and use the public Outline host.

Outline answers with a relative ``url`` (``/doc/<slug>-<urlId>``). The tools
must turn it into a link on the host behind ``OUTLINE_API_URL``, never a guessed
host and never the internal ``OUTLINE_INTERNAL_BASE_URL`` host.
"""

from __future__ import annotations

import pytest

from outline_mcp import client as client_mod
from outline_mcp.document_cache import reset_document_cache
from outline_mcp.document_links import configured_public_base, public_base_url, public_document_url
from outline_mcp.models import BatchCreateItem, BatchUpdateItem, DocumentEdit
from outline_mcp.moneta import client as moneta_client
from outline_mcp.tools import (
    batch_operations,
    document_content,
    document_editing,
    document_reading,
    document_search,
)
from outline_mcp.tools.document_search import _format_collection_documents, _format_documents_list

PUBLIC_API = "https://docs.example.com/api"
INTERNAL_BASE = "http://outline:3000"
DOC_PATH = "/doc/release-notes-YlA3w9d83C"
EXPECTED_LINK = "https://docs.example.com/doc/release-notes-YlA3w9d83C"
DOCUMENT = {"id": "doc-1", "title": "Release notes", "text": "hello world", "url": DOC_PATH}
SEARCH_RESPONSE = {
    "data": [{"document": DOCUMENT, "context": "hello", "ranking": 0.9}],
    "pagination": {"limit": 25, "offset": 0},
}


class _ToolCapture:
    def __init__(self) -> None:
        self.tools: dict = {}

    def tool(self, **_kwargs):
        def register(fn):
            self.tools[fn.__name__] = fn
            return fn

        return register


class _FakeOutline:
    async def post(self, _endpoint: str, _data: dict) -> dict:
        return {"data": dict(DOCUMENT)}

    async def get_document(self, _document_id: str) -> dict:
        return dict(DOCUMENT)

    async def search_documents(self, *_args, **_kwargs) -> dict:
        return SEARCH_RESPONSE


def _tools(module) -> dict:
    capture = _ToolCapture()
    module.register_tools(capture)
    return capture.tools


def _assert_public_link(output: str) -> None:
    assert EXPECTED_LINK in output
    assert "getoutline.com" not in output


def _assert_relative_link(output: str) -> None:
    assert f"URL: {DOC_PATH}" in output
    assert "getoutline.com" not in output
    assert "outline:3000" not in output


@pytest.fixture(autouse=True)
def _deployment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OUTLINE_API_URL", PUBLIC_API)
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", INTERNAL_BASE)
    monkeypatch.setenv("OUTLINE_ENABLE_BATCH_OPS", "true")
    monkeypatch.delenv("OUTLINE_API_KEY", raising=False)
    monkeypatch.setattr(client_mod, "_get_header_api_key", lambda: None)
    monkeypatch.setattr(moneta_client, "stored_access_token", lambda: None)

    async def _client():
        return _FakeOutline()

    for module in (document_content, document_reading, document_editing, batch_operations, document_search):
        monkeypatch.setattr(module, "get_outline_client", _client)
    reset_document_cache()
    yield
    reset_document_cache()


# --- tool outputs ----------------------------------------------------------


async def test_create_document_returns_public_link() -> None:
    output = await _tools(document_content)["create_document"](title="Release notes", collection_id="col-1")
    assert "URL: " in output
    _assert_public_link(output)


async def test_update_document_returns_public_link() -> None:
    output = await _tools(document_content)["update_document"](document_id="doc-1", title="Release notes")
    _assert_public_link(output)


async def test_read_document_returns_public_link() -> None:
    output = await _tools(document_reading)["read_document"](document_id="doc-1")
    _assert_public_link(output)


async def test_edit_document_save_returns_public_link() -> None:
    edit = DocumentEdit(old_string="hello", new_string="goodbye")
    output = await _tools(document_editing)["edit_document"](document_id="doc-1", edits=[edit])
    _assert_public_link(output)


async def test_batch_create_returns_public_link() -> None:
    item = BatchCreateItem(title="Release notes", collection_id="col-1")
    output = await _tools(batch_operations)["batch_create_documents"](documents=[item])
    _assert_public_link(output)


async def test_batch_update_all_success_returns_public_link() -> None:
    item = BatchUpdateItem(id="doc-1", title="Release notes")
    output = await _tools(batch_operations)["batch_update_documents"](updates=[item])
    assert "All 1 documents updated successfully" in output
    assert f"Updated documents:\n  - doc-1 ({EXPECTED_LINK})" in output
    _assert_public_link(output)


async def test_search_documents_returns_public_link() -> None:
    output = await _tools(document_search)["search_documents"](query="release")
    assert f"URL: {EXPECTED_LINK}" in output
    _assert_public_link(output)


async def test_get_document_id_from_title_returns_public_link() -> None:
    output = await _tools(document_search)["get_document_id_from_title"](query="Release notes")
    assert output == f"Document ID: doc-1 (Title: Release notes)\nURL: {EXPECTED_LINK}"


async def test_get_document_id_from_title_best_match_returns_public_link() -> None:
    output = await _tools(document_search)["get_document_id_from_title"](query="release")
    assert output == f"Best match - Document ID: doc-1 (Title: Release notes)\nURL: {EXPECTED_LINK}"


def test_documents_list_returns_public_link() -> None:
    output = _format_documents_list([DOCUMENT], "Archived Documents")
    assert f"ID: doc-1\nURL: {EXPECTED_LINK}\n" in output


def test_collection_structure_returns_public_link() -> None:
    output = _format_collection_documents([dict(DOCUMENT, children=[])])
    assert f"- Release notes (ID: doc-1, URL: {EXPECTED_LINK})" in output


def test_documents_list_without_url_has_no_url_line() -> None:
    output = _format_documents_list([{"id": "doc-1", "title": "Release notes"}], "Archived Documents")
    assert "URL:" not in output


async def test_link_stays_relative_without_public_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OUTLINE_API_URL", raising=False)
    output = await _tools(document_content)["create_document"](title="Release notes", collection_id="col-1")
    _assert_relative_link(output)


async def test_link_stays_relative_when_api_url_is_the_internal_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUTLINE_API_URL", "http://outline:3000/api")
    output = await _tools(document_content)["create_document"](title="Release notes", collection_id="col-1")
    _assert_relative_link(output)


@pytest.mark.parametrize(
    ("api_url", "internal_base"),
    [
        ("http://OUTLINE:3000/api", "http://outline:3000"),
        ("http://outline:3000/api", '"http://outline:3000/"'),
    ],
)
def test_configured_public_base_rejects_internal_host(
    monkeypatch: pytest.MonkeyPatch, api_url: str, internal_base: str
) -> None:
    monkeypatch.setenv("OUTLINE_API_URL", api_url)
    monkeypatch.setenv("OUTLINE_INTERNAL_BASE_URL", internal_base)
    assert configured_public_base() == ""


@pytest.mark.parametrize(
    "api_url",
    ["http://outline:3001/api", "http://localhost:3000/api"],
)
def test_configured_public_base_keeps_other_hosts(monkeypatch: pytest.MonkeyPatch, api_url: str) -> None:
    monkeypatch.setenv("OUTLINE_API_URL", api_url)
    assert configured_public_base() == api_url.removesuffix("/api")


# --- helpers ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("api_url", "expected"),
    [
        ("https://docs.example.com/api", "https://docs.example.com"),
        ("https://docs.example.com/api/", "https://docs.example.com"),
        ("https://docs.example.com/API", "https://docs.example.com"),
        ("  https://docs.example.com/  ", "https://docs.example.com"),
        ('"https://docs.example.com/api"', "https://docs.example.com"),
        ("  'https://docs.example.com/api/'  ", "https://docs.example.com"),
        ("https://example.com/outline/api", "https://example.com/outline"),
        ("", ""),
        ("docs.example.com/api", ""),
        ("ftp://docs.example.com/api", ""),
    ],
)
def test_public_base_url(api_url: str, expected: str) -> None:
    assert public_base_url(api_url) == expected


@pytest.mark.parametrize(
    ("path_or_url", "base", "expected"),
    [
        (DOC_PATH, "https://docs.example.com", EXPECTED_LINK),
        (DOC_PATH, "https://docs.example.com/", EXPECTED_LINK),
        ("doc/release-notes-YlA3w9d83C", "https://docs.example.com", EXPECTED_LINK),
        ("https://other.example.com/doc/x", "https://docs.example.com", "https://other.example.com/doc/x"),
        ("//other.example.com/doc/x", "https://docs.example.com", "//other.example.com/doc/x"),
        ("", "https://docs.example.com", ""),
        (DOC_PATH, "", DOC_PATH),
    ],
)
def test_public_document_url(path_or_url: str, base: str, expected: str) -> None:
    assert public_document_url(path_or_url, base) == expected
