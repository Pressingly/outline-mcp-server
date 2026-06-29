"""Smoke tests for the Outline MCP server factories and auth seam."""

from __future__ import annotations

import pytest

from outline_mcp import client as client_mod
from outline_mcp.server import get_http_mcp, get_stdio_mcp


async def _tool_names(mcp) -> set[str]:
    return {tool.name for tool in await mcp.list_tools()}


async def test_stdio_registers_tools() -> None:
    """The stdio server registers a non-trivial set of tools."""
    names = await _tool_names(get_stdio_mcp())
    assert len(names) >= 20
    assert "search_documents" in names


async def test_read_only_mode_drops_write_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """OUTLINE_READ_ONLY hides write tools but keeps read tools."""
    monkeypatch.setenv("OUTLINE_READ_ONLY", "true")
    names = await _tool_names(get_stdio_mcp())
    assert "search_documents" in names
    assert "create_document" not in names


async def test_disable_ai_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """OUTLINE_DISABLE_AI_TOOLS hides the AI tool."""
    monkeypatch.setenv("OUTLINE_DISABLE_AI_TOOLS", "true")
    names = await _tool_names(get_stdio_mcp())
    assert "ask_ai_about_documents" not in names


async def test_http_factory_builds() -> None:
    """The HTTP factory constructs without a provider."""
    names = await _tool_names(get_http_mcp())
    assert len(names) >= 20


def test_resolved_api_key_prefers_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Outside a request context, the env var supplies the key."""
    monkeypatch.setenv("OUTLINE_API_KEY", "ol_api_test")
    assert client_mod.get_resolved_api_key() == "ol_api_test"


async def test_enabled_tools_filters_to_subset(monkeypatch: pytest.MonkeyPatch) -> None:
    """OUTLINE_MCP_ENABLED_TOOLS limits the server to only the listed tools."""
    monkeypatch.setenv("OUTLINE_MCP_ENABLED_TOOLS", "search_documents,read_document")
    names = await _tool_names(get_stdio_mcp())
    assert names == {"search_documents", "read_document"}


async def test_enabled_tools_overrides_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """OUTLINE_MCP_ENABLED_TOOLS takes precedence over OUTLINE_READ_ONLY.

    Even with READ_ONLY=true, an explicit allow-list that includes a write
    tool must surface that tool.
    """
    monkeypatch.setenv("OUTLINE_READ_ONLY", "true")
    monkeypatch.setenv("OUTLINE_MCP_ENABLED_TOOLS", "create_document,search_documents")
    names = await _tool_names(get_stdio_mcp())
    assert "create_document" in names
    assert "search_documents" in names


async def test_enabled_tools_empty_registers_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty OUTLINE_MCP_ENABLED_TOOLS behaves like unset (all tools)."""
    monkeypatch.setenv("OUTLINE_MCP_ENABLED_TOOLS", "")
    names = await _tool_names(get_stdio_mcp())
    assert len(names) >= 20
