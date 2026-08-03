"""Smoke tests for the Outline MCP server factories and auth seam."""

from __future__ import annotations

import importlib
import pkgutil

import pytest
from fastmcp import FastMCP

import outline_mcp.tools
from outline_mcp import client as client_mod
from outline_mcp.server import get_http_mcp, get_stdio_mcp

# The removed runtime-discovery layer. None of these may reappear on tools/list.
META_TOOLS = ("list_available_tools", "enable_tools", "execute_tool")

# Every env flag that gates registration. Cleared before any test that asserts
# on the default listing, so a stray value in the runner env cannot make an
# assertion pass vacuously.
GATE_FLAGS = (
    "OUTLINE_READ_ONLY",
    "OUTLINE_DISABLE_AI_TOOLS",
    "OUTLINE_ENABLE_DELETE",
    "OUTLINE_ENABLE_BATCH_OPS",
)

DELETE_TOOLS = {"delete_document", "delete_collection", "batch_delete_documents"}
BATCH_OP_TOOLS = {
    "batch_archive_documents",
    "batch_move_documents",
    "batch_update_documents",
    "batch_create_documents",
}


def _clear_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unset every registration gate so the default listing is deterministic."""
    for flag in GATE_FLAGS:
        monkeypatch.delenv(flag, raising=False)


async def _tool_names(mcp) -> set[str]:
    return {tool.name for tool in await mcp.list_tools()}


async def _names_registered_by_every_module() -> set[str]:
    """Every tool name any ``outline_mcp.tools`` submodule registers.

    Discovered by walking the package rather than the curated module tuples in
    ``outline_mcp.tools``, so dropping a module from those tuples is caught
    instead of silently shrinking the expectation too.
    """
    names: set[str] = set()
    for _, mod_name, _ in pkgutil.iter_modules(outline_mcp.tools.__path__):
        mod = importlib.import_module(f"outline_mcp.tools.{mod_name}")
        register = getattr(mod, "register_tools", None)
        if register is None:
            continue
        scratch = FastMCP("scratch")
        register(scratch)
        names |= await _tool_names(scratch)
    return names


async def test_stdio_registers_every_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stdio lists exactly what the tool modules register — no more, no less."""
    _clear_gates(monkeypatch)
    names = await _tool_names(get_stdio_mcp())
    assert "search_documents" in names
    # Tools that were previously hidden behind enable_tools are listed up front.
    assert "create_document" in names
    assert "ask_ai_about_documents" in names
    assert names == await _names_registered_by_every_module()


async def test_destructive_tools_are_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both gates are opt-in: no delete and no bulk write registers unflagged."""
    _clear_gates(monkeypatch)
    names = await _tool_names(get_stdio_mcp())
    assert not (DELETE_TOOLS & names)
    assert not (BATCH_OP_TOOLS & names)


async def test_enable_delete_registers_delete_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """OUTLINE_ENABLE_DELETE adds exactly the three delete tools."""
    _clear_gates(monkeypatch)
    baseline = await _tool_names(get_stdio_mcp())
    monkeypatch.setenv("OUTLINE_ENABLE_DELETE", "true")
    names = await _tool_names(get_stdio_mcp())
    assert names - baseline == DELETE_TOOLS


async def test_enable_batch_ops_adds_only_batch_ops(monkeypatch: pytest.MonkeyPatch) -> None:
    """OUTLINE_ENABLE_BATCH_OPS adds exactly the bulk writes, nothing else."""
    _clear_gates(monkeypatch)
    monkeypatch.setenv("OUTLINE_ENABLE_DELETE", "true")
    baseline = await _tool_names(get_stdio_mcp())
    monkeypatch.setenv("OUTLINE_ENABLE_BATCH_OPS", "true")
    names = await _tool_names(get_stdio_mcp())
    assert names - baseline == BATCH_OP_TOOLS
    # Enabling batch ops adds only; nothing already listed may disappear.
    assert baseline - names == set()
    # batch_delete_documents is a delete: it rides the delete gate, so it was
    # already listed in the baseline and must not appear in that difference.
    assert "batch_delete_documents" in baseline


async def test_flags_tolerate_surrounding_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    """A trailing space (routine in Docker .env files) must still be honoured."""
    _clear_gates(monkeypatch)
    monkeypatch.setenv("OUTLINE_ENABLE_DELETE", "true ")
    names = await _tool_names(get_stdio_mcp())
    assert DELETE_TOOLS <= names

    monkeypatch.setenv("OUTLINE_READ_ONLY", " true ")
    names = await _tool_names(get_stdio_mcp())
    assert "search_documents" in names
    assert "create_document" not in names
    assert not (DELETE_TOOLS & names)


async def test_read_only_overrides_both_opt_in_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    """Read-only wins over every opt-in — the precedence the startup log promises.

    Locks the module split: moving batch_operations into _READ_MODULES (as
    collection_tools already is) would let OUTLINE_ENABLE_BATCH_OPS register
    bulk writes on a read-only server, which no other test would catch.
    """
    _clear_gates(monkeypatch)
    monkeypatch.setenv("OUTLINE_READ_ONLY", "true")
    monkeypatch.setenv("OUTLINE_ENABLE_DELETE", "true")
    monkeypatch.setenv("OUTLINE_ENABLE_BATCH_OPS", "true")
    names = await _tool_names(get_stdio_mcp())
    assert not (DELETE_TOOLS & names)
    assert not (BATCH_OP_TOOLS & names)
    assert "search_documents" in names


async def test_meta_tools_are_gone() -> None:
    """The discovery layer is not registered or listed anywhere."""
    for factory in (get_stdio_mcp, get_http_mcp):
        names = await _tool_names(factory())
        for meta in META_TOOLS:
            assert meta not in names


async def test_stdio_and_http_expose_the_same_tools() -> None:
    """Both factories go through register_tools, so their listings match."""
    assert await _tool_names(get_stdio_mcp()) == await _tool_names(get_http_mcp())


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


async def test_read_only_and_disable_ai_compose(monkeypatch: pytest.MonkeyPatch) -> None:
    """The two gates are independent and apply together."""
    monkeypatch.setenv("OUTLINE_READ_ONLY", "true")
    monkeypatch.setenv("OUTLINE_DISABLE_AI_TOOLS", "true")
    names = await _tool_names(get_stdio_mcp())
    assert "search_documents" in names
    assert "create_document" not in names
    assert "ask_ai_about_documents" not in names


async def test_enabled_tools_env_var_is_not_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    """OUTLINE_MCP_ENABLED_TOOLS was removed — a stale value must not narrow the set."""
    monkeypatch.setenv("OUTLINE_MCP_ENABLED_TOOLS", "search_documents,read_document")
    names = await _tool_names(get_stdio_mcp())
    assert "create_document" in names


async def test_http_factory_builds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The HTTP factory constructs and lists the full tool set."""
    _clear_gates(monkeypatch)
    names = await _tool_names(get_http_mcp())
    assert "search_documents" in names
    assert names == await _names_registered_by_every_module()


def test_resolved_api_key_prefers_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Outside a request context, the env var supplies the key."""
    monkeypatch.setenv("OUTLINE_API_KEY", "ol_api_test")
    assert client_mod.get_resolved_api_key() == "ol_api_test"
