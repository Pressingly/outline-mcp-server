"""Tool registration for the Outline MCP Server.

Read-only tools are always registered. AI and write tools are gated by env
flags so the server can run against locked-down or read-only Outline instances:

- ``OUTLINE_READ_ONLY=true`` — register read-only tools only.
- ``OUTLINE_DISABLE_AI_TOOLS=true`` — skip the AI ``ask_ai_about_documents`` tool.
- ``OUTLINE_MCP_ENABLED_TOOLS=tool1,tool2`` — register *only* the listed tools.
  When set this takes precedence over ``OUTLINE_READ_ONLY`` and
  ``OUTLINE_DISABLE_AI_TOOLS``.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP
from fastmcp.tools import Tool
from fastmcp.utilities.logging import get_logger

from outline_mcp.tools import (
    ai_tools,
    batch_operations,
    collection_tools,
    document_attachments,
    document_collaboration,
    document_content,
    document_editing,
    document_lifecycle,
    document_navigation,
    document_organization,
    document_reading,
    document_search,
)

logger = get_logger(__name__)

_TRUTHY = ("true", "1", "yes")

_ALL_MODULES = (
    document_search,
    document_reading,
    document_navigation,
    document_attachments,
    document_collaboration,
    collection_tools,
    ai_tools,
    document_content,
    document_editing,
    document_lifecycle,
    document_organization,
    batch_operations,
)


def _flag(name: str) -> bool:
    return os.getenv(name, "").lower() in _TRUTHY


def _register_all_modules(mcp: FastMCP) -> None:
    """Register every tool module unconditionally."""
    for mod in _ALL_MODULES:
        mod.register_tools(mcp)


def _registered_tool_names(mcp: FastMCP) -> set[str]:
    """Return the names of all currently registered tools."""
    return {
        c.name
        for c in mcp.local_provider._components.values()
        if isinstance(c, Tool)
    }


def _filter_to_enabled(mcp: FastMCP, enabled: set[str]) -> None:
    """Remove any registered tools whose names are not in *enabled*."""
    registered = _registered_tool_names(mcp)
    for name in registered - enabled:
        mcp.local_provider.remove_tool(name)

    final = enabled & registered
    missing = enabled - registered
    if missing:
        logger.warning(
            "OUTLINE_MCP_ENABLED_TOOLS requested tools not found: %s",
            ", ".join(sorted(missing)),
        )
    logger.info("Enabled tools (explicit allow-list): %s", ", ".join(sorted(final)))


def register_tools(mcp: FastMCP) -> None:
    """Register Outline tools with the MCP server.

    If ``OUTLINE_MCP_ENABLED_TOOLS`` is set to a comma-separated list of tool
    names, *only* those tools are registered — ``OUTLINE_READ_ONLY`` and
    ``OUTLINE_DISABLE_AI_TOOLS`` are ignored in that case.

    Otherwise the existing flag-gated behaviour applies.
    """
    enabled_raw = os.getenv("OUTLINE_MCP_ENABLED_TOOLS", "").strip()

    if enabled_raw:
        # Explicit allow-list — register everything, then prune.
        enabled = {t.strip() for t in enabled_raw.split(",") if t.strip()}
        _register_all_modules(mcp)
        _filter_to_enabled(mcp, enabled)
        return

    # --- Default flag-gated path (backward compatible) ---

    # Read-only tools — always available.
    document_search.register_tools(mcp)
    document_reading.register_tools(mcp)
    document_navigation.register_tools(mcp)
    document_attachments.register_tools(mcp)
    document_collaboration.register_tools(mcp)
    collection_tools.register_tools(mcp)

    # AI tool — opt out for instances without the AI feature.
    if not _flag("OUTLINE_DISABLE_AI_TOOLS"):
        ai_tools.register_tools(mcp)

    # Write tools — skipped entirely in read-only mode.
    if not _flag("OUTLINE_READ_ONLY"):
        document_content.register_tools(mcp)
        document_editing.register_tools(mcp)
        document_lifecycle.register_tools(mcp)
        document_organization.register_tools(mcp)
        batch_operations.register_tools(mcp)

    tool_names = sorted(_registered_tool_names(mcp))
    logger.info("Registered tools: %s", ", ".join(tool_names))
