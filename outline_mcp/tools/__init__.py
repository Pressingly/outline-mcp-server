"""Tool registration for the Outline MCP Server.

Read-only tools are always registered. AI and write tools are gated by env
flags so the server can run against locked-down or read-only Outline instances:

- ``OUTLINE_READ_ONLY=true`` — register read-only tools only.
- ``OUTLINE_DISABLE_AI_TOOLS=true`` — skip the AI ``ask_ai_about_documents`` tool.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

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

_TRUTHY = ("true", "1", "yes")


def _flag(name: str) -> bool:
    return os.getenv(name, "").lower() in _TRUTHY


def register_tools(mcp: FastMCP) -> None:
    """Register all Outline tools with the MCP server."""
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
