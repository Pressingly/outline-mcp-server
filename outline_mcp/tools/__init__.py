"""Tool registration for the Outline MCP Server.

Every tool the server is allowed to expose is registered on startup and listed
on ``tools/list`` — the standard MCPO convention, where each listed tool becomes
one generated HTTP endpoint. There is no runtime discovery or enablement step:
an LLM sees the real tool list on connect and calls tools directly.

Four env flags still gate which tools load, so the server can run against
locked-down or read-only Outline instances:

- ``OUTLINE_READ_ONLY=true`` — register read-only tools only.
- ``OUTLINE_DISABLE_AI_TOOLS=true`` — skip the AI ``ask_ai_about_documents`` tool.
- ``OUTLINE_ENABLE_DELETE=true`` — opt in to ``delete_document``,
  ``delete_collection`` and ``batch_delete_documents``. **Defaults to false**:
  no delete tool is registered unless this is explicitly set.
- ``OUTLINE_ENABLE_BATCH_OPS=true`` — opt in to the wide-blast-radius bulk
  writes ``batch_archive_documents``, ``batch_move_documents``,
  ``batch_update_documents`` and ``batch_create_documents``. **Defaults to
  false**: no bulk-write tool is registered unless this is explicitly set.
  Bulk creation sits behind the same flag as the other bulk writes — a gate
  named "enable batch ops" that left creation open would be misleading.
  ``batch_delete_documents`` stays under ``OUTLINE_ENABLE_DELETE``: it is a
  delete (it can bypass the trash entirely), so enabling bulk moves must not
  quietly change an operator's delete posture.

All four are parsed by :func:`outline_mcp.env_flags.env_flag`.
"""

from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.tools import Tool
from fastmcp.utilities.logging import get_logger

from outline_mcp.env_flags import env_flag
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

# Read-only modules — always registered.
_READ_MODULES = (
    document_search,
    document_reading,
    document_navigation,
    document_attachments,
    document_collaboration,
    collection_tools,
)

# Write modules — skipped when ``OUTLINE_READ_ONLY`` is set.
_WRITE_MODULES = (
    document_content,
    document_editing,
    document_lifecycle,
    document_organization,
    batch_operations,
)


def register_tools(mcp: FastMCP) -> None:
    """Register every Outline tool allowed by the four registration env flags."""
    read_only = env_flag("OUTLINE_READ_ONLY")
    disable_ai = env_flag("OUTLINE_DISABLE_AI_TOOLS")
    enable_delete = env_flag("OUTLINE_ENABLE_DELETE")
    enable_batch_ops = env_flag("OUTLINE_ENABLE_BATCH_OPS")

    modules = _READ_MODULES
    if not disable_ai:
        modules += (ai_tools,)
    if not read_only:
        modules += _WRITE_MODULES

    for mod in modules:
        mod.register_tools(mcp)

    count = sum(1 for c in mcp.local_provider._components.values() if isinstance(c, Tool))
    logger.info(
        "Registered %d tool(s) from %d module(s) (read_only=%s, ai_disabled=%s)",
        count,
        len(modules),
        read_only,
        disable_ai,
    )
    # Say why a tool is missing, so an operator whose tools vanished after an
    # upgrade finds the reason in the logs instead of a silently shorter list.
    # Under read-only the write modules never load, so naming the opt-in flag
    # would send the operator to a switch that cannot bring the tools back.
    if read_only:
        logger.info("OUTLINE_READ_ONLY is set — all write tools are withheld regardless of the other flags")
    else:
        if not enable_delete:
            logger.info("Destructive delete tools are DISABLED — set OUTLINE_ENABLE_DELETE=true to register them")
        if not enable_batch_ops:
            logger.info("Bulk batch write tools are DISABLED — set OUTLINE_ENABLE_BATCH_OPS=true to register them")
