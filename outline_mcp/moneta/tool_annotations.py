"""Single source of truth for the MCP tool hints published on ``tools/list``.

Every tool is classified once, in :data:`TOOL_ACCESS`. A middleware rewrites the
``readOnlyHint`` and ``destructiveHint`` of each listed tool from that table, so
the hints never depend on the per-tool decorators. A tool missing from the table
is published as a destructive write: the fail-safe default, because a client
may auto-approve a read-only tool and must never do so for one that writes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum

import mcp.types as mt
from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.middleware.middleware import CallNext
from fastmcp.tools import Tool
from mcp.types import ToolAnnotations


class Access(Enum):
    READ = "read"
    ADD = "add"
    WRITE = "write"


TOOL_ACCESS: Mapping[str, Access] = {
    "ask_ai_about_documents": Access.READ,
    "export_document": Access.READ,
    "fetch_attachment": Access.READ,
    "get_attachment_url": Access.READ,
    "get_collection_structure": Access.READ,
    "get_comment": Access.READ,
    "get_document_backlinks": Access.READ,
    "get_document_id_from_title": Access.READ,
    "get_document_toc": Access.READ,
    "list_archived_documents": Access.READ,
    "list_collections": Access.READ,
    "list_document_attachments": Access.READ,
    "list_document_comments": Access.READ,
    "list_trash": Access.READ,
    "read_document": Access.READ,
    "read_document_section": Access.READ,
    "search_document_content": Access.READ,
    "search_documents": Access.READ,
    "add_comment": Access.ADD,
    "export_all_collections": Access.ADD,
    "export_collection": Access.ADD,
    "create_collection": Access.ADD,
    "create_document": Access.ADD,
    "batch_create_documents": Access.ADD,
    "archive_document": Access.WRITE,
    "batch_archive_documents": Access.WRITE,
    "batch_delete_documents": Access.WRITE,
    "batch_move_documents": Access.WRITE,
    "batch_update_documents": Access.WRITE,
    "delete_collection": Access.WRITE,
    "delete_document": Access.WRITE,
    "edit_document": Access.WRITE,
    "move_document": Access.WRITE,
    "restore_document": Access.WRITE,
    "unarchive_document": Access.WRITE,
    "update_collection": Access.WRITE,
    "update_document": Access.WRITE,
}


def access_for(tool_name: str) -> Access:
    return TOOL_ACCESS.get(tool_name, Access.WRITE)


def hints_for(access: Access) -> dict[str, bool]:
    return {
        "readOnlyHint": access is Access.READ,
        "destructiveHint": access is Access.WRITE,
    }


def annotated(tool: Tool) -> Tool:
    current = tool.annotations or ToolAnnotations()
    updated = current.model_copy(update=hints_for(access_for(tool.name)))
    return tool.model_copy(update={"annotations": updated})


class ToolAnnotationsMiddleware(Middleware):
    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        return [annotated(tool) for tool in await call_next(context)]


def install_tool_annotations(mcp: FastMCP) -> None:
    mcp.add_middleware(ToolAnnotationsMiddleware())
