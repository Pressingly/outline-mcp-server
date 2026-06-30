"""Outline MCP Server — FastMCP v3 server factories.

Two transport factories:

* :func:`get_stdio_mcp` — single-user stdio mode, credential from
  ``OUTLINE_API_KEY``.
* :func:`get_http_mcp` — multi-user streamable-HTTP mode, credential from the
  per-request ``x-outline-api-key`` header.

This (upstream) base has no OAuth provider. The Pressingly ``moneta`` fork adds
an ``OutlineCognitoProvider`` (AWS Cognito / mPass) and a ``get_header_mcp``
factory that becomes the sole inbound auth layer in the devstack.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

from outline_mcp.tools import register_tools

_INSTRUCTIONS = (
    "Manages documents in Outline, a wiki and knowledge base. Use for "
    "searching, reading, navigating, editing, and organizing documents and "
    "collections.\n\n"
    "Tool discovery: only a small default set of tools is enabled on startup. "
    "If the current tools cannot fulfill a request, call list_available_tools "
    "to see the full catalog of available tools (collections, lifecycle, batch "
    "operations, AI, etc.), then call enable_tools to activate the ones you "
    "need before using them.\n\n"
    "Finding content: search_documents or get_document_id_from_title to get "
    "document IDs, list_collections to discover collections.\n\n"
    "Large documents: start with get_document_toc to see heading structure, "
    "then read_document_section to read by heading, search_document_content to "
    "grep for text, or read_document with offset/limit for line ranges.\n\n"
    "Editing: use edit_document for targeted changes. Batch all changes into "
    "one call when possible. Use update_document only for full content "
    "replacement, title changes, or appending.\n\n"
    "Markdown: Outline uses standard markdown. For Mermaid diagrams use "
    "mermaidjs (not mermaid) as the code fence language."
)


def get_stdio_mcp() -> FastMCP:
    """Stdio mode — credential from ``OUTLINE_API_KEY``."""
    mcp = FastMCP("Outline MCP Server (stdio)", instructions=_INSTRUCTIONS)
    register_tools(mcp)
    return mcp


def get_http_mcp() -> FastMCP:
    """HTTP mode — per-request ``x-outline-api-key`` header auth.

    No OAuth provider: each request supplies its own Outline API key via the
    ``x-outline-api-key`` header (resolved in :mod:`outline_mcp.client`). The
    moneta fork replaces this with a Cognito-backed provider.
    """
    mcp = FastMCP("Outline MCP Server (http)", instructions=_INSTRUCTIONS)
    register_tools(mcp)
    return mcp


def read_only() -> bool:
    """Whether write tools are disabled (``OUTLINE_READ_ONLY``)."""
    return os.getenv("OUTLINE_READ_ONLY", "").lower() in ("true", "1", "yes")
