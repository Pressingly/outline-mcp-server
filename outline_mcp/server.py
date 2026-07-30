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

INSTRUCTIONS = (
    "Manages documents, collections, and collaboration in Outline, "
    "a knowledge base and wiki.\n\n"
    "Every available tool is listed up front — call them directly. There is no "
    "discovery or enablement step.\n\n"
    "Getting started: use search_documents to find content, read_document to "
    "view a document, or list_collections to browse the wiki structure."
)


def get_stdio_mcp() -> FastMCP:
    """Stdio mode — credential from ``OUTLINE_API_KEY``."""
    mcp = FastMCP("Outline MCP Server (stdio)", instructions=INSTRUCTIONS)
    register_tools(mcp)
    return mcp


def get_http_mcp() -> FastMCP:
    """HTTP mode — per-request ``x-outline-api-key`` header auth.

    No OAuth provider: each request supplies its own Outline API key via the
    ``x-outline-api-key`` header (resolved in :mod:`outline_mcp.client`). The
    moneta fork replaces this with a Cognito-backed provider.
    """
    mcp = FastMCP("Outline MCP Server (http)", instructions=INSTRUCTIONS)
    register_tools(mcp)
    return mcp


def read_only() -> bool:
    """Whether write tools are disabled (``OUTLINE_READ_ONLY``)."""
    return os.getenv("OUTLINE_READ_ONLY", "").lower() in ("true", "1", "yes")
