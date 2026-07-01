"""Tool registration for the Outline MCP Server.

Read-only tools are always registered. AI and write tools are gated by env
flags so the server can run against locked-down or read-only Outline instances:

- ``OUTLINE_READ_ONLY=true`` — register read-only tools only.
- ``OUTLINE_DISABLE_AI_TOOLS=true`` — skip the AI ``ask_ai_about_documents`` tool.
- ``OUTLINE_MCP_ENABLED_TOOLS=tool1,tool2`` — override the default startup set.
  When set, these tools (plus the two meta tools) are exposed on startup instead
  of the built-in defaults.  Only tools allowed by the read-only / AI flags can
  be enabled.

Progressive discovery
---------------------
On startup only a small default set of tools is registered.  Two meta tools are
always available:

- ``list_available_tools`` — returns the full catalog of all tools with
  descriptions, grouped by category, indicating which are currently enabled.
- ``enable_tools`` — dynamically registers additional tools by name.
"""

from __future__ import annotations

import os
from types import ModuleType
from typing import Any

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

# Ordered list of all tool modules.
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

# Human-friendly category labels keyed by module name suffix.
_MODULE_CATEGORIES: dict[str, str] = {
    "document_search": "Search & Discovery",
    "document_reading": "Reading",
    "document_navigation": "Navigation",
    "document_attachments": "Attachments",
    "document_collaboration": "Collaboration",
    "collection_tools": "Collections",
    "ai_tools": "AI",
    "document_content": "Content Creation",
    "document_editing": "Editing",
    "document_lifecycle": "Lifecycle",
    "document_organization": "Organization",
    "batch_operations": "Batch Operations",
}

# Default tools exposed on startup (before any explicit enable_tools call).
_DEFAULT_TOOLS = frozenset(
    {
        "search_documents",
        "read_document",
        "create_document",
        "update_document",
        "list_collections",
    }
)

# Names of the two meta tools — always registered, never pruned or catalogued.
_META_TOOL_NAMES = frozenset({"list_available_tools", "enable_tools", "execute_tool"})


def _flag(name: str) -> bool:
    return os.getenv(name, "").lower() in _TRUTHY


def _registered_tool_names(mcp: FastMCP) -> set[str]:
    """Return the names of all currently registered tools."""
    return {c.name for c in mcp.local_provider._components.values() if isinstance(c, Tool)}


# ---------------------------------------------------------------------------
# Catalog: built once during ``register_tools`` and shared with the meta tools
# via closure.
# ---------------------------------------------------------------------------

# Each entry: tool_name -> {"description": str, "category": str, "module": ModuleType}
_ToolCatalog = dict[str, dict]


def _build_catalog(mcp: FastMCP, modules: tuple[ModuleType, ...]) -> _ToolCatalog:
    """Register *modules* one-by-one and record which tools each provides.

    Returns a catalog mapping ``tool_name`` to metadata.  The catalog
    represents the *maximum* set of tools the server will ever expose (subject
    to read-only / AI flags).
    """
    catalog: _ToolCatalog = {}
    for mod in modules:
        before = _registered_tool_names(mcp)
        mod.register_tools(mcp)
        after = _registered_tool_names(mcp)
        new_tools = after - before

        mod_key = mod.__name__.rsplit(".", 1)[-1]
        category = _MODULE_CATEGORIES.get(mod_key, mod_key)

        for name in new_tools:
            # Grab the Tool object to capture its description.
            tool_obj: Tool | None = None
            for comp in mcp.local_provider._components.values():
                if isinstance(comp, Tool) and comp.name == name:
                    tool_obj = comp
                    break
            catalog[name] = {
                "description": (tool_obj.description or "")[:200] if tool_obj else "",
                "category": category,
                "module": mod,
                "component": tool_obj,
            }
    return catalog


def _filter_to(mcp: FastMCP, keep: set[str]) -> None:
    """Remove all registered tools except those in *keep*.

    Meta tools are never removed by this function.
    """
    registered = _registered_tool_names(mcp)
    removable = registered - _META_TOOL_NAMES
    for name in removable - keep:
        mcp.local_provider.remove_tool(name)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def register_tools(mcp: FastMCP) -> None:
    """Register Outline tools with the MCP server.

    1. Register tool modules respecting ``OUTLINE_READ_ONLY`` and
       ``OUTLINE_DISABLE_AI_TOOLS``.
    2. Build a catalog from whatever was registered.
    3. Prune to the startup set (env override or built-in defaults).
    4. Register the two always-on meta tools.
    """

    # --- Determine which modules to load (respects read-only / AI flags) ---
    read_only = _flag("OUTLINE_READ_ONLY")
    disable_ai = _flag("OUTLINE_DISABLE_AI_TOOLS")

    read_modules = (
        document_search,
        document_reading,
        document_navigation,
        document_attachments,
        document_collaboration,
        collection_tools,
    )
    ai_modules = () if disable_ai else (ai_tools,)
    write_modules = (
        ()
        if read_only
        else (
            document_content,
            document_editing,
            document_lifecycle,
            document_organization,
            batch_operations,
        )
    )
    allowed_modules = read_modules + ai_modules + write_modules

    # --- Build catalog (registers all allowed tools, captures metadata) ---
    catalog = _build_catalog(mcp, allowed_modules)

    # --- Determine startup set ---
    enabled_raw = os.getenv("OUTLINE_MCP_ENABLED_TOOLS", "").strip()
    if enabled_raw:
        startup_set = {t.strip() for t in enabled_raw.split(",") if t.strip()}
        # Only keep names that actually exist in the catalog.
        invalid = startup_set - set(catalog)
        if invalid:
            logger.warning(
                "OUTLINE_MCP_ENABLED_TOOLS requested tools not in catalog: %s",
                ", ".join(sorted(invalid)),
            )
        startup_set &= set(catalog)
    else:
        startup_set = _DEFAULT_TOOLS & set(catalog)

    # --- Prune to startup set ---
    _filter_to(mcp, startup_set)

    final_names = startup_set & _registered_tool_names(mcp)
    logger.info("Startup tools: %s", ", ".join(sorted(final_names)))

    # --- Register meta tools (always available) ---
    _register_meta_tools(mcp, catalog)

    all_registered = sorted(_registered_tool_names(mcp))
    logger.info("All registered tools (incl. meta): %s", ", ".join(all_registered))


# ---------------------------------------------------------------------------
# Meta tools
# ---------------------------------------------------------------------------


def _register_meta_tools(mcp: FastMCP, catalog: _ToolCatalog) -> None:
    """Register ``list_available_tools``, ``enable_tools``, and ``execute_tool``."""

    @mcp.tool(
        description=(
            "Lists ALL available Outline tools grouped by category, showing "
            "which are currently enabled. Tools marked 'not yet enabled' ARE "
            "available — call enable_tools to activate them before use."
        )
    )
    async def list_available_tools() -> str:
        """Return the full tool catalog with enabled/disabled status."""
        currently_enabled = _registered_tool_names(mcp) - _META_TOOL_NAMES

        # Group by category.
        by_category: dict[str, list[dict]] = {}
        for name, meta in sorted(catalog.items()):
            cat = meta["category"]
            by_category.setdefault(cat, []).append(
                {
                    "name": name,
                    "enabled": name in currently_enabled,
                    "description": meta["description"],
                }
            )

        lines: list[str] = []
        for category, tools in sorted(by_category.items()):
            lines.append(f"\n## {category}")
            for t in sorted(tools, key=lambda x: x["name"]):
                status = "[enabled]" if t["enabled"] else "[not yet enabled — call enable_tools]"
                lines.append(f"  - {t['name']} {status}")
                if t["description"]:
                    # Show first sentence of the description.
                    first_sentence = t["description"].split("\n")[0].strip()
                    lines.append(f"    {first_sentence}")
                # Include parameter schema when available.
                comp = catalog[t["name"]].get("component") if t["name"] in catalog else None
                if comp and hasattr(comp, "parameters"):
                    params = comp.parameters or {}
                    if "properties" in params:
                        param_names = list(params["properties"].keys())
                        required = params.get("required", [])
                        param_list = ", ".join(f"{p} (required)" if p in required else p for p in param_names)
                        lines.append(f"    Parameters: {param_list}")

        total = len(catalog)
        enabled_count = len(currently_enabled)
        header = (
            f"Outline MCP Tools: {enabled_count}/{total} enabled\n"
            f"{total - enabled_count} more tools are available and ready to use — "
            "call enable_tools(tool_names=[...]) to activate them.\n"
        )
        return header + "\n".join(lines)

    @mcp.tool(
        description=(
            "REQUIRED before using any non-default tool. Activates additional "
            "Outline tools by name so you can call them. Call "
            "list_available_tools first to see what's available."
        )
    )
    async def enable_tools(tool_names: list[str]) -> str:
        """Enable tools by name, registering their parent modules."""
        if not tool_names:
            return "No tool names provided. Call list_available_tools to see available tools."

        valid: list[str] = []
        invalid: list[str] = []
        already_enabled: list[str] = []
        currently_registered = _registered_tool_names(mcp)

        # Collect modules that need registering.
        modules_to_register: dict[int, ModuleType] = {}
        for name in tool_names:
            if name in _META_TOOL_NAMES:
                already_enabled.append(name)
                continue
            if name not in catalog:
                invalid.append(name)
                continue
            if name in currently_registered:
                already_enabled.append(name)
                continue
            valid.append(name)
            mod = catalog[name]["module"]
            modules_to_register[id(mod)] = mod

        # Re-register the required modules.
        before = _registered_tool_names(mcp)
        for mod in modules_to_register.values():
            mod.register_tools(mcp)
        after = _registered_tool_names(mcp)
        newly_registered = after - before

        # Build response.
        parts: list[str] = []
        if valid:
            parts.append(f"Enabled: {', '.join(sorted(valid))}")
        extras = sorted(newly_registered - set(valid))
        if extras:
            parts.append(f"Also enabled (same module): {', '.join(extras)}")
        if already_enabled:
            parts.append(f"Already enabled: {', '.join(sorted(already_enabled))}")
        if invalid:
            parts.append(f"Not found in catalog (check spelling): {', '.join(sorted(invalid))}")

        return "\n".join(parts) if parts else "No changes made."

    @mcp.tool(
        description=(
            "Execute any available tool by name. Use list_available_tools "
            "first to discover tool names and their parameters, then call "
            "this with the tool name and arguments dict."
        )
    )
    async def execute_tool(tool_name: str, arguments: dict) -> Any:
        """Execute a cataloged tool via proxy."""
        if tool_name in _META_TOOL_NAMES:
            return {"error": f"Meta tool '{tool_name}' must be called directly"}
        entry = catalog.get(tool_name)
        if entry is None:
            return {
                "error": f"Unknown tool: {tool_name}",
                "hint": "Call list_available_tools to see available tools",
            }
        comp = entry.get("component")
        if comp is None:
            return {"error": f"Tool '{tool_name}' has no callable component"}
        return await comp.run(arguments)
