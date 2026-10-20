"""Tool hints published on tools/list come from one table and fail safe."""

from __future__ import annotations

import pytest
from fastmcp import Client, FastMCP
from mcp.types import ToolAnnotations

from outline_mcp.moneta.tool_annotations import TOOL_ACCESS, Access, hints_for
from outline_mcp.server import get_stdio_mcp
from outline_mcp.tools import register_tools

READ_ONLY = {
    "ask_ai_about_documents",
    "export_document",
    "fetch_attachment",
    "get_attachment_url",
    "get_collection_structure",
    "get_comment",
    "get_document_backlinks",
    "get_document_id_from_title",
    "get_document_toc",
    "list_archived_documents",
    "list_collections",
    "list_document_attachments",
    "list_document_comments",
    "list_trash",
    "read_document",
    "read_document_section",
    "search_document_content",
    "search_documents",
}
EXPORT_JOBS = {"export_all_collections", "export_collection"}
ADD_ONLY = {
    "add_comment",
    "create_collection",
    "create_document",
    "batch_create_documents",
} | EXPORT_JOBS
DESTRUCTIVE = {
    "archive_document",
    "batch_archive_documents",
    "batch_delete_documents",
    "batch_move_documents",
    "batch_update_documents",
    "delete_collection",
    "delete_document",
    "edit_document",
    "move_document",
    "restore_document",
    "unarchive_document",
    "update_collection",
    "update_document",
}


@pytest.fixture
def all_tools_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OUTLINE_READ_ONLY", raising=False)
    monkeypatch.delenv("OUTLINE_DISABLE_AI_TOOLS", raising=False)
    monkeypatch.setenv("OUTLINE_ENABLE_DELETE", "true")
    monkeypatch.setenv("OUTLINE_ENABLE_BATCH_OPS", "true")


async def _listed(mcp: FastMCP) -> dict:
    async with Client(mcp) as client:
        return {tool.name: tool.annotations for tool in await client.list_tools()}


async def test_every_tool_publishes_both_hints(all_tools_enabled):
    listed = await _listed(get_stdio_mcp())
    assert listed
    for name, hints in listed.items():
        assert hints is not None, name
        assert hints.readOnlyHint is not None, name
        assert hints.destructiveHint is not None, name


async def test_published_hints_match_expected_classification(all_tools_enabled):
    listed = await _listed(get_stdio_mcp())
    expected = {
        **dict.fromkeys(READ_ONLY, (True, False)),
        **dict.fromkeys(ADD_ONLY, (False, False)),
        **dict.fromkeys(DESTRUCTIVE, (False, True)),
    }
    published = {name: (a.readOnlyHint, a.destructiveHint) for name, a in listed.items()}
    assert published == expected


async def test_table_covers_exactly_the_registered_tools(all_tools_enabled):
    listed = await _listed(get_stdio_mcp())
    assert set(TOOL_ACCESS) == set(listed)


async def test_no_data_changing_tool_is_read_only(all_tools_enabled):
    listed = await _listed(get_stdio_mcp())
    for name in ADD_ONLY | DESTRUCTIVE:
        assert listed[name].readOnlyHint is False, name


async def test_unclassified_tool_is_published_as_destructive_write():
    mcp = FastMCP("scratch")

    @mcp.tool
    def brand_new_tool() -> str:
        return "x"

    register_tools(mcp)
    annotations = (await _listed(mcp))["brand_new_tool"]
    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is True


async def test_collection_exports_are_not_advertised_as_idempotent(all_tools_enabled):
    listed = await _listed(get_stdio_mcp())
    for name in EXPORT_JOBS:
        assert listed[name].idempotentHint is False, name


@pytest.mark.parametrize(
    ("tool_name", "decorator_hints", "expected"),
    [
        (
            "delete_document",
            ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=False),
            (False, True),
        ),
        (
            "list_collections",
            ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False),
            (True, False),
        ),
    ],
)
async def test_hints_replace_conflicting_decorator_values(all_tools_enabled, tool_name, decorator_hints, expected):
    mcp = FastMCP("scratch")
    register_tools(mcp)

    @mcp.tool(name=tool_name, annotations=decorator_hints)
    def stub() -> str:
        return "x"

    annotations = (await _listed(mcp))[tool_name]
    assert (annotations.readOnlyHint, annotations.destructiveHint) == expected
    assert annotations.idempotentHint is False


def test_hints_for_each_access_level():
    assert hints_for(Access.READ) == {"readOnlyHint": True, "destructiveHint": False}
    assert hints_for(Access.ADD) == {"readOnlyHint": False, "destructiveHint": False}
    assert hints_for(Access.WRITE) == {"readOnlyHint": False, "destructiveHint": True}
    assert hints_for(Access.START_JOB) == {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
    }
