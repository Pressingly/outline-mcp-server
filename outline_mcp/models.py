"""
Pydantic models for MCP tool parameters.

These models generate rich JSON schemas with field names
and descriptions, so LLMs see the expected structure in
the tool's inputSchema — not just ``Dict[str, Any]``.
"""

from pydantic import BaseModel, Field


class DocumentEdit(BaseModel):
    """A single text replacement in a document."""

    old_string: str = Field(description="Exact text to find in the document")
    new_string: str = Field(description="Replacement text")


class BatchUpdateItem(BaseModel):
    """Update specification for a single document."""

    id: str = Field(description="Document ID to update")
    title: str | None = Field(
        default=None,
        description="New title",
    )
    text: str | None = Field(
        default=None,
        description="New content",
    )
    append: bool | None = Field(
        default=None,
        description=("If True, appends text instead of replacing"),
    )


class BatchCreateItem(BaseModel):
    """Creation specification for a single document."""

    title: str = Field(description="Document title")
    collection_id: str = Field(description="Collection ID to create in")
    text: str | None = Field(
        default=None,
        description="Markdown content",
    )
    parent_document_id: str | None = Field(
        default=None,
        description="Parent document ID for nesting",
    )
    publish: bool | None = Field(
        default=None,
        description=("Whether to publish immediately (default: True)"),
    )
