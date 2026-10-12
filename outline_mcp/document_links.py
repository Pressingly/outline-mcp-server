"""Absolute, user-facing document links.

Outline returns a document's ``url`` as a path (``/doc/<slug>-<urlId>``). The
public host is derived from ``OUTLINE_API_URL``; when it is not configured the
path is returned unchanged, so a link never points at a guessed host or at the
internal API URL.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

_API_SUFFIX = "/api"


def _is_web_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _is_absolute(path_or_url: str) -> bool:
    return bool(urlparse(path_or_url).netloc)


def public_base_url(api_url: str) -> str:
    """Return the public Outline base for an API URL, or "" if it is not a web URL."""
    base = api_url.strip().rstrip("/")
    if base.lower().endswith(_API_SUFFIX):
        base = base[: -len(_API_SUFFIX)].rstrip("/")
    return base if _is_web_url(base) else ""


def public_document_url(path_or_url: str, base: str) -> str:
    """Join a document path onto ``base``; absolute URLs and empty inputs pass through."""
    if not path_or_url or not base or _is_absolute(path_or_url):
        return path_or_url
    return f"{base.rstrip('/')}/{path_or_url.lstrip('/')}"


def configured_public_base() -> str:
    """Return the public Outline base derived from ``OUTLINE_API_URL``."""
    return public_base_url(os.getenv("OUTLINE_API_URL", ""))


def document_link(path_or_url: str) -> str:
    """Return the link to show a user for an Outline document ``url``."""
    return public_document_url(path_or_url, configured_public_base())


def with_document_link(message: str, path_or_url: str) -> str:
    """Append a ``URL:`` line to ``message`` when the document has a link."""
    link = document_link(path_or_url)
    return f"{message}\nURL: {link}" if link else message
