# Outline MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes
an [Outline](https://www.getoutline.com) wiki / knowledge base to any
MCP-compatible client (Claude Desktop, Claude Code, Cursor, MCP Inspector, …).

Built on [FastMCP v3](https://gofastmcp.com). The server is a thin wrapper over
Outline's HTTP API — searching, reading, navigating, editing, organizing
documents and collections, comments, attachments, and batch operations.

## Transports

| Mode | Command | Auth |
|---|---|---|
| stdio | `outline-mcp-server stdio` | `OUTLINE_API_KEY` env var |
| streamable-HTTP | `outline-mcp-server http` | per-request `x-outline-api-key` header |

## Configuration

| Variable | Required for | Purpose |
|---|---|---|
| `OUTLINE_API_KEY` | stdio | Outline API key (Settings → API). |
| `OUTLINE_API_URL` | all | Outline API base URL, e.g. `https://app.getoutline.com/api`. |
| `OUTLINE_READ_ONLY` | optional | `true` to register read-only tools only. |
| `OUTLINE_DISABLE_AI_TOOLS` | optional | `true` to skip the AI `ask_ai_about_documents` tool. |
| `OUTLINE_VERIFY_SSL` | optional | `false` to skip TLS verification (self-signed certs). |
| `MCP_HTTP_PORT` | http | Listener port (default `8213`). |
| `MCP_ALLOWED_ORIGINS` | http | Comma-separated CORS allow-list (default `*`). |
| `MCP_LOG_LEVEL` | optional | `DEBUG` / `INFO` / `WARNING` / `ERROR`. |

## Quick start

```bash
uv pip install -e ".[dev]"

# stdio
OUTLINE_API_KEY=ol_api_... OUTLINE_API_URL=https://app.getoutline.com/api \
  outline-mcp-server stdio

# streamable-HTTP (per-request x-outline-api-key header)
OUTLINE_API_URL=https://app.getoutline.com/api outline-mcp-server http
```

Claude Code (stdio):

```bash
claude mcp add outline -- uvx outline-mcp-server stdio
```

## Development

```bash
uv pip install -e ".[dev]"
ruff check outline_mcp/
ruff format outline_mcp/
pytest
```

## Credits

The Outline API tool implementations are ported (MIT) from
[`Vortiago/mcp-outline`](https://github.com/Vortiago/mcp-outline) and rebuilt on
FastMCP v3. See [`LICENSE`](./LICENSE).
