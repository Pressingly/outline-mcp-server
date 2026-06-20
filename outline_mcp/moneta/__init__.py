"""Moneta fork additions for the Outline MCP Server.

All Pressingly/Moneta-specific code lives in this package so the upstream
``outline_mcp`` modules stay close to the Arbisoft base — upstream pulls then
touch only a handful of one-line hooks, not the fork logic.

Hooks into upstream (kept intentionally tiny):

* ``outline_mcp.__main__`` — http mode delegates to
  :func:`outline_mcp.moneta.http.run` when :func:`outline_mcp.moneta.http.enabled`
  is true (Cognito / devstack).
* ``outline_mcp.client`` — :func:`outline_mcp.client.get_outline_client` tries
  :func:`outline_mcp.moneta.apitoken.build_outline_client` first (mint + cache a
  per-user Outline API key from the relayed Cognito identity).

Everything else (the Cognito provider, OAuth-state storage, the Cognito HTTP
app, the API-key minting bridge) is defined here. Some helpers are duplicated
from upstream rather than imported, by design — duplication is cheaper than
recurring merge conflicts.
"""
