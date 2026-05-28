"""MCP connection layer (transport-level).

Thin wrapper over the official `mcp` Python SDK. This package owns
transport-specific session setup. The higher-level normalized API lives in
``mcp_strike.target`` (see docs/PLAN.md §6).
"""

from mcp_strike.client.stdio import open_stdio_session

__all__ = ["open_stdio_session"]
