"""Stdio transport for the MCP client layer.

Phase 1 role: expose a single async context manager that launches an MCP
server as a subprocess and yields a fully-initialized `mcp.ClientSession`.
Higher-level abstractions (Target, attacks) sit on top of this.

This module is a thin wrapper over the official `mcp` Python SDK; we do not
hand-roll the protocol.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@asynccontextmanager
async def open_stdio_session(
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
) -> AsyncIterator[ClientSession]:
    """Launch an MCP server over stdio and yield an initialized ClientSession.

    The subprocess is spawned on enter and torn down on exit. The yielded
    session has already completed the MCP ``initialize`` handshake, so
    callers can issue RPCs immediately.

    Args:
        command: The executable to run (e.g. ``"python"``).
        args: Arguments passed to ``command``.
        env: Optional environment for the subprocess. When ``None``, the SDK
            supplies a minimal default environment.
    """
    params = StdioServerParameters(command=command, args=args, env=env)
    # `stdio_client` spawns the subprocess and gives us the two streams
    # speaking MCP over its stdin/stdout. `ClientSession` wraps those with
    # JSON-RPC + MCP lifecycle handling.
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            # MCP requires `initialize` before any other RPC.
            await session.initialize()
            yield session
