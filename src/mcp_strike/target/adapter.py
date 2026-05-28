"""Target adapter — the normalized 'server under test' surface.

Attack modules consume :class:`Target` and don't need to know whether the
underlying transport is stdio or HTTP. Phase 1 wires up stdio only; HTTP
arrives in a later phase (see docs/PLAN.md §6).

Two pieces live here:

- :class:`ToolInfo`  — a small, attack-friendly representation of one tool.
- :class:`Target`    — a connected MCP session, with normalized methods.
- :func:`open_stdio_target` — convenience async context manager that
  combines :func:`mcp_strike.client.open_stdio_session` with a Target wrapper.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession
from mcp.types import CallToolResult

from mcp_strike.client import open_stdio_session


@dataclass
class ToolInfo:
    """A tool exposed by the target, reduced to the fields attacks care about.

    Intentionally NOT ``frozen=True`` because ``input_schema`` is a mutable
    dict. Treat the schema as read-only by convention.
    """

    name: str
    description: str
    # The JSON Schema describing the tool's arguments, as the MCP server
    # advertised it (typically a dict with a top-level ``properties`` key).
    # Empty for tools that take no parameters.
    input_schema: dict[str, Any] = field(default_factory=dict)


class Target:
    """A connected, initialized MCP session, ready to be attacked.

    Construct via :func:`open_stdio_target` (or a future
    ``open_http_target``); don't instantiate directly outside of that.
    """

    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def list_tools(self) -> list[ToolInfo]:
        """Enumerate the tools the target advertises."""
        result = await self._session.list_tools()
        return [
            ToolInfo(
                name=tool.name,
                # MCP allows `description` to be null in the spec; coerce.
                description=tool.description or "",
                # And likewise for the schema — older servers may omit it.
                input_schema=tool.inputSchema or {},
            )
            for tool in result.tools
        ]

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> CallToolResult:
        """Invoke a tool by name with the given arguments.

        Returns the raw MCP ``CallToolResult`` so attacks can inspect the
        content blocks themselves. We don't normalize the response shape
        here because different attacks care about different parts of it.
        """
        return await self._session.call_tool(name, arguments)


@asynccontextmanager
async def open_stdio_target(
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
) -> AsyncIterator[Target]:
    """Open a :class:`Target` backed by an MCP server launched over stdio.

    The subprocess is started on enter and torn down on exit; the yielded
    Target is usable for the duration of the ``async with`` block.
    """
    async with open_stdio_session(command=command, args=args, env=env) as session:
        yield Target(session)
