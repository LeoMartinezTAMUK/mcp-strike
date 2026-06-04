"""Target adapter: the normalized 'server under test' surface.

Attack modules consume :class:`Target` and don't need to know whether the
underlying transport is stdio or HTTP. Currently stdio only.

Three pieces live here:

- :class:`ToolInfo`: a small, attack-friendly representation of one tool.
- :class:`Target`: a connected MCP session, with normalized methods.
- :func:`open_stdio_target`: convenience async context manager that
  combines :func:`mcp_strike.client.open_stdio_session` with a Target wrapper.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession
from mcp.types import CallToolResult

from mcp_strike.client import open_stdio_session

# Default per-call timeout in seconds. Applied to list_tools() and
# call_tool() when nothing more specific is configured. Documented in the
# CLI's --call-timeout help text.
_DEFAULT_CALL_TIMEOUT = 30.0


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

    Every protocol call is bounded by ``call_timeout`` seconds via
    :func:`asyncio.wait_for`. On timeout, :class:`asyncio.TimeoutError`
    propagates to the caller (typically an attack module, which catches
    broadly and records the failure).
    """

    def __init__(
        self,
        session: ClientSession,
        *,
        call_timeout: float = _DEFAULT_CALL_TIMEOUT,
    ) -> None:
        self._session = session
        self._call_timeout = call_timeout
        # Cached on the first successful list_tools() call. Stays put for
        # the lifetime of this Target, typically one scan run. Several
        # attacks plus the agent each call list_tools() independently;
        # caching collapses those N stdio round-trips into 1.
        #
        # MCP has tools/list_changed notifications; the SDK handles them
        # for long-lived sessions. For our scan-then-tear-down lifecycle
        # the cache won't go stale in practice.
        self._cached_tools: list[ToolInfo] | None = None

    async def list_tools(self) -> list[ToolInfo]:
        """Enumerate the tools the target advertises (cached after first call)."""
        if self._cached_tools is not None:
            return self._cached_tools

        result = await asyncio.wait_for(
            self._session.list_tools(), timeout=self._call_timeout
        )
        self._cached_tools = [
            ToolInfo(
                name=tool.name,
                # MCP allows `description` to be null in the spec; coerce.
                description=tool.description or "",
                # And likewise for the schema; older servers may omit it.
                input_schema=tool.inputSchema or {},
            )
            for tool in result.tools
        ]
        return self._cached_tools

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> CallToolResult:
        """Invoke a tool by name with the given arguments.

        Bounded by ``call_timeout``. Returns the raw MCP ``CallToolResult``
        so attacks can inspect the content blocks themselves. We don't
        normalize the response shape here because different attacks care
        about different parts of it.
        """
        return await asyncio.wait_for(
            self._session.call_tool(name, arguments),
            timeout=self._call_timeout,
        )


@asynccontextmanager
async def open_stdio_target(
    command: str,
    args: list[str],
    env: dict[str, str] | None = None,
    *,
    call_timeout: float = _DEFAULT_CALL_TIMEOUT,
) -> AsyncIterator[Target]:
    """Open a :class:`Target` backed by an MCP server launched over stdio.

    The subprocess is started on enter and torn down on exit; the yielded
    Target is usable for the duration of the ``async with`` block.
    ``call_timeout`` applies to every protocol call made via the Target.
    """
    async with open_stdio_session(command=command, args=args, env=env) as session:
        yield Target(session, call_timeout=call_timeout)
