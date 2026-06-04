"""Tests for the Target adapter behaviors that don't need a real MCP server.

Covers:

- Per-call timeout via ``asyncio.wait_for`` (P1.1).
- ``list_tools`` caching (P4.16).

Both use fake sessions with controlled timing / call counting.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from mcp_strike.target.adapter import Target


class _FakeSession:
    """Minimal ClientSession stand-in for timeout tests.

    ``call_tool`` and ``list_tools`` sleep for ``delay`` seconds before
    returning, so the timeout wrapper has something slow to interrupt.
    """

    def __init__(self, *, delay: float) -> None:
        self._delay = delay

    async def call_tool(self, name: str, arguments: dict[str, object]) -> object:
        await asyncio.sleep(self._delay)
        return object()  # never reached when the timeout fires

    async def list_tools(self) -> object:
        await asyncio.sleep(self._delay)
        return object()


# --- Fakes for caching tests ----------------------------------------------
# A separate fake that returns a real ListToolsResult-shaped object (with
# .tools, each tool having .name / .description / .inputSchema) and tracks
# how many times list_tools() was invoked.


@dataclass
class _FakeTool:
    name: str
    description: str
    inputSchema: dict[str, Any] = field(default_factory=dict)  # noqa: N815  (mimic MCP field name)


@dataclass
class _FakeListToolsResult:
    tools: list[_FakeTool]


class _CountingSession:
    """Tracks how many times list_tools() is called."""

    def __init__(self) -> None:
        self.list_tools_calls = 0

    async def list_tools(self) -> _FakeListToolsResult:
        self.list_tools_calls += 1
        return _FakeListToolsResult(
            tools=[_FakeTool(name="dummy", description="dummy desc")]
        )

    async def call_tool(self, name: str, arguments: dict[str, object]) -> object:
        return object()


def test_call_tool_raises_timeout_error_after_deadline() -> None:
    """A call slower than the timeout should raise asyncio.TimeoutError."""
    session = _FakeSession(delay=1.0)
    target = Target(session, call_timeout=0.05)  # 50ms timeout

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(target.call_tool("anything", {}))


def test_list_tools_raises_timeout_error_after_deadline() -> None:
    """list_tools should respect the same timeout."""
    session = _FakeSession(delay=1.0)
    target = Target(session, call_timeout=0.05)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(target.list_tools())


def test_no_timeout_when_call_returns_quickly() -> None:
    """A call faster than the timeout should succeed normally.

    Pairing with the above tests proves the timeout actually does
    something, not just always-raises behavior.
    """
    # Delay shorter than timeout. Real call returns a sentinel.
    session = _FakeSession(delay=0.0)
    target = Target(session, call_timeout=1.0)

    # Should not raise. The fake returns object() so we just confirm completion.
    result = asyncio.run(target.call_tool("anything", {}))
    assert result is not None


# --- caching tests (P4.16) ------------------------------------------------


def test_list_tools_is_cached_after_first_call() -> None:
    """A second list_tools() returns the cached list without a new RPC.

    This is the optimization that collapses N attack-invocations into 1
    stdio round-trip per scan.
    """
    session = _CountingSession()
    target = Target(session, call_timeout=1.0)

    tools_a = asyncio.run(target.list_tools())
    tools_b = asyncio.run(target.list_tools())

    # Same list object, not just equal; proves we returned the cache.
    assert tools_a is tools_b
    # And the underlying session was hit exactly once.
    assert session.list_tools_calls == 1


def test_list_tools_cache_survives_multiple_calls() -> None:
    """Many calls => exactly one underlying list_tools invocation."""
    session = _CountingSession()
    target = Target(session, call_timeout=1.0)

    async def hit_n(n: int) -> None:
        for _ in range(n):
            await target.list_tools()

    asyncio.run(hit_n(10))
    assert session.list_tools_calls == 1
