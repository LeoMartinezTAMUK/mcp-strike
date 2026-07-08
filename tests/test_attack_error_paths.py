"""Unit tests for attack error / UNCERTAIN branches and arg generation.

The per-attack integration tests run against the live demo server, which
exercises the happy paths but not the defensive branches: tools the attack
must skip, probes that raise at the transport layer, and the scalar-type
handling in :func:`benign_args`. Those branches are exactly the "a single
bad probe must not abort the scan" guarantees, so they get direct unit
coverage here with small in-memory fakes (no subprocess).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcp_strike.attacks._helpers import benign_args
from mcp_strike.attacks.base import Verdict
from mcp_strike.attacks.data_exfiltration import DataExfiltrationProbe
from mcp_strike.attacks.path_traversal import PathTraversalProbe
from mcp_strike.attacks.response_injection import ResponseInjectionProbe
from mcp_strike.target import ToolInfo

# --- in-memory fakes --------------------------------------------------------


@dataclass
class _Block:
    text: str


@dataclass
class _CallResult:
    content: list[_Block]
    isError: bool = False  # noqa: N815  (mimic MCP's field name)


class _FakeTarget:
    """A Target stand-in with scripted ``list_tools`` / ``call_tool``."""

    def __init__(
        self,
        tools: list[ToolInfo],
        call_behavior: Callable[[str, dict[str, Any]], _CallResult],
    ) -> None:
        self._tools = tools
        self._call_behavior = call_behavior

    async def list_tools(self) -> list[ToolInfo]:
        return self._tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> _CallResult:
        # ``call_behavior`` may return a result or raise to simulate a
        # transport-layer failure.
        return self._call_behavior(name, arguments)


def _raises(_name: str, _args: dict[str, Any]) -> _CallResult:
    raise RuntimeError("simulated transport failure")


def _string_tool(name: str = "t") -> ToolInfo:
    return ToolInfo(
        name=name,
        description="",
        input_schema={
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "required": ["q"],
        },
    )


# --- benign_args ------------------------------------------------------------


def test_benign_args_fills_each_scalar_type() -> None:
    """Every JSON-Schema scalar type maps to a placeholder value."""
    schema = {
        "properties": {
            "s": {"type": "string"},
            "i": {"type": "integer"},
            "n": {"type": "number"},
            "b": {"type": "boolean"},
        },
        "required": ["s", "i", "n", "b"],
    }
    assert benign_args(schema) == {"s": "status", "i": 1, "n": 1.0, "b": True}


def test_benign_args_returns_none_for_compound_type() -> None:
    """An object/array (or any unmodeled) required type is the skip signal."""
    schema = {"properties": {"o": {"type": "object"}}, "required": ["o"]}
    assert benign_args(schema) is None


def test_benign_args_returns_none_without_properties() -> None:
    assert benign_args({}) is None


def test_benign_args_returns_none_when_required_is_not_a_list() -> None:
    assert benign_args({"properties": {}, "required": "oops"}) is None


def test_benign_args_returns_none_when_required_prop_has_no_spec() -> None:
    """A required name whose spec isn't a dict can't be built safely."""
    assert benign_args({"properties": {"x": "not-a-dict"}, "required": ["x"]}) is None


def test_benign_args_uses_first_enum_value() -> None:
    """An enum-constrained param gets an allowed value, not the generic word."""
    schema = {
        "properties": {"mode": {"type": "string", "enum": ["read", "write"]}},
        "required": ["mode"],
    }
    assert benign_args(schema) == {"mode": "read"}


def test_benign_args_handles_union_typed_property() -> None:
    """A list-typed `type` (e.g. ["string","null"]) is built, not skipped."""
    schema = {
        "properties": {"path": {"type": ["string", "null"]}},
        "required": ["path"],
    }
    assert benign_args(schema) == {"path": "status"}


def test_benign_args_union_picks_first_buildable_type() -> None:
    """The first known scalar type in the union list wins."""
    schema = {
        "properties": {"n": {"type": ["integer", "string"]}},
        "required": ["n"],
    }
    assert benign_args(schema) == {"n": 1}


# --- path traversal ---------------------------------------------------------


def test_path_traversal_skips_tool_without_string_parameter() -> None:
    """A tool with no string parameter is out of scope, not a finding."""
    int_tool = ToolInfo(
        name="counter",
        description="",
        input_schema={"properties": {"n": {"type": "integer"}}, "required": ["n"]},
    )
    target = _FakeTarget([int_tool], _raises)
    results = asyncio.run(PathTraversalProbe().execute(target))
    assert results == []


def test_path_traversal_all_probes_erroring_is_uncertain() -> None:
    """If every traversal payload raises, we can't decide → UNCERTAIN."""
    target = _FakeTarget([_string_tool()], _raises)
    results = asyncio.run(PathTraversalProbe().execute(target))
    assert len(results) == 1
    assert results[0].verdict == Verdict.UNCERTAIN
    assert results[0].evidence["payloads_errored"]


def test_path_traversal_probes_every_string_parameter() -> None:
    """The vulnerable param may not be first, and other params get filled.

    Here only ``path`` leaks the file, and it's the *second* string param.
    The probe must reach it (not just test the first param) and must fill
    the required ``query`` param with a benign placeholder so the tool runs.
    """
    tool = ToolInfo(
        name="reader",
        description="",
        input_schema={
            "properties": {
                "query": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["query", "path"],
        },
    )

    def behavior(_name: str, args: dict[str, Any]) -> _CallResult:
        path = args.get("path", "")
        if isinstance(path, str) and "etc/passwd" in path:
            return _CallResult(
                content=[_Block(text="root:x:0:0:root:/root:/bin/bash")]
            )
        return _CallResult(content=[_Block(text="no results")])

    target = _FakeTarget([tool], behavior)
    results = asyncio.run(PathTraversalProbe().execute(target))
    assert len(results) == 1
    assert results[0].verdict == Verdict.SUCCESS
    assert results[0].evidence["parameter"] == "path"


# --- response injection -----------------------------------------------------


def test_response_injection_skips_tool_with_unbuildable_args() -> None:
    """A schema benign_args can't satisfy means the tool is skipped."""
    obj_tool = ToolInfo(
        name="needs_object",
        description="",
        input_schema={"properties": {"o": {"type": "object"}}, "required": ["o"]},
    )
    target = _FakeTarget([obj_tool], _raises)
    results = asyncio.run(ResponseInjectionProbe().execute(target))
    assert results == []


def test_response_injection_transport_error_is_uncertain() -> None:
    """A call that raises at the transport layer yields UNCERTAIN."""
    target = _FakeTarget([_string_tool()], _raises)
    results = asyncio.run(ResponseInjectionProbe().execute(target))
    assert len(results) == 1
    assert results[0].verdict == Verdict.UNCERTAIN
    assert "transport" in results[0].rationale.lower()


# --- data exfiltration ------------------------------------------------------


def test_data_exfiltration_skips_tool_with_unbuildable_args() -> None:
    obj_tool = ToolInfo(
        name="needs_object",
        description="",
        input_schema={"properties": {"o": {"type": "object"}}, "required": ["o"]},
    )
    target = _FakeTarget([obj_tool], _raises)
    results = asyncio.run(DataExfiltrationProbe().execute(target))
    assert results == []


def test_data_exfiltration_transport_error_is_uncertain() -> None:
    target = _FakeTarget([_string_tool()], _raises)
    results = asyncio.run(DataExfiltrationProbe().execute(target))
    assert len(results) == 1
    assert results[0].verdict == Verdict.UNCERTAIN
    assert "transport" in results[0].rationale.lower()
