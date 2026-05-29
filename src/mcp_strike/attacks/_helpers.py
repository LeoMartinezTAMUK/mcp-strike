"""Shared utilities for attack modules.

Private (underscore-prefixed) because nothing outside ``mcp_strike.attacks``
should depend on these helpers. They exist to keep individual attack
modules small and consistent — two Phase-2 attacks (response-injection,
exfiltration) plus the Phase-1 path-traversal probe all need to invoke
tools with "normal" input and inspect the response text.
"""

from __future__ import annotations

from typing import Any


def benign_args(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Build a minimal valid args dict from a tool's JSON Schema.

    Returns ``None`` when we can't safely build args — typically when the
    schema asks for object/array/enum types we don't model, or when the
    schema isn't shaped like we expect. Returning ``None`` is the signal
    for "skip this tool".

    Strategy: cover the schema's ``required`` properties with placeholder
    values keyed by JSON-Schema ``type``. Strings get a benign-looking
    word, numerics get small constants, booleans get True.

    We deliberately don't try to make the args "realistic" — most attacks
    here only care whether the tool responds at all and what's in that
    response. A clever placeholder won't increase recall meaningfully.
    """
    props = schema.get("properties")
    if not isinstance(props, dict):
        return None

    required = schema.get("required", [])
    if not isinstance(required, list):
        return None

    args: dict[str, Any] = {}
    for name in required:
        spec = props.get(name)
        if not isinstance(spec, dict):
            return None
        type_ = spec.get("type")
        if type_ == "string":
            args[name] = "status"
        elif type_ == "integer":
            args[name] = 1
        elif type_ == "number":
            args[name] = 1.0
        elif type_ == "boolean":
            args[name] = True
        else:
            # Unknown / compound type — can't safely build a value.
            return None
    return args


def response_text(call_result: Any) -> str:
    """Concatenate text-typed content blocks from a CallToolResult.

    Duck-typed: looks for a ``.text`` attribute on each block in the
    result's ``content`` list. Non-text content (images, embedded
    resources) is ignored. Used by Stage-2/3 active attacks that need to
    inspect tool output text.
    """
    parts: list[str] = []
    for block in getattr(call_result, "content", []) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def is_error_result(call_result: Any) -> bool:
    """Return True when a CallToolResult signals an in-band error.

    MCP servers don't propagate tool exceptions as transport errors — when
    a tool's Python body raises, FastMCP (and most servers) catch the
    exception and return a normal CallToolResult with ``isError=True``
    plus the error message as text content. So an attack can't rely on
    ``try/except`` around ``target.call_tool(...)`` to detect tool failure;
    it has to look at this flag explicitly.
    """
    return bool(getattr(call_result, "isError", False))
