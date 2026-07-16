"""Shared utilities for attack modules.

Private (underscore-prefixed) because nothing outside ``mcp_strike.attacks``
should depend on these helpers. They exist to keep individual attack
modules small and consistent: the response-injection, exfiltration, and
path-traversal probes all need to invoke tools with "normal" input and
inspect the response text.
"""

from __future__ import annotations

from typing import Any

# --- Truncation lengths for evidence-dict fields ----------------------------
# Attacks store excerpts of response text in :attr:`AttackResult.evidence`
# for reports and the JSON output. Cap them so reports stay readable and
# JSON payloads don't balloon.

#: Used when the attack found a vuln; give enough context to verify.
EVIDENCE_EXCERPT_CHARS = 500
#: Used when the attack found nothing; still include some context, but
#: tighter since the row is mostly noise.
EVIDENCE_SHORT_EXCERPT_CHARS = 200

# Canonical prompt-injection markers. The patterns are pipeline-stage-
# agnostic: an injection planted in a tool description and one planted
# in a tool response look the same. Shared by
# :mod:`mcp_strike.attacks.description_injection` and
# :mod:`mcp_strike.attacks.response_injection` to avoid drift.
#
# Curated rather than exhaustive: a small list of high-confidence markers
# keeps the false-positive rate low. We deliberately exclude generic
# phrases like "you must"; they fire on legitimate descriptions ("you
# must provide a city name") without buying meaningful recall.
INJECTION_MARKERS: tuple[str, ...] = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore the above",
    "disregard previous",
    "you are now",
    "as an ai",
    "system:",
    "<|im_start|>",
    "</system>",
    "do not mention",
    "do not tell the user",
)


# Sentinel meaning "couldn't build a placeholder for this property". Distinct
# from ``None`` because ``None`` (JSON null) can be a legitimate value.
_UNBUILDABLE = object()


def _placeholder_for_spec(spec: dict[str, Any]) -> Any:
    """Return a benign placeholder for one property spec, or ``_UNBUILDABLE``.

    - An ``enum`` constrains the value to a fixed set, so any placeholder
      outside it would be rejected; use the first allowed value.
    - JSON Schema allows ``type`` to be a list (e.g. ``["string", "null"]``);
      try each in order and use the first scalar we know how to build.
    """
    enum = spec.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]

    type_ = spec.get("type")
    types = type_ if isinstance(type_, list) else [type_]
    for t in types:
        if t == "string":
            return "status"
        if t == "integer":
            return 1
        if t == "number":
            return 1.0
        if t == "boolean":
            return True
    # Unknown or compound type (object/array/etc.); can't safely build a value.
    return _UNBUILDABLE


def benign_args(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Build a minimal valid args dict from a tool's JSON Schema.

    Returns ``None`` when we can't safely build args (typically when a
    required property is a compound type we don't model, or when the schema
    isn't shaped like we expect). Returning ``None`` is the signal for
    "skip this tool".

    Strategy: cover the schema's ``required`` properties with placeholder
    values (see :func:`_placeholder_for_spec`): the first ``enum`` value
    when constrained, otherwise a type-keyed constant.

    We deliberately don't try to make the args "realistic"; most attacks here
    only care whether the tool responds at all and what's in that response.
    A clever placeholder won't increase recall meaningfully.
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
        value = _placeholder_for_spec(spec)
        if value is _UNBUILDABLE:
            return None
        args[name] = value
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

    MCP servers don't propagate tool exceptions as transport errors: when
    a tool's Python body raises, FastMCP (and most servers) catch the
    exception and return a normal CallToolResult with ``isError=True``
    plus the error message as text content. So an attack can't rely on
    ``try/except`` around ``target.call_tool(...)`` to detect tool failure;
    it has to look at this flag explicitly.
    """
    return bool(getattr(call_result, "isError", False))
