"""Stage-2 attack: path-traversal probe.

Active attack. For each tool that takes a string parameter (its *first*
string parameter, to keep Phase 1 simple), invoke the tool with traversal
payloads pointing at well-known host files and inspect the response text
for filesystem signatures.

Tradeoffs:
- High precision: signatures are specific enough (``"root:x:0:0:"``) that a
  match strongly implies the file was actually read. False positives are
  unlikely.
- Lower recall: this only catches tools whose first string parameter is
  interpreted as a path. A future version will probe each string parameter
  independently and learn richer payloads from the schema.
"""

from __future__ import annotations

from typing import Any

from mcp_strike.attacks.base import (
    AttackResult,
    BaseAttack,
    Stage,
    Verdict,
)
from mcp_strike.attacks.registry import register_attack
from mcp_strike.target import Target, ToolInfo

# Each probe is (payload, signature_to_look_for_in_response).
# The signature must be specific enough that its presence implies the file
# was actually read (and not just echoed from the request).
_TRAVERSAL_PROBES: tuple[tuple[str, str], ...] = (
    ("../../../../../../etc/passwd", "root:x:0:0:"),
    ("/etc/passwd", "root:x:0:0:"),
)


def _first_string_parameter(schema: dict[str, Any]) -> str | None:
    """Return the name of the first string-typed parameter in ``schema``.

    Looks at JSON Schema ``properties`` and returns the first entry whose
    ``type`` is ``"string"``. Returns ``None`` if the schema has no string
    parameter (or no parsable structure at all).
    """
    props = schema.get("properties")
    if not isinstance(props, dict):
        return None
    for name, spec in props.items():
        if isinstance(spec, dict) and spec.get("type") == "string":
            return name
    return None


def _response_text(call_result: Any) -> str:
    """Concatenate any text content blocks in a CallToolResult.

    Duck-typed deliberately: we don't want to import MCP's specific content
    classes here, so we just look for a ``.text`` attribute on each block.
    Non-text content (images, embedded resources) is ignored.
    """
    parts: list[str] = []
    for block in getattr(call_result, "content", []) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


@register_attack
class PathTraversalProbe(BaseAttack):
    """Probe string-parameter tools with traversal payloads."""

    name = "path_traversal_probe"
    stage = Stage.PARAMETERS

    async def execute(self, target: Target) -> list[AttackResult]:
        results: list[AttackResult] = []
        for tool in await target.list_tools():
            result = await self._probe_one(tool, target)
            # Tools with no string parameter are silently skipped — they're
            # outside this attack's scope, not "uncertain" findings.
            if result is not None:
                results.append(result)
        return results

    async def _probe_one(
        self, tool: ToolInfo, target: Target
    ) -> AttackResult | None:
        """Probe a single tool. Returns None if it has no string parameter."""
        param_name = _first_string_parameter(tool.input_schema)
        if param_name is None:
            return None

        attempted: list[str] = []
        errored: list[str] = []

        for payload, signature in _TRAVERSAL_PROBES:
            attempted.append(payload)
            try:
                call_result = await target.call_tool(
                    tool.name, {param_name: payload}
                )
            except Exception:
                # The tool may reject the input, time out, etc. Don't let
                # one bad probe abort the whole scan; keep trying.
                errored.append(payload)
                continue

            text = _response_text(call_result)
            if signature in text:
                return AttackResult(
                    attack_name=self.name,
                    stage=self.stage,
                    target_tool=tool.name,
                    verdict=Verdict.SUCCESS,
                    rationale=(
                        f"Tool returned filesystem content when called with "
                        f"traversal payload {payload!r} on parameter "
                        f"{param_name!r}. Signature {signature!r} found in "
                        f"response."
                    ),
                    evidence={
                        "parameter": param_name,
                        "payload": payload,
                        "signature": signature,
                    },
                )

        # No signature-bearing response. If *every* probe raised, we don't
        # actually know whether the tool is vulnerable — escalate to
        # UNCERTAIN so a human can take a look.
        if errored and len(errored) == len(attempted):
            return AttackResult(
                attack_name=self.name,
                stage=self.stage,
                target_tool=tool.name,
                verdict=Verdict.UNCERTAIN,
                rationale=(
                    f"All {len(attempted)} traversal payload(s) on parameter "
                    f"{param_name!r} raised an error. Tool may reject all "
                    f"inputs by design, or may have a stricter validator."
                ),
                evidence={"parameter": param_name, "payloads_errored": errored},
            )

        return AttackResult(
            attack_name=self.name,
            stage=self.stage,
            target_tool=tool.name,
            verdict=Verdict.FAILURE,
            rationale=(
                f"No traversal signature observed across {len(attempted)} "
                f"payload(s) on parameter {param_name!r}."
            ),
            evidence={
                "parameter": param_name,
                "payloads_tried": attempted,
            },
        )
