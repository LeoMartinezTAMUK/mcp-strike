"""JSON report renderer.

Produces a machine-readable representation of scan results for CI/CD use.
The schema is intended to be stable — additions are non-breaking but
renames or removals require a major version bump (when there's a version
to bump).

Schema overview::

    {
      "summary": {
        "total":            int,
        "success":          int,
        "uncertain":        int,
        "failure":          int,
        "llm_calls_used":   int | null,   # null when no judge ran
        "llm_calls_cap":    int | null,   # null when no judge ran
        "agent_calls_used": int | null,   # null when no agent ran (Phase 3)
        "agent_calls_cap":  int | null    # null when no agent ran (Phase 3)
      },
      "results": [
        {
          "attack_name":    str,
          "stage":          "metadata" | "parameters" | "response",
          "target_tool":    str,
          "verdict":        "success" | "failure" | "uncertain",
          "rationale":      str,
          "evidence":       dict,                       # opaque, attack-specific
          "judge":          {                           # null when no annotation
            "verdict":      "success" | "failure" | "uncertain",
            "rationale":    str,
            "model":        str,
            "ran":          bool
          } | null
        },
        ...
      ]
    }
"""

from __future__ import annotations

import json
from typing import Any

from mcp_strike.attacks import AttackResult, JudgeAnnotation, Verdict


def render_json(
    results: list[AttackResult],
    *,
    llm_calls_used: int | None = None,
    llm_calls_cap: int | None = None,
    agent_calls_used: int | None = None,
    agent_calls_cap: int | None = None,
) -> dict[str, Any]:
    """Render scan results as a JSON-serializable dict.

    Args:
        results: The full list of AttackResults produced by the scan.
        llm_calls_used: How many real LLM calls were made by the judge pass.
            ``None`` means the judge didn't run; ``0`` means it ran but
            made no calls.
        llm_calls_cap: The configured per-run judge call cap. ``None``
            when no judge ran.
        agent_calls_used: How many real LLM calls were made by the
            adaptive agent. Same null-vs-zero semantics as above.
        agent_calls_cap: The configured per-run agent call cap. ``None``
            when no agent ran.

    Returns:
        A dict suitable for ``json.dumps``.
    """
    n_total = len(results)
    n_success = sum(1 for r in results if r.verdict == Verdict.SUCCESS)
    n_uncertain = sum(1 for r in results if r.verdict == Verdict.UNCERTAIN)
    n_failure = n_total - n_success - n_uncertain

    return {
        "summary": {
            "total": n_total,
            "success": n_success,
            "uncertain": n_uncertain,
            "failure": n_failure,
            "llm_calls_used": llm_calls_used,
            "llm_calls_cap": llm_calls_cap,
            "agent_calls_used": agent_calls_used,
            "agent_calls_cap": agent_calls_cap,
        },
        "results": [_result_to_dict(r) for r in results],
    }


def render_json_string(
    results: list[AttackResult],
    *,
    llm_calls_used: int | None = None,
    llm_calls_cap: int | None = None,
    agent_calls_used: int | None = None,
    agent_calls_cap: int | None = None,
    indent: int | None = 2,
) -> str:
    """Convenience: render as a pretty-printed JSON string.

    ``default=str`` is a belt-and-suspenders escape for any non-JSON-native
    values an attack might tuck into ``evidence`` (e.g. enums).
    """
    return json.dumps(
        render_json(
            results,
            llm_calls_used=llm_calls_used,
            llm_calls_cap=llm_calls_cap,
            agent_calls_used=agent_calls_used,
            agent_calls_cap=agent_calls_cap,
        ),
        indent=indent,
        default=str,
    )


def _result_to_dict(result: AttackResult) -> dict[str, Any]:
    """Convert one AttackResult to a JSON-serializable dict."""
    return {
        "attack_name": result.attack_name,
        "stage": result.stage.value,
        "target_tool": result.target_tool,
        "verdict": result.verdict.value,
        "rationale": result.rationale,
        "evidence": result.evidence,
        "judge": _judge_to_dict(result.judge) if result.judge is not None else None,
    }


def _judge_to_dict(judge: JudgeAnnotation) -> dict[str, Any]:
    return {
        "verdict": judge.verdict.value,
        "rationale": judge.rationale,
        "model": judge.model,
        "ran": judge.ran,
    }
