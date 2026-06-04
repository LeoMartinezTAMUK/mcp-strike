"""Tests for the JSON report renderer."""

from __future__ import annotations

import json

from mcp_strike.attacks import AttackResult, JudgeAnnotation, Stage, Verdict
from mcp_strike.report.json_report import render_json, render_json_string


def _result(**kwargs: object) -> AttackResult:
    """Build a default AttackResult; kwargs override individual fields."""
    defaults: dict[str, object] = dict(
        attack_name="test_attack",
        stage=Stage.METADATA,
        target_tool="test_tool",
        verdict=Verdict.SUCCESS,
        rationale="rationale",
    )
    defaults.update(kwargs)
    return AttackResult(**defaults)  # type: ignore[arg-type]


def test_summary_counts_match_verdicts() -> None:
    """The summary block reflects the actual verdict distribution."""
    results = [
        _result(verdict=Verdict.SUCCESS),
        _result(verdict=Verdict.SUCCESS),
        _result(verdict=Verdict.UNCERTAIN),
        _result(verdict=Verdict.FAILURE),
    ]
    doc = render_json(results)
    summary = doc["summary"]
    assert summary["total"] == 4
    assert summary["success"] == 2
    assert summary["uncertain"] == 1
    assert summary["failure"] == 1


def test_result_row_has_documented_shape() -> None:
    """Each result row has the documented keys with the right value types."""
    results = [_result(evidence={"k": "v"})]
    doc = render_json(results)
    row = doc["results"][0]

    assert set(row.keys()) >= {
        "attack_name",
        "stage",
        "target_tool",
        "verdict",
        "rationale",
        "evidence",
        "judge",
    }
    # Stage/verdict are emitted as the str-Enum's *value*, not the repr;
    # CI consumers shouldn't have to know about Python enums.
    assert row["stage"] == "metadata"
    assert row["verdict"] == "success"
    assert row["evidence"] == {"k": "v"}
    assert row["judge"] is None


def test_judge_annotation_round_trips() -> None:
    """When a result carries a JudgeAnnotation, it shows up in JSON."""
    result = _result()
    result.judge = JudgeAnnotation(
        verdict=Verdict.SUCCESS,
        rationale="LLM agreed",
        model="gpt-4o-mini",
        ran=True,
    )
    doc = render_json([result])
    judge = doc["results"][0]["judge"]
    assert judge is not None
    assert judge["verdict"] == "success"
    assert judge["rationale"] == "LLM agreed"
    assert judge["model"] == "gpt-4o-mini"
    assert judge["ran"] is True


def test_llm_call_metadata_passes_through() -> None:
    """llm_calls_used and _cap appear in the summary when provided."""
    doc = render_json([], llm_calls_used=7, llm_calls_cap=20)
    assert doc["summary"]["llm_calls_used"] == 7
    assert doc["summary"]["llm_calls_cap"] == 20


def test_llm_call_metadata_defaults_to_none() -> None:
    """Calls with no judge metadata yield null; distinguishable from 0."""
    doc = render_json([])
    assert doc["summary"]["llm_calls_used"] is None
    assert doc["summary"]["llm_calls_cap"] is None


def test_agent_call_metadata_passes_through() -> None:
    """agent_calls_used and _cap appear in the summary when provided."""
    doc = render_json([], agent_calls_used=12, agent_calls_cap=50)
    assert doc["summary"]["agent_calls_used"] == 12
    assert doc["summary"]["agent_calls_cap"] == 50


def test_agent_call_metadata_defaults_to_none() -> None:
    """Calls with no agent metadata yield null; distinguishable from 0."""
    doc = render_json([])
    assert doc["summary"]["agent_calls_used"] is None
    assert doc["summary"]["agent_calls_cap"] is None


def test_render_json_string_is_parseable() -> None:
    """``render_json_string`` output round-trips through ``json.loads``."""
    results = [_result()]
    text = render_json_string(results)
    parsed = json.loads(text)
    assert parsed["summary"]["total"] == 1
    assert parsed["results"][0]["verdict"] == "success"


def test_render_json_string_indents() -> None:
    """Default indent is 2 (pretty-printed); confirm by looking for whitespace."""
    text = render_json_string([_result()])
    assert "\n  " in text  # at least one indented line
