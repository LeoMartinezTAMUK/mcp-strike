"""Tests for the judge foundation (BaseJudge contract + NullJudge)."""

from __future__ import annotations

import asyncio

from mcp_strike.attacks import AttackResult, JudgeAnnotation, Stage, Verdict
from mcp_strike.judge import NullJudge


def _result(verdict: Verdict = Verdict.UNCERTAIN) -> AttackResult:
    return AttackResult(
        attack_name="x",
        stage=Stage.METADATA,
        target_tool="t",
        verdict=verdict,
        rationale="r",
    )


def test_attack_result_has_no_judge_annotation_by_default() -> None:
    """Newly-constructed AttackResults should have judge=None."""
    assert _result().judge is None


def test_null_judge_returns_not_ran() -> None:
    """NullJudge must report ran=False and an empty model."""
    judge = NullJudge()
    annotation = asyncio.run(judge.judge(_result()))
    assert isinstance(annotation, JudgeAnnotation)
    assert annotation.ran is False
    assert annotation.model == ""


def test_null_judge_preserves_heuristic_verdict() -> None:
    """The no-op annotation mirrors the heuristic verdict.

    The pipeline will use the heuristic verdict as the final answer when
    the judge didn't actually run; mirroring keeps reports unambiguous.
    """
    for verdict in (Verdict.SUCCESS, Verdict.UNCERTAIN, Verdict.FAILURE):
        judge = NullJudge()
        annotation = asyncio.run(judge.judge(_result(verdict=verdict)))
        assert annotation.verdict == verdict, f"mismatch for {verdict}"


def test_judge_annotation_can_be_attached_to_attack_result() -> None:
    """Sanity check: a JudgeAnnotation can populate AttackResult.judge."""
    annotation = JudgeAnnotation(
        verdict=Verdict.SUCCESS,
        rationale="LLM agreed",
        model="gpt-4o-mini",
        ran=True,
    )
    result = _result()
    result.judge = annotation
    assert result.judge is annotation
    assert result.judge.ran is True
