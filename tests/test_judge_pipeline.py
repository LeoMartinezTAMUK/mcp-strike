"""Tests for the judge pipeline helper.

We use a counting fake-judge so each test can assert exactly how many real
LLM calls were made under different policies and caps.
"""

from __future__ import annotations

import asyncio

from mcp_strike.attacks import AttackResult, JudgeAnnotation, Stage, Verdict
from mcp_strike.judge import NullJudge, annotate_with_judge
from mcp_strike.judge.base import BaseJudge


class _CountingJudge(BaseJudge):
    """Judge that records every call and returns a canned annotation.

    Configurable: pick the verdict the fake judge always returns, and
    whether ``ran`` is True (consumes budget) or False (doesn't).
    """

    def __init__(self, *, verdict: Verdict = Verdict.SUCCESS, ran: bool = True) -> None:
        self._verdict = verdict
        self._ran = ran
        self.calls = 0

    async def judge(self, result: AttackResult) -> JudgeAnnotation:
        self.calls += 1
        return JudgeAnnotation(
            verdict=self._verdict,
            rationale=f"call #{self.calls}",
            model="test-model",
            ran=self._ran,
        )


def _result(name: str, verdict: Verdict) -> AttackResult:
    return AttackResult(
        attack_name="a",
        stage=Stage.METADATA,
        target_tool=name,
        verdict=verdict,
        rationale="r",
    )


def test_failure_rows_are_skipped() -> None:
    """The pipeline should not waste LLM calls on FAILURE rows."""
    results = [
        _result("t1", Verdict.FAILURE),
        _result("t2", Verdict.FAILURE),
    ]
    judge = _CountingJudge()
    calls = asyncio.run(annotate_with_judge(results, judge, max_calls=10))

    assert calls == 0
    assert judge.calls == 0
    # FAILURE rows keep judge=None; nothing was attached.
    assert all(r.judge is None for r in results)


def test_uncertain_and_success_rows_are_judged() -> None:
    """Both UNCERTAIN and SUCCESS should be eligible for the judge."""
    results = [
        _result("t1", Verdict.UNCERTAIN),
        _result("t2", Verdict.SUCCESS),
        _result("t3", Verdict.FAILURE),  # skipped
    ]
    judge = _CountingJudge()
    calls = asyncio.run(annotate_with_judge(results, judge, max_calls=10))

    assert calls == 2
    assert judge.calls == 2
    assert results[0].judge is not None and results[0].judge.ran is True
    assert results[1].judge is not None and results[1].judge.ran is True
    assert results[2].judge is None


def test_cap_is_enforced() -> None:
    """Once max_calls is reached, remaining eligible rows get the capped annotation."""
    results = [_result(f"t{i}", Verdict.UNCERTAIN) for i in range(5)]
    judge = _CountingJudge()
    calls = asyncio.run(annotate_with_judge(results, judge, max_calls=2))

    assert calls == 2
    assert judge.calls == 2
    # First two were actually judged.
    assert results[0].judge is not None and results[0].judge.ran is True
    assert results[1].judge is not None and results[1].judge.ran is True
    # Remaining three got the cap-reached annotation, not a real call.
    for r in results[2:]:
        assert r.judge is not None
        assert r.judge.ran is False
        assert "cap" in r.judge.rationale.lower()


def test_ran_false_does_not_consume_budget() -> None:
    """A judge returning ran=False (e.g. NullJudge) shouldn't burn the cap."""
    results = [_result(f"t{i}", Verdict.UNCERTAIN) for i in range(3)]
    judge = _CountingJudge(ran=False)
    calls = asyncio.run(annotate_with_judge(results, judge, max_calls=1))

    # judge.calls==3 because the judge was *called* for all three;
    # but `calls` (real-LLM-call count) stays at 0 because each returned ran=False.
    assert judge.calls == 3
    assert calls == 0
    # All three got annotations.
    assert all(r.judge is not None for r in results)


def test_null_judge_attaches_disabled_annotations() -> None:
    """End-to-end smoke: NullJudge + pipeline = every eligible row gets ran=False."""
    results = [
        _result("t1", Verdict.SUCCESS),
        _result("t2", Verdict.UNCERTAIN),
        _result("t3", Verdict.FAILURE),
    ]
    calls = asyncio.run(annotate_with_judge(results, NullJudge(), max_calls=10))
    assert calls == 0
    assert results[0].judge is not None and results[0].judge.ran is False
    assert results[1].judge is not None and results[1].judge.ran is False
    assert results[2].judge is None  # FAILURE skipped
