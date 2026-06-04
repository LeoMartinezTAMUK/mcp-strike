"""Pipeline helpers for running the judge over scan results.

The scan pipeline runs attacks first (cheap, deterministic) and then runs
the judge over candidates that benefit from a second opinion. This module
owns that policy: which results are judged, in what order, and how the
per-run LLM-call cap is enforced.

Layered scoring rationale:
- ``FAILURE`` rows are cheap negatives; judging them wastes calls.
- ``UNCERTAIN`` rows are the prime targets; heuristic couldn't decide.
- ``SUCCESS`` rows get a confirmation pass; catches heuristic false positives.
"""

from __future__ import annotations

from mcp_strike.attacks import AttackResult, JudgeAnnotation, Verdict
from mcp_strike.judge.base import BaseJudge


async def annotate_with_judge(
    results: list[AttackResult],
    judge: BaseJudge,
    *,
    max_calls: int = 20,
) -> int:
    """Run the judge over eligible candidates in ``results`` (in place).

    Mutates each eligible result's :attr:`AttackResult.judge` field. Results
    of verdict ``FAILURE`` are skipped (their ``judge`` stays ``None``).

    Enforces ``max_calls``: once that many *real* LLM calls have been made
    (a real call = the returned annotation has ``ran=True``), subsequent
    eligible results get a "cap reached" annotation without an actual API
    call. This bounds spend per scan regardless of how many SUCCESS/UNCERTAIN
    rows there are.

    Args:
        results: AttackResults from a scan run. Mutated in place.
        judge: Judge implementation. Pass :class:`NullJudge` to attach
            "judge disabled" annotations without spending money.
        max_calls: Hard cap on real LLM calls for this run.

    Returns:
        The number of real LLM calls actually made; useful for reports
        ("ran 7 of 20 LLM calls").
    """
    calls_made = 0

    for result in results:
        # Skip FAILURE rows (already-cheap negatives). Their ``judge`` stays None.
        if result.verdict == Verdict.FAILURE:
            continue

        if calls_made >= max_calls:
            # Cap reached; record it so the report can explain why this row
            # didn't get a second opinion.
            result.judge = _capped_annotation(result)
            continue

        annotation = await judge.judge(result)
        result.judge = annotation
        # Only count real LLM calls. NullJudge / error-fallbacks set ran=False
        # and shouldn't burn budget.
        if annotation.ran:
            calls_made += 1

    return calls_made


def _capped_annotation(result: AttackResult) -> JudgeAnnotation:
    """Build the annotation attached when the LLM-call cap is reached."""
    return JudgeAnnotation(
        verdict=result.verdict,
        rationale="judge call cap reached for this run",
        model="",
        ran=False,
    )
