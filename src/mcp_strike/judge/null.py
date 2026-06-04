"""No-op judge.

Returned by the pipeline whenever the judge is disabled (no API key,
``--no-judge``, or the per-run call cap was reached). Lets call sites
stay branchless: they always invoke ``.judge()`` and may receive a
``ran=False`` annotation, rather than having to handle ``Optional[Judge]``.
"""

from __future__ import annotations

from mcp_strike.attacks import AttackResult, JudgeAnnotation
from mcp_strike.judge.base import BaseJudge


class NullJudge(BaseJudge):
    """A judge that never actually calls an LLM.

    The annotation mirrors the heuristic verdict so reports show "judge
    didn't run, heuristic stands" rather than a contradictory verdict.
    """

    async def judge(self, result: AttackResult) -> JudgeAnnotation:
        return JudgeAnnotation(
            verdict=result.verdict,
            rationale="judge disabled",
            model="",
            ran=False,
        )
