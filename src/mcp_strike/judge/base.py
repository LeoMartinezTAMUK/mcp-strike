"""Abstract LLM-as-judge interface.

Implementations score an :class:`mcp_strike.attacks.AttackResult` and return
their own opinion as a :class:`JudgeAnnotation`. The scan pipeline calls
:meth:`BaseJudge.judge` on candidates worth a second look (typically
``UNCERTAIN`` rows) and attaches the annotation to the result so reports
can show both heuristic and judge verdicts side by side.
"""

from __future__ import annotations

import abc

from mcp_strike.attacks import AttackResult, JudgeAnnotation


class BaseJudge(abc.ABC):
    """Abstract interface for an LLM judge.

    Subclasses implement :meth:`judge` to return a :class:`JudgeAnnotation`
    for any given :class:`AttackResult`. The scan pipeline owns the
    decision of *when* to call the judge; implementations should just
    answer when asked.
    """

    @abc.abstractmethod
    async def judge(self, result: AttackResult) -> JudgeAnnotation:
        """Return the judge's opinion on this attack result.

        Implementations must not raise on API errors; wrap any failure in
        a ``ran=False`` annotation with a rationale so callers can keep
        the scan going. The scan pipeline shouldn't have to know about
        provider-specific failure modes.
        """
