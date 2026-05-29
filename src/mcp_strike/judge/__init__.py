"""Scoring / LLM-as-judge (see docs/PLAN.md §6).

Cost discipline rules (from CLAUDE.md):
- Prefer deterministic heuristics first; only run the judge on candidates
  worth a second look (typically UNCERTAIN rows).
- Default to a cheap model.
- Respect the per-run LLM-call cap from configuration.

This package's :class:`BaseJudge` is the abstract interface;
:class:`NullJudge` is the no-op used when the judge is disabled.
:class:`mcp_strike.judge.openai.OpenAIJudge` (Phase 2 S2) is the concrete
production implementation.
"""

from mcp_strike.judge.base import BaseJudge
from mcp_strike.judge.null import NullJudge
from mcp_strike.judge.openai_judge import OpenAIJudge
from mcp_strike.judge.pipeline import annotate_with_judge

__all__ = ["BaseJudge", "NullJudge", "OpenAIJudge", "annotate_with_judge"]
