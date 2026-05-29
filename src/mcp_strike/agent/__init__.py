"""Adaptive red-team agent (Phase 3).

Given a tool surface, an LLM loop proposes and mutates attacks, observes
results, and iterates. The agent emits one :class:`AttackResult` per tool
with ``attack_name = "adaptive_agent"``.

See docs/PLAN.md §6 / §10.
"""

from mcp_strike.agent.adaptive import ATTACK_NAME, AdaptiveAgent

__all__ = ["ATTACK_NAME", "AdaptiveAgent"]
