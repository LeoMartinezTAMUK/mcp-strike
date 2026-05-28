"""Report renderers (see docs/PLAN.md §6).

Phase 1 ships a terminal renderer. JSON arrives in Phase 2; HTML is a stretch.
"""

from mcp_strike.report.terminal import render_terminal

__all__ = ["render_terminal"]
