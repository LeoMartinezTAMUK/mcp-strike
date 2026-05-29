"""Report renderers (see docs/PLAN.md §6).

Phase 1 shipped the terminal renderer; Phase 2 adds JSON for CI use.
HTML remains a stretch goal.
"""

from mcp_strike.report.json_report import render_json, render_json_string
from mcp_strike.report.terminal import render_terminal

__all__ = ["render_json", "render_json_string", "render_terminal"]
