"""Target adapter — normalized representation of the server under test.

Attack modules consume :class:`Target` (see docs/PLAN.md §6) so they don't
need to care about transport details.
"""

from mcp_strike.target.adapter import Target, ToolInfo, open_stdio_target

__all__ = ["Target", "ToolInfo", "open_stdio_target"]
