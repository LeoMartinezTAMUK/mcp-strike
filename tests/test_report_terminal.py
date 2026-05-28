"""Tests for the terminal report renderer.

We render into a Console that writes to an in-memory StringIO so the test
can inspect the output without touching the actual terminal.
"""

from __future__ import annotations

import io

from rich.console import Console

from mcp_strike.attacks import AttackResult, Stage, Verdict
from mcp_strike.report.terminal import render_terminal


def _make_console() -> tuple[Console, io.StringIO]:
    """Build a Console that writes to a StringIO buffer.

    ``record=True`` and ``force_terminal=False`` make rich output
    deterministic and ANSI-free, which keeps assertions simple.
    """
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=200)
    return console, buf


def _result(
    *,
    attack: str = "demo_attack",
    tool: str = "demo_tool",
    verdict: Verdict = Verdict.SUCCESS,
    rationale: str = "demo rationale",
) -> AttackResult:
    return AttackResult(
        attack_name=attack,
        stage=Stage.METADATA,
        target_tool=tool,
        verdict=verdict,
        rationale=rationale,
    )


def test_renders_summary_with_mixed_verdicts() -> None:
    console, buf = _make_console()
    render_terminal(
        [
            _result(verdict=Verdict.SUCCESS, rationale="bad finding"),
            _result(verdict=Verdict.UNCERTAIN, rationale="needs review"),
            _result(verdict=Verdict.FAILURE, rationale="all clear"),
        ],
        console=console,
    )
    output = buf.getvalue()

    # Summary counts present.
    assert "3 check(s) ran" in output
    assert "1 SUCCESS" in output
    assert "1 UNCERTAIN" in output
    assert "1 FAILURE" in output

    # FAILURE rationale should be HIDDEN by default.
    assert "bad finding" in output
    assert "needs review" in output
    assert "all clear" not in output


def test_show_all_includes_failure_rows() -> None:
    console, buf = _make_console()
    render_terminal(
        [_result(verdict=Verdict.FAILURE, rationale="all clear")],
        show_all=True,
        console=console,
    )
    output = buf.getvalue()
    assert "all clear" in output


def test_no_findings_when_only_failures_hidden() -> None:
    """With only FAILURE results and show_all=False, the 'No findings' banner shows."""
    console, buf = _make_console()
    render_terminal(
        [_result(verdict=Verdict.FAILURE)],
        console=console,
    )
    output = buf.getvalue()
    assert "No findings" in output


def test_empty_results() -> None:
    """Zero results shouldn't crash; summary line + No findings banner expected."""
    console, buf = _make_console()
    render_terminal([], console=console)
    output = buf.getvalue()
    assert "0 check(s) ran" in output
    assert "No findings" in output
