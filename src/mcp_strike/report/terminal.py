"""Terminal report renderer.

Renders a list of :class:`mcp_strike.attacks.AttackResult` to a Rich
Console. Default: only ``SUCCESS`` and ``UNCERTAIN`` rows are shown — the
noisy ``FAILURE`` rows can be re-enabled with ``show_all=True`` for
debugging or coverage inspection.

Future sibling functions in this package will render the same data as JSON
(Phase 2) and HTML (stretch).
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcp_strike.attacks import AttackResult, Verdict

# Verdict → (rich-markup colour, label, sort_priority).
# Sort priority puts SUCCESS at the top, UNCERTAIN below, FAILURE last —
# matches "alarming stuff first" reading order.
_VERDICT_STYLE: dict[Verdict, tuple[str, str, int]] = {
    Verdict.SUCCESS: ("red", "SUCCESS", 0),
    Verdict.UNCERTAIN: ("yellow", "UNCERTAIN", 1),
    Verdict.FAILURE: ("dim", "FAILURE", 2),
}


def render_terminal(
    results: list[AttackResult],
    *,
    show_all: bool = False,
    console: Console | None = None,
) -> None:
    """Render attack results to a Rich console.

    Args:
        results: The full list of AttackResults from a scan run.
        show_all: If False (default), FAILURE rows are suppressed.
            The summary line always reflects the full counts regardless.
        console: Optional Console to render into. Pass a Console wrapping a
            StringIO for testing. Default: a fresh Console writing to stdout.
    """
    if console is None:
        console = Console()

    # Summary line — always derived from the FULL result set so the user
    # sees how many checks ran even when ``show_all`` is False.
    n_total = len(results)
    n_success = sum(1 for r in results if r.verdict == Verdict.SUCCESS)
    n_uncertain = sum(1 for r in results if r.verdict == Verdict.UNCERTAIN)
    n_failure = n_total - n_success - n_uncertain

    console.print(
        f"[bold]Scan summary[/bold]: {n_total} check(s) ran — "
        f"[red]{n_success} SUCCESS[/red], "
        f"[yellow]{n_uncertain} UNCERTAIN[/yellow], "
        f"[dim]{n_failure} FAILURE[/dim]"
    )

    visible = (
        results if show_all
        else [r for r in results if r.verdict != Verdict.FAILURE]
    )
    if not visible:
        console.print(
            "[green]No findings.[/green] "
            "Pass --show-all to see clean checks too."
        )
        return

    # Sort by (verdict severity, stage, attack, tool). Stable across runs so
    # diffs against previous scans are readable.
    visible_sorted = sorted(
        visible,
        key=lambda r: (
            _VERDICT_STYLE[r.verdict][2],
            r.stage.value,
            r.attack_name,
            r.target_tool,
        ),
    )

    table = Table(header_style="bold")
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Stage", no_wrap=True)
    table.add_column("Attack", no_wrap=True)
    table.add_column("Tool", no_wrap=True)
    table.add_column("Rationale")

    for r in visible_sorted:
        colour, label, _ = _VERDICT_STYLE[r.verdict]
        # User-derived fields (especially `rationale`, which can contain
        # arbitrary tool output like 'root:x:0:0:') are wrapped in `Text`
        # so Rich treats them as literal characters rather than re-parsing
        # markup or emoji shortcodes. The verdict cell keeps markup because
        # we control its content.
        table.add_row(
            f"[{colour}]{label}[/{colour}]",
            Text(r.stage.value),
            Text(r.attack_name),
            Text(r.target_tool),
            Text(r.rationale),
        )

    console.print(table)
