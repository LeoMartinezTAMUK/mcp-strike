"""Command-line interface for MCP-Strike.

Entry point: the ``mcp-strike`` console script (defined in pyproject.toml's
``[project.scripts]``) calls :data:`app`. Three subcommands are exposed:

- ``scan``         — connect to a target and run all attacks against it.
- ``list-attacks`` — show every registered attack (name, stage, class).
- ``demo``         — convenience: run a scan against the bundled
                     deliberately-vulnerable demo server.

The responsible-use notice prints at startup of ``scan`` and ``demo`` unless
explicitly suppressed with ``--no-notice``.
"""

from __future__ import annotations

import asyncio
import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_strike.attacks import AttackResult, BaseAttack, get_all_attacks
from mcp_strike.config import RunConfig, TargetConfig
from mcp_strike.report.terminal import render_terminal
from mcp_strike.target import open_stdio_target

app = typer.Typer(
    add_completion=False,
    help="Active, runtime adversarial testing for MCP servers you own.",
    no_args_is_help=True,
)

# Kept as module-level text so it's easy to copy-paste into docs and
# trivial to update without editing function bodies.
_NOTICE_TEXT = (
    "MCP-Strike is a defensive tool for testing MCP servers you own.\n"
    "Running it against systems you don't control may be illegal in your\n"
    "jurisdiction. See README + docs/PLAN.md §14 for the full note."
)


def _print_notice(console: Console) -> None:
    """Render the responsible-use notice in a yellow panel."""
    console.print(
        Panel(
            _NOTICE_TEXT,
            title="[yellow]Responsible use[/yellow]",
            border_style="yellow",
        )
    )


def _select_attacks(filter_names: list[str] | None) -> list[type[BaseAttack]]:
    """Resolve the attack-name filter into actual attack classes.

    ``None`` or an empty list means "every registered attack". An unknown
    name raises :class:`typer.BadParameter` so the CLI exits cleanly with
    code 2 and a formatted error.
    """
    all_attacks = get_all_attacks()
    if not filter_names:
        return all_attacks

    by_name = {cls.name: cls for cls in all_attacks}
    selected: list[type[BaseAttack]] = []
    for name in filter_names:
        if name not in by_name:
            raise typer.BadParameter(
                f"Unknown attack {name!r}. Run `mcp-strike list-attacks` "
                f"to see available names."
            )
        selected.append(by_name[name])
    return selected


async def _scan_async(
    target_cfg: TargetConfig, run_cfg: RunConfig
) -> list[AttackResult]:
    """Connect to the target, run the selected attacks, and return findings."""
    selected = _select_attacks(run_cfg.attacks)

    async with open_stdio_target(
        command=target_cfg.command,
        args=target_cfg.args,
        env=target_cfg.env,
    ) as target:
        all_results: list[AttackResult] = []
        for cls in selected:
            attack = cls()
            attack.prepare()
            results = await attack.execute(target)
            all_results.extend(results)
        return all_results


def _run_scan_to_terminal(
    target_cfg: TargetConfig, run_cfg: RunConfig, *, show_all: bool
) -> None:
    """Shared back end for `scan` and `demo`: scan, then render."""
    console = Console()
    if run_cfg.show_responsible_use_notice:
        _print_notice(console)

    results = asyncio.run(_scan_async(target_cfg, run_cfg))
    render_terminal(results, show_all=show_all, console=console)


@app.command()
def scan(
    command: str = typer.Option(
        ..., "--command", "-c", help="Executable to launch the MCP server."
    ),
    arg: list[str] = typer.Option(
        [], "--arg", "-a", help="Argument for the server (repeatable)."
    ),
    only: list[str] = typer.Option(
        [],
        "--only",
        help="Run only attacks with these names (repeatable).",
    ),
    show_all: bool = typer.Option(
        False, "--show-all", help="Include FAILURE rows in the report."
    ),
    notice: bool = typer.Option(
        True,
        "--notice/--no-notice",
        help="Print the responsible-use notice (default: on).",
    ),
) -> None:
    """Connect to an MCP server over stdio and run all attacks against it."""
    target_cfg = TargetConfig(command=command, args=arg)
    run_cfg = RunConfig(
        # `or None` so an empty list (typer's default) is treated as
        # "run everything" by the config model.
        attacks=only or None,
        show_responsible_use_notice=notice,
    )
    _run_scan_to_terminal(target_cfg, run_cfg, show_all=show_all)


@app.command("list-attacks")
def list_attacks() -> None:
    """List every registered attack."""
    console = Console()
    table = Table(header_style="bold")
    table.add_column("Name")
    table.add_column("Stage")
    table.add_column("Class")
    for cls in get_all_attacks():
        table.add_row(cls.name, cls.stage.value, cls.__name__)
    console.print(table)


@app.command()
def demo(
    only: list[str] = typer.Option(
        [], "--only", help="Run only attacks with these names (repeatable)."
    ),
    show_all: bool = typer.Option(
        False, "--show-all", help="Include FAILURE rows in the report."
    ),
    notice: bool = typer.Option(
        True,
        "--notice/--no-notice",
        help="Print the responsible-use notice (default: on).",
    ),
) -> None:
    """Run all attacks against the bundled deliberately-vulnerable demo server."""
    target_cfg = TargetConfig(
        command=sys.executable, args=["-m", "demo_server"]
    )
    run_cfg = RunConfig(
        attacks=only or None,
        show_responsible_use_notice=notice,
    )
    _run_scan_to_terminal(target_cfg, run_cfg, show_all=show_all)


# Allow `python -m mcp_strike.cli` for development convenience.
if __name__ == "__main__":
    app()
