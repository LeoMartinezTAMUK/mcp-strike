"""Command-line interface for MCP-Strike.

Entry point: the ``mcp-strike`` console script (defined in pyproject.toml's
``[project.scripts]``) calls :data:`app`. Three subcommands are exposed:

- ``scan``         — connect to a target and run all attacks against it.
- ``list-attacks`` — show every registered attack (name, stage, class).
- ``demo``         — convenience: run a scan against the bundled
                     deliberately-vulnerable demo server.

The responsible-use notice prints at startup of ``scan`` and ``demo`` in
terminal mode unless suppressed with ``--no-notice``. JSON mode auto-
suppresses the notice (it's for human eyes, not for machines).

Judge defaults (Phase 2 — see PLAN.md §10):
- ``--judge`` / ``--no-judge`` is tri-state: omit to auto-detect
  (enabled iff ``OPENAI_API_KEY`` is set), or pass either form to override.
- Default model is gpt-4o-mini; override with ``--judge-model``.
- ``--max-llm-calls`` caps real LLM calls per run (default 20).

Adaptive agent defaults (Phase 3):
- Same tri-state pattern via ``--agent`` / ``--no-agent``.
- Default model gpt-4o-mini; override with ``--agent-model``.
- ``--max-agent-calls`` caps real LLM calls per run (default 50). Separate
  budget from the judge's cap.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_strike import __version__
from mcp_strike.agent import ATTACK_NAME as AGENT_ATTACK_NAME
from mcp_strike.agent import AdaptiveAgent
from mcp_strike.attacks import AttackResult, BaseAttack, get_all_attacks
from mcp_strike.config import RunConfig, TargetConfig
from mcp_strike.config.dotenv import load_dotenv
from mcp_strike.judge import BaseJudge, NullJudge, OpenAIJudge, annotate_with_judge
from mcp_strike.report.json_report import render_json_string
from mcp_strike.report.terminal import render_terminal
from mcp_strike.target import open_stdio_target

app = typer.Typer(
    add_completion=False,
    help="Active, runtime adversarial testing for MCP servers you own.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    """Eager callback for ``--version``: print version, then exit cleanly.

    ``is_eager=True`` on the option (below) means this fires before any
    subcommand routing — so ``mcp-strike --version`` works even when no
    subcommand follows.
    """
    if value:
        typer.echo(f"mcp-strike {__version__}")
        raise typer.Exit()


@app.callback()
def _main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Top-level app callback — only the global flags live here."""

# Kept as module-level text so it's easy to copy-paste into docs and trivial
# to update without editing function bodies.
_NOTICE_TEXT = (
    "MCP-Strike is a defensive tool for testing MCP servers you own.\n"
    "Running it against systems you don't control may be illegal in your\n"
    "jurisdiction. See README + docs/PLAN.md §14 for the full note."
)


@dataclass
class _ScanMetadata:
    """Counts emitted by ``_scan_async`` so the CLI knows what to report."""

    llm_calls_used: int
    agent_calls_used: int


# ---------------------------------------------------------------------------
# Internal helpers (not subcommands)
# ---------------------------------------------------------------------------


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
    """Resolve the attack-name filter into static attack classes.

    ``None`` or an empty list means "every registered attack". Unknown
    static-attack names raise :class:`typer.BadParameter`. The special
    name ``"adaptive_agent"`` is recognized but skipped here — the agent
    isn't a registered ``BaseAttack``, it's handled by :func:`_should_run_agent`.
    """
    all_attacks = get_all_attacks()
    if not filter_names:
        return all_attacks

    by_name = {cls.name: cls for cls in all_attacks}
    valid_names = set(by_name) | {AGENT_ATTACK_NAME}
    selected: list[type[BaseAttack]] = []
    for name in filter_names:
        if name not in valid_names:
            raise typer.BadParameter(
                f"Unknown attack {name!r}. Run `mcp-strike list-attacks` "
                f"to see available names "
                f"(also valid: {AGENT_ATTACK_NAME!r})."
            )
        # Agent name is valid but doesn't contribute a static attack class.
        if name in by_name:
            selected.append(by_name[name])
    return selected


def _should_run_agent(
    *, agent: AdaptiveAgent | None, filter_names: list[str] | None
) -> bool:
    """Decide whether the agent should run for this scan.

    Returns False when the agent wasn't built (no key / --no-agent) OR when
    ``--only`` was set without including ``"adaptive_agent"``. The latter
    makes the filter strict: ``--only description_prompt_injection`` runs
    only that static attack and nothing else, including no agent.
    """
    if agent is None:
        return False
    if not filter_names:
        return True  # no filter = run everything
    return AGENT_ATTACK_NAME in filter_names


def _resolve_auto_flag(flag: bool | None) -> bool:
    """Turn a --flag/--no-flag tri-state into a definite bool.

    Shared by ``--judge`` and ``--agent``: ``True``/``False`` respects an
    explicit choice; ``None`` auto-detects based on whether
    ``OPENAI_API_KEY`` is set.
    """
    if flag is not None:
        return flag
    return bool(os.environ.get("OPENAI_API_KEY"))


def _build_judge(*, enabled: bool, model: str | None) -> BaseJudge:
    """Construct the judge implementation for this run.

    Falls back to :class:`NullJudge` when disabled OR when ``OPENAI_API_KEY``
    is missing despite enabled=True (with a warning to stderr). Never raises.
    """
    if not enabled:
        return NullJudge()
    try:
        return OpenAIJudge.from_env(model=model)
    except OSError as exc:
        # Key missing or invalid env. Warn to stderr so JSON-on-stdout
        # consumers still get clean JSON; fall back so the scan continues.
        typer.echo(f"warning: judge disabled — {exc}", err=True)
        return NullJudge()


def _build_agent(
    *,
    enabled: bool,
    model: str | None,
    max_rounds: int,
    max_calls: int,
) -> AdaptiveAgent | None:
    """Construct the adaptive agent if enabled. Returns ``None`` when off.

    Unlike the judge (which has a NullJudge no-op) we use ``None`` here
    because the agent isn't always present in the pipeline — call sites
    just branch on ``if agent is not None``. Less code than a NullAgent.
    """
    if not enabled:
        return None
    try:
        return AdaptiveAgent.from_env(
            model=model, max_rounds=max_rounds, max_calls=max_calls
        )
    except OSError as exc:
        typer.echo(f"warning: agent disabled — {exc}", err=True)
        return None


async def _scan_async(
    target_cfg: TargetConfig,
    run_cfg: RunConfig,
    judge: BaseJudge,
    agent: AdaptiveAgent | None,
) -> tuple[list[AttackResult], _ScanMetadata]:
    """Connect, run attacks + judge + (optional) agent. Returns (results, metadata).

    Pipeline order:
      1. Static attacks → ``all_results``.
      2. Judge pass over ``all_results`` (only the static-attack rows exist
         here; the agent's findings are not double-judged — the agent
         already uses an LLM with reasoning).
      3. Adaptive agent runs over the tool surface, appends its
         AttackResults to ``all_results``.
    """
    selected = _select_attacks(run_cfg.attacks)

    async with open_stdio_target(
        command=target_cfg.command,
        args=target_cfg.args,
        env=target_cfg.env,
        call_timeout=target_cfg.call_timeout,
    ) as target:
        all_results: list[AttackResult] = []

        # 1. Static attacks.
        for cls in selected:
            attack = cls()
            results = await attack.execute(target)
            all_results.extend(results)

        # 2. Judge pass — only over static-attack rows; agent results
        # haven't been generated yet.
        llm_calls_used = await annotate_with_judge(
            all_results, judge, max_calls=run_cfg.max_llm_calls
        )

        # 3. Adaptive agent (optional).
        #
        # We skip the agent in two cases:
        #   - It wasn't built (no key, or --no-agent).
        #   - ``--only`` was set without including "adaptive_agent" — the
        #     user explicitly narrowed to a subset that doesn't include us.
        agent_calls_used = 0
        if _should_run_agent(agent=agent, filter_names=run_cfg.attacks):
            assert agent is not None  # narrowed by _should_run_agent
            tools = await target.list_tools()
            agent_results = await agent.attack_all_tools(tools, target)
            all_results.extend(agent_results)
            agent_calls_used = agent.calls_made

        return all_results, _ScanMetadata(
            llm_calls_used=llm_calls_used,
            agent_calls_used=agent_calls_used,
        )


def _run_scan(
    target_cfg: TargetConfig,
    run_cfg: RunConfig,
    *,
    show_all: bool,
    json_output: bool,
    output_file: str | None,
) -> None:
    """Shared back end for ``scan`` and ``demo``: scan, judge, agent, render."""
    # Auto-load .env from cwd before resolving any auth-dependent config.
    # Shell-exported vars still take precedence — purely additive.
    load_dotenv(Path.cwd() / ".env")

    judge_enabled = _resolve_auto_flag(run_cfg.judge_enabled)
    agent_enabled = _resolve_auto_flag(run_cfg.agent_enabled)

    judge = _build_judge(enabled=judge_enabled, model=run_cfg.judge_model)
    agent = _build_agent(
        enabled=agent_enabled,
        model=run_cfg.agent_model,
        max_rounds=run_cfg.agent_max_rounds,  # CLI's --agent-max-rounds lands here
        max_calls=run_cfg.max_agent_calls,
    )

    # If _build_agent fell back to None (no key), OR if --only filtered the
    # agent out, reflect that in the "did the agent run" reporting so the
    # JSON shows null, not 0.
    agent_actually_ran = _should_run_agent(agent=agent, filter_names=run_cfg.attacks)

    # Notice: terminal-mode only, when not suppressed.
    if not json_output and not output_file and run_cfg.show_responsible_use_notice:
        _print_notice(Console())

    results, metadata = asyncio.run(
        _scan_async(target_cfg, run_cfg, judge, agent)
    )

    # JSON output path: file or stdout.
    if json_output or output_file:
        text = render_json_string(
            results,
            # null vs 0: null = feature didn't run, 0 = ran but made 0 calls.
            llm_calls_used=metadata.llm_calls_used if judge_enabled else None,
            llm_calls_cap=run_cfg.max_llm_calls if judge_enabled else None,
            agent_calls_used=metadata.agent_calls_used if agent_actually_ran else None,
            agent_calls_cap=run_cfg.max_agent_calls if agent_actually_ran else None,
        )
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            # typer.echo, not Console.print — avoid Rich post-processing on JSON.
            typer.echo(text)
        return

    # Terminal mode.
    render_terminal(results, show_all=show_all, console=Console())


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


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
    call_timeout: float = typer.Option(
        30.0,
        "--call-timeout",
        help=(
            "Per-tool-call timeout in seconds (default 30). Applies to "
            "every MCP protocol call; a malicious or hung server can't "
            "block the scan beyond this."
        ),
    ),
    show_all: bool = typer.Option(
        False, "--show-all", help="Include FAILURE rows in the terminal report."
    ),
    notice: bool = typer.Option(
        True,
        "--notice/--no-notice",
        help="Print the responsible-use notice (terminal mode only).",
    ),
    judge: bool = typer.Option(
        None,
        "--judge/--no-judge",
        help=(
            "Run the LLM judge after static attacks. Default: auto — "
            "enabled iff OPENAI_API_KEY is set."
        ),
    ),
    judge_model: str = typer.Option(
        None,
        "--judge-model",
        help="Override the default judge model (gpt-4o-mini).",
    ),
    max_llm_calls: int = typer.Option(
        20,
        "--max-llm-calls",
        help="Cap on real LLM calls per run from the judge (default 20).",
    ),
    agent: bool = typer.Option(
        None,
        "--agent/--no-agent",
        help=(
            "Run the adaptive LLM agent after static attacks. Default: "
            "auto — enabled iff OPENAI_API_KEY is set."
        ),
    ),
    agent_model: str = typer.Option(
        None,
        "--agent-model",
        help="Override the default agent model (gpt-4o-mini).",
    ),
    agent_max_rounds: int = typer.Option(
        3,
        "--agent-max-rounds",
        help=(
            "Per-tool round cap for the agent (default 3). Each round is "
            "~1 LLM call, plus a final verdict call after the rounds."
        ),
    ),
    max_agent_calls: int = typer.Option(
        50,
        "--max-agent-calls",
        help="Cap on real LLM calls per run from the agent (default 50).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON to stdout instead of a terminal table.",
    ),
    output_file: str = typer.Option(
        None,
        "--output-file",
        help="Write the JSON report to this path. Implies --json.",
    ),
) -> None:
    """Connect to an MCP server over stdio and run all attacks against it."""
    target_cfg = TargetConfig(command=command, args=arg, call_timeout=call_timeout)
    run_cfg = RunConfig(
        # `or None` so an empty list (typer's default) is treated as
        # "run everything" by the config model.
        attacks=only or None,
        show_responsible_use_notice=notice,
        judge_enabled=judge,
        judge_model=judge_model,
        max_llm_calls=max_llm_calls,
        agent_enabled=agent,
        agent_model=agent_model,
        agent_max_rounds=agent_max_rounds,
        max_agent_calls=max_agent_calls,
    )
    _run_scan(
        target_cfg,
        run_cfg,
        show_all=show_all,
        json_output=json_output,
        output_file=output_file,
    )


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
    call_timeout: float = typer.Option(
        30.0,
        "--call-timeout",
        help="Per-tool-call timeout in seconds (default 30).",
    ),
    show_all: bool = typer.Option(
        False, "--show-all", help="Include FAILURE rows in the terminal report."
    ),
    notice: bool = typer.Option(
        True,
        "--notice/--no-notice",
        help="Print the responsible-use notice (terminal mode only).",
    ),
    judge: bool = typer.Option(
        None,
        "--judge/--no-judge",
        help=(
            "Run the LLM judge after static attacks. Default: auto — "
            "enabled iff OPENAI_API_KEY is set."
        ),
    ),
    judge_model: str = typer.Option(
        None,
        "--judge-model",
        help="Override the default judge model (gpt-4o-mini).",
    ),
    max_llm_calls: int = typer.Option(
        20,
        "--max-llm-calls",
        help="Cap on real LLM calls per run from the judge (default 20).",
    ),
    agent: bool = typer.Option(
        None,
        "--agent/--no-agent",
        help=(
            "Run the adaptive LLM agent after static attacks. Default: "
            "auto — enabled iff OPENAI_API_KEY is set."
        ),
    ),
    agent_model: str = typer.Option(
        None,
        "--agent-model",
        help="Override the default agent model (gpt-4o-mini).",
    ),
    agent_max_rounds: int = typer.Option(
        3,
        "--agent-max-rounds",
        help=(
            "Per-tool round cap for the agent (default 3). Each round is "
            "~1 LLM call, plus a final verdict call after the rounds."
        ),
    ),
    max_agent_calls: int = typer.Option(
        50,
        "--max-agent-calls",
        help="Cap on real LLM calls per run from the agent (default 50).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON to stdout instead of a terminal table.",
    ),
    output_file: str = typer.Option(
        None,
        "--output-file",
        help="Write the JSON report to this path. Implies --json.",
    ),
) -> None:
    """Run all attacks against the bundled deliberately-vulnerable demo server."""
    target_cfg = TargetConfig(
        command=sys.executable,
        args=["-m", "mcp_strike.demo_server"],
        call_timeout=call_timeout,
    )
    run_cfg = RunConfig(
        attacks=only or None,
        show_responsible_use_notice=notice,
        judge_enabled=judge,
        judge_model=judge_model,
        max_llm_calls=max_llm_calls,
        agent_enabled=agent,
        agent_model=agent_model,
        agent_max_rounds=agent_max_rounds,
        max_agent_calls=max_agent_calls,
    )
    _run_scan(
        target_cfg,
        run_cfg,
        show_all=show_all,
        json_output=json_output,
        output_file=output_file,
    )


# Allow `python -m mcp_strike.cli` for development convenience.
if __name__ == "__main__":
    app()
