"""Command-line interface for MCP-Strike.

Entry point: the ``mcp-strike`` console script (defined in pyproject.toml's
``[project.scripts]``) calls :data:`app`. Three subcommands are exposed:

- ``scan``: connect to a target and run all attacks against it.
- ``list-attacks``: show every registered attack (name, stage, class).
- ``demo``: convenience wrapper that runs a scan against the bundled
  deliberately-vulnerable demo server.

The responsible-use notice prints at startup of ``scan`` and ``demo`` in
terminal mode unless suppressed with ``--no-notice``. JSON mode auto-
suppresses the notice (it's for human eyes, not for machines).

Judge defaults:
- ``--judge`` / ``--no-judge`` is tri-state: omit to auto-detect
  (enabled iff ``OPENAI_API_KEY`` is set), or pass either form to override.
- Default model is gpt-4o-mini; override with ``--judge-model``.
- ``--max-llm-calls`` caps real LLM calls per run (default 20).

Adaptive agent defaults:
- Same tri-state pattern via ``--agent`` / ``--no-agent``.
- Default model gpt-4o-mini; override with ``--agent-model``.
- ``--max-agent-calls`` caps real LLM calls per run (default 50). Separate
  budget from the judge's cap.
"""

from __future__ import annotations

import asyncio
import logging
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
    subcommand routing, so ``mcp-strike --version`` works even when no
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
    """Top-level app callback; only the global flags live here."""

# Kept as module-level text so it's easy to copy-paste into docs and trivial
# to update without editing function bodies.
_NOTICE_TEXT = (
    "MCP-Strike is a defensive tool for testing MCP servers you own.\n"
    "Running it against systems you don't control may be illegal in your\n"
    "jurisdiction. See the README's Responsible-use section for details."
)


@dataclass
class _ScanMetadata:
    """Counts emitted by ``_scan_async`` so the CLI knows what to report."""

    llm_calls_used: int
    agent_calls_used: int


# ---------------------------------------------------------------------------
# Internal helpers (not subcommands)
# ---------------------------------------------------------------------------


def _configure_logging(*, verbose: bool) -> None:
    """Surface mcp-strike's own DEBUG logs when ``--verbose`` is set.

    The judge and agent log parse failures (and other diagnostics) at DEBUG;
    they're invisible at the default level. ``--verbose`` attaches a stderr
    handler scoped to the ``mcp_strike`` logger tree, so third-party DEBUG
    noise (httpx, openai, mcp, asyncio) stays out. A no-op without the flag,
    so default runs are unchanged.
    """
    if not verbose:
        return
    handler = logging.StreamHandler()  # defaults to stderr
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger = logging.getLogger("mcp_strike")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)


def _describe_target_error(exc: BaseException) -> str:
    """Pull a human-readable cause out of a target connection failure.

    The MCP stdio client runs its transport inside an anyio task group, so a
    failure to launch the server (bad command) or to speak MCP to it (the
    process started but isn't an MCP server) often surfaces as an
    ``ExceptionGroup`` whose own message is the unhelpful "unhandled errors
    in a TaskGroup". We unwrap to the first leaf so the user sees the real
    cause ("No such file or directory") instead.

    Duck-typed on ``.exceptions`` rather than catching ``ExceptionGroup`` by
    type: that attribute exists on both the 3.11+ builtin and the
    ``exceptiongroup`` backport used on 3.10, so this stays version-portable
    without a conditional import.
    """
    inner = getattr(exc, "exceptions", None)
    if inner:
        return _describe_target_error(inner[0])
    return f"{type(exc).__name__}: {exc}"


def _parse_env(pairs: list[str]) -> dict[str, str] | None:
    """Parse repeated ``--env KEY=VALUE`` options into a dict (or ``None``).

    Returns ``None`` when nothing was passed, so the target keeps the MCP
    SDK's minimal default environment. Only the first ``=`` splits key from
    value, so values may themselves contain ``=``.

    Note on secrets: the SDK merges these on top of its *default* environment
    (PATH, HOME, ...), which does not include the scanner's own variables. So
    ``OPENAI_API_KEY`` and friends are never forwarded to the target unless
    you pass them explicitly here.
    """
    if not pairs:
        return None
    env: dict[str, str] = {}
    for item in pairs:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise typer.BadParameter(f"--env expects KEY=VALUE, got {item!r}")
        env[key] = value
    return env


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
    name ``"adaptive_agent"`` is recognized but skipped here; the agent
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

    Returns False when the agent wasn't built (no key, or --no-agent), or
    when ``--only`` was set without including ``"adaptive_agent"``. The
    latter makes the filter strict: ``--only description_prompt_injection``
    runs only that static attack and nothing else, including no agent.
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
        typer.echo(f"warning: judge disabled: {exc}", err=True)
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
    because the agent isn't always present in the pipeline; call sites
    just branch on ``if agent is not None``. Less code than a NullAgent.
    """
    if not enabled:
        return None
    try:
        return AdaptiveAgent.from_env(
            model=model, max_rounds=max_rounds, max_calls=max_calls
        )
    except OSError as exc:
        typer.echo(f"warning: agent disabled: {exc}", err=True)
        return None


async def _scan_async(
    target_cfg: TargetConfig,
    run_cfg: RunConfig,
    judge: BaseJudge,
    agent: AdaptiveAgent | None,
) -> tuple[list[AttackResult], _ScanMetadata]:
    """Connect, run attacks + judge + (optional) agent. Returns (results, metadata).

    Pipeline order:
      1. Static attacks populate ``all_results``.
      2. Judge pass over ``all_results`` (only the static-attack rows exist
         here; the agent's findings are not double-judged because the
         agent already uses an LLM with reasoning).
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

        # 2. Judge pass: only over static-attack rows; agent results
        # haven't been generated yet.
        llm_calls_used = await annotate_with_judge(
            all_results, judge, max_calls=run_cfg.max_llm_calls
        )

        # 3. Adaptive agent (optional).
        #
        # We skip the agent in two cases:
        #   - It wasn't built (no key, or --no-agent).
        #   - ``--only`` was set without including "adaptive_agent", meaning
        #     the user explicitly narrowed to a subset that doesn't include us.
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
    verbose: bool = False,
) -> None:
    """Shared back end for ``scan`` and ``demo``: scan, judge, agent, render."""
    _configure_logging(verbose=verbose)

    # Auto-load .env from cwd before resolving any auth-dependent config.
    # Shell-exported vars still take precedence; this is purely additive.
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

    # Mirror the agent's null-vs-0 handling for the judge. ``judge_enabled``
    # is what the user *requested*; ``_build_judge`` may still have fallen
    # back to NullJudge (e.g. ``--judge`` forced on with no OPENAI_API_KEY).
    # Keying the JSON metadata off whether a *real* judge was constructed
    # keeps "null = judge didn't run" honest, instead of reporting 0 calls
    # for a judge that never actually ran.
    judge_actually_ran = not isinstance(judge, NullJudge)

    # Notice: terminal-mode only, when not suppressed.
    if not json_output and not output_file and run_cfg.show_responsible_use_notice:
        _print_notice(Console())

    try:
        results, metadata = asyncio.run(
            _scan_async(target_cfg, run_cfg, judge, agent)
        )
    except Exception as exc:
        # Anything escaping here is a connect/transport-phase failure:
        # attacks catch their own probe errors (returning UNCERTAIN rows), so
        # by the time we're running them the scan no longer raises. The
        # dominant case is a mistyped --command or a server that fails to
        # start — the most common first-run mistake. Surface it as one clean
        # line instead of a deep asyncio/anyio traceback.
        typer.echo(
            f"error: could not scan target {target_cfg.command!r}: "
            f"{_describe_target_error(exc)}",
            err=True,
        )
        typer.echo(
            "hint: ensure the command launches a working MCP server over stdio.",
            err=True,
        )
        raise typer.Exit(code=2) from exc

    # JSON output path: file or stdout.
    if json_output or output_file:
        text = render_json_string(
            results,
            # null vs 0: null = feature didn't run, 0 = ran but made 0 calls.
            llm_calls_used=metadata.llm_calls_used if judge_actually_ran else None,
            llm_calls_cap=run_cfg.max_llm_calls if judge_actually_ran else None,
            agent_calls_used=metadata.agent_calls_used if agent_actually_ran else None,
            agent_calls_cap=run_cfg.max_agent_calls if agent_actually_ran else None,
        )
        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(text)
            except OSError as exc:
                # e.g. the parent directory doesn't exist, or it's not
                # writable. Surface it cleanly instead of a traceback.
                typer.echo(
                    f"error: could not write report to {output_file!r}: {exc}",
                    err=True,
                )
                raise typer.Exit(code=2) from exc
        else:
            # typer.echo, not Console.print: avoid Rich post-processing on JSON.
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
    env: list[str] = typer.Option(
        [],
        "--env",
        "-e",
        help=(
            "Environment variable for the target server as KEY=VALUE "
            "(repeatable). Merged onto a minimal default env; the scanner's "
            "own variables are not forwarded unless listed here."
        ),
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
            "Run the LLM judge after static attacks. Default: auto, "
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
            "auto, enabled iff OPENAI_API_KEY is set."
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
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable mcp-strike debug logging to stderr (parse failures, etc.).",
    ),
) -> None:
    """Connect to an MCP server over stdio and run all attacks against it."""
    target_cfg = TargetConfig(
        command=command,
        args=arg,
        env=_parse_env(env),
        call_timeout=call_timeout,
    )
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
        verbose=verbose,
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
            "Run the LLM judge after static attacks. Default: auto, "
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
            "auto, enabled iff OPENAI_API_KEY is set."
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
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable mcp-strike debug logging to stderr (parse failures, etc.).",
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
        verbose=verbose,
    )


# Allow `python -m mcp_strike.cli` for development convenience.
if __name__ == "__main__":
    app()
