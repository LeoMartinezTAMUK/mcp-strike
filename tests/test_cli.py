"""Tests for the typer CLI.

Uses ``typer.testing.CliRunner`` to invoke the app in-process. Each
``invoke`` call runs the relevant command function synchronously (with
``asyncio.run`` handling the async target-and-scan inside).

The ``demo`` test launches the deliberately-vulnerable demo server as a
subprocess and exercises the full scan-and-render path end to end.
"""

from __future__ import annotations

from typer.testing import CliRunner

from mcp_strike.cli import app

runner = CliRunner()


def test_list_attacks_shows_all_three() -> None:
    """`list-attacks` should mention every registered Phase 1 attack."""
    result = runner.invoke(app, ["list-attacks"])
    assert result.exit_code == 0, result.output
    assert "description_prompt_injection" in result.stdout
    assert "overreaching_parameters" in result.stdout
    assert "path_traversal_probe" in result.stdout


def test_demo_runs_and_surfaces_planted_vulns() -> None:
    """`demo --no-notice` should run a full scan and surface SUCCESS findings.

    --no-notice keeps the output tighter for assertions. We don't grep for
    very specific rationales (those may evolve); we just check that the
    Verdict labels and at least one attack name made it to the report.
    """
    result = runner.invoke(app, ["demo", "--no-notice"])
    assert result.exit_code == 0, result.output

    # Summary counts at least one SUCCESS (the description-injection planted vuln).
    assert "SUCCESS" in result.stdout
    # Specific attack name appears in either the table or the summary.
    assert "description_prompt_injection" in result.stdout


def test_scan_rejects_unknown_attack_name() -> None:
    """`scan --only no_such_attack ...` should exit non-zero with a clear error."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--command", "python",
            "--arg", "-m",
            "--arg", "demo_server",
            "--only", "no_such_attack",
        ],
    )
    assert result.exit_code != 0
    # typer.BadParameter formats the message under the Click 'Invalid value'
    # banner; we just check that the bad name shows up somewhere.
    assert "no_such_attack" in result.output


def test_root_help_lists_subcommands() -> None:
    """Bare invocation prints help (no_args_is_help=True) and lists subcommands."""
    result = runner.invoke(app, [])
    # `no_args_is_help` causes click to print help with exit code 0 in
    # recent typer; in older versions it may be 2. Either is acceptable.
    assert result.exit_code in (0, 2)
    output = result.output
    assert "scan" in output
    assert "demo" in output
    assert "list-attacks" in output
