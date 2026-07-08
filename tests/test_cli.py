"""Tests for the typer CLI.

Uses ``typer.testing.CliRunner`` to invoke the app in-process. Each invoke
call runs the relevant command function synchronously (the async
target-and-scan inside is bridged with ``asyncio.run``).

The ``demo`` tests launch the deliberately-vulnerable demo server as a
subprocess and exercise the full scan-and-render path end to end. We pass
``--no-judge --no-agent`` to keep them hermetic: even when an
``OPENAI_API_KEY`` happens to be in the developer's env, the LLM
features stay off and the tests don't make real API calls.

The single real-API agent test at the bottom of this file is the
exception: it's gated on ``OPENAI_API_KEY`` and skipped otherwise.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from mcp_strike.attacks import AttackResult, Stage, Verdict
from mcp_strike.cli import _meets_fail_threshold, _parse_env, app

runner = CliRunner()


def test_list_attacks_shows_every_registered_attack() -> None:
    """`list-attacks` should mention every attack registered so far."""
    result = runner.invoke(app, ["list-attacks"])
    assert result.exit_code == 0, result.output
    # Metadata-stage and parameters-stage attacks.
    assert "description_prompt_injection" in result.stdout
    assert "overreaching_parameters" in result.stdout
    assert "path_traversal_probe" in result.stdout
    # Response-stage attacks.
    assert "response_injection_probe" in result.stdout
    assert "data_exfiltration_probe" in result.stdout


def test_demo_runs_and_surfaces_planted_vulns() -> None:
    """`demo --no-notice --no-judge --no-agent` runs a full static scan.

    --no-notice keeps output tight; --no-judge + --no-agent skip any
    OpenAI calls so the test is hermetic. We don't grep for specific
    rationales (those may evolve), just for the verdict label and an
    attack name.
    """
    result = runner.invoke(
        app, ["demo", "--no-notice", "--no-judge", "--no-agent"]
    )
    assert result.exit_code == 0, result.output
    assert "SUCCESS" in result.stdout
    assert "description_prompt_injection" in result.stdout


def test_demo_json_output_is_valid_json() -> None:
    """`demo --json --no-judge --no-agent` emits parseable JSON to stdout.

    Asserts top-level schema only; we trust the schema tests in
    test_report_json.py for finer-grained checks.
    """
    result = runner.invoke(
        app, ["demo", "--json", "--no-judge", "--no-agent"]
    )
    assert result.exit_code == 0, result.output

    parsed = json.loads(result.stdout)
    assert "summary" in parsed
    assert "results" in parsed
    summary = parsed["summary"]
    assert summary["total"] == len(parsed["results"])
    # With --no-judge + --no-agent, both feature blocks should be null.
    assert summary["llm_calls_used"] is None
    assert summary["llm_calls_cap"] is None
    assert summary["agent_calls_used"] is None
    assert summary["agent_calls_cap"] is None
    # At least one SUCCESS from the planted static vulns.
    assert summary["success"] >= 1


def test_demo_json_judge_metadata_when_disabled() -> None:
    """With --no-judge, no row should claim a real LLM call happened.

    Important nuance: ``--no-judge`` doesn't make ``judge`` always-null.
    The judge pipeline still runs NullJudge over UNCERTAIN/SUCCESS rows
    (FAILURE rows are skipped to save calls). NullJudge attaches a
    ``ran=False`` annotation so consumers can distinguish three states:

    - ``judge: null``                          → row wasn't eligible (FAILURE)
    - ``judge: {..., "ran": false}``           → eligible but judge disabled
    - ``judge: {..., "ran": true}``            → real LLM call happened
    """
    result = runner.invoke(
        app, ["demo", "--json", "--no-judge", "--no-agent"]
    )
    parsed = json.loads(result.stdout)
    for row in parsed["results"]:
        judge = row["judge"]
        if row["verdict"] == "failure":
            # FAILURE rows are skipped by the cost-saving policy.
            assert judge is None, f"unexpected judge on FAILURE row: {row}"
        else:
            # SUCCESS / UNCERTAIN rows get a NullJudge annotation with ran=False.
            assert judge is not None, f"missing judge annotation on {row}"
            assert judge["ran"] is False, f"unexpected ran=True with --no-judge: {row}"


def test_demo_judge_forced_without_key_reports_null_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--judge` with no API key falls back to NullJudge; metadata stays null.

    Regression guard for the null-vs-0 fix: a judge that was *requested* but
    couldn't actually run must report `null` call counts, not `0`. We chdir
    into an empty tmp dir so the repo's own `.env` can't re-inject a key, and
    use a runner that keeps the fallback warning (stderr) out of the JSON.
    """
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)

    # Write the report to a file rather than parsing stdout: the judge-disabled
    # warning goes to stderr, and reading the file sidesteps any stdout/stderr
    # handling differences across click versions.
    out_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        [
            "demo",
            "--judge",
            "--no-agent",
            "--no-notice",
            "--output-file",
            str(out_path),
        ],
    )
    assert result.exit_code == 0, result.output

    summary = json.loads(out_path.read_text(encoding="utf-8"))["summary"]
    assert summary["llm_calls_used"] is None
    assert summary["llm_calls_cap"] is None


def test_demo_output_file_writes_json_to_disk(tmp_path: Path) -> None:
    """`--output-file PATH` writes the JSON report to disk."""
    out_path = tmp_path / "scan.json"
    result = runner.invoke(
        app,
        ["demo", "--no-judge", "--no-agent", "--output-file", str(out_path)],
    )
    assert result.exit_code == 0, result.output

    text = out_path.read_text(encoding="utf-8")
    parsed = json.loads(text)
    assert "summary" in parsed
    assert parsed["summary"]["total"] >= 1


def test_scan_rejects_unknown_attack_name() -> None:
    """`scan --only no_such_attack ...` exits non-zero with a clear error."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--command", "python",
            "--arg", "-m",
            "--arg", "mcp_strike.demo_server",
            "--only", "no_such_attack",
            "--no-judge",
            "--no-agent",
        ],
    )
    assert result.exit_code != 0
    assert "no_such_attack" in result.output


def test_scan_reports_clean_error_for_unlaunchable_target() -> None:
    """A bogus --command should yield a clean error, not a Python traceback.

    This is the most common first-run mistake. We assert a non-zero exit, a
    human-readable 'error:' line, and crucially that no raw traceback leaked
    to the user.
    """
    result = runner.invoke(
        app,
        [
            "scan",
            "--command", "no_such_executable_xyz",
            "--no-judge",
            "--no-agent",
            "--no-notice",
        ],
    )
    assert result.exit_code != 0
    assert "could not scan target" in result.output
    # The whole point: the deep asyncio/anyio stack must not reach the user.
    assert "Traceback" not in result.output


def test_only_adaptive_agent_is_a_valid_filter() -> None:
    """`--only adaptive_agent` should be accepted as a valid filter name.

    Before P1.2, the CLI rejected this because the agent isn't a registered
    BaseAttack. Now we recognize it specially so users can run agent-only.
    Test runs with --no-agent so we don't actually need a key; we're just
    asserting the filter is *accepted*, not that the agent fires.
    """
    result = runner.invoke(
        app,
        [
            "demo",
            "--only", "adaptive_agent",
            "--no-judge",
            "--no-agent",  # makes the test hermetic; agent won't actually run
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    # No static attacks ran (filter is "adaptive_agent" only), and the
    # agent is disabled, so the summary should show zero results.
    assert parsed["summary"]["total"] == 0


def test_scan_against_demo_server_completes_successfully() -> None:
    """Positive end-to-end test for the `scan` subcommand.

    All previous CLI tests for `scan` exercised the error path
    (--only no_such_attack). This is the happy-path counterpart: hand
    `scan` real arguments pointing at the bundled demo server and assert
    a green exit + visible SUCCESS rows.
    """
    import sys

    result = runner.invoke(
        app,
        [
            "scan",
            "--command", sys.executable,
            "--arg", "-m",
            "--arg", "mcp_strike.demo_server",
            "--no-notice",
            "--no-judge",
            "--no-agent",
        ],
    )
    assert result.exit_code == 0, result.output
    # The demo server has planted vulns that static attacks find.
    assert "SUCCESS" in result.stdout


def test_parse_env_builds_dict_and_keeps_equals_in_value() -> None:
    """KEY=VALUE parsing; only the first `=` splits, so values may contain `=`."""
    assert _parse_env(["A=1", "URL=postgres://h/db?x=y"]) == {
        "A": "1",
        "URL": "postgres://h/db?x=y",
    }


def test_parse_env_empty_is_none() -> None:
    """No --env means None, so the target keeps the SDK's default environment."""
    assert _parse_env([]) is None


def test_parse_env_rejects_missing_equals() -> None:
    """A value without `=` is a usage error, not a silent skip."""
    with pytest.raises(typer.BadParameter):
        _parse_env(["NOEQUALS"])


def test_scan_accepts_env_flag_end_to_end() -> None:
    """`scan ... --env FOO=bar` wires through and completes (demo ignores it)."""
    import sys

    result = runner.invoke(
        app,
        [
            "scan",
            "--command", sys.executable,
            "--arg", "-m",
            "--arg", "mcp_strike.demo_server",
            "--env", "MCP_STRIKE_TEST=1",
            "--no-notice",
            "--no-judge",
            "--no-agent",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "SUCCESS" in result.stdout


def _result(verdict: Verdict) -> AttackResult:
    return AttackResult(
        attack_name="a",
        stage=Stage.METADATA,
        target_tool="t",
        verdict=verdict,
        rationale="r",
    )


def test_fail_threshold_none_never_trips() -> None:
    assert _meets_fail_threshold([_result(Verdict.SUCCESS)], None) is False


def test_fail_threshold_success_trips_only_on_success() -> None:
    assert _meets_fail_threshold(
        [_result(Verdict.UNCERTAIN), _result(Verdict.FAILURE)], "success"
    ) is False
    assert _meets_fail_threshold([_result(Verdict.SUCCESS)], "success") is True


def test_fail_threshold_uncertain_is_the_lower_bar() -> None:
    """`uncertain` also trips on SUCCESS, but never on plain FAILURE."""
    assert _meets_fail_threshold([_result(Verdict.UNCERTAIN)], "uncertain") is True
    assert _meets_fail_threshold([_result(Verdict.SUCCESS)], "uncertain") is True
    assert _meets_fail_threshold([_result(Verdict.FAILURE)], "uncertain") is False


def test_demo_fail_on_success_exits_nonzero() -> None:
    """The demo has confirmed vulns, so --fail-on success must exit code 1."""
    result = runner.invoke(
        app, ["demo", "--no-judge", "--no-agent", "--no-notice", "--fail-on", "success"]
    )
    assert result.exit_code == 1, result.output


def test_fail_on_rejects_invalid_value() -> None:
    result = runner.invoke(
        app, ["demo", "--no-judge", "--no-agent", "--no-notice", "--fail-on", "bogus"]
    )
    # Exit code 2 = usage/operational error. Asserting the code (not the
    # rendered message text) keeps this robust across terminal widths.
    assert result.exit_code == 2, result.output
    assert "fail-on" in result.output.lower()


def test_version_flag_prints_and_exits() -> None:
    """`mcp-strike --version` should print the version and exit 0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    # Format: "mcp-strike X.Y.Z[+dev]"; assert prefix and the major.minor.
    assert "mcp-strike" in result.stdout
    assert "0.1" in result.stdout  # tolerant: matches 0.1.0, 0.1.0+dev, etc.


def test_only_filter_skips_agent_when_not_listed() -> None:
    """`--only <static_attack>` should NOT also run the agent.

    Before P1.3 the agent ran even when --only narrowed to a single static
    attack. Now --only is a strict filter across the whole pipeline.
    """
    # Note: we use --no-agent so this is hermetic without a key, but the
    # important assertion is that agent rows don't appear regardless.
    result = runner.invoke(
        app,
        [
            "demo",
            "--only", "description_prompt_injection",
            "--no-judge",
            "--no-agent",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    # No row should have attack_name="adaptive_agent".
    for row in parsed["results"]:
        assert row["attack_name"] != "adaptive_agent", (
            f"agent ran despite --only filter: {row}"
        )


def test_root_help_lists_subcommands() -> None:
    """Bare invocation prints help (no_args_is_help=True) and lists subcommands."""
    result = runner.invoke(app, [])
    # `no_args_is_help` produces exit code 0 in recent typer; older versions
    # may use 2. Either is acceptable for help.
    assert result.exit_code in (0, 2)
    output = result.output
    assert "scan" in output
    assert "demo" in output
    assert "list-attacks" in output


# --- real-API integration test, gated by env -------------------------------


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set; skipping real-API agent test",
)
def test_demo_with_agent_catches_vuln_six() -> None:
    """End-to-end: the adaptive agent should flag check_session (VULN #6).

    Static attacks all land on FAILURE (or skip) for check_session; that's
    enforced by ``test_vuln_six_static_blindspot.py``. The agent is the
    only line of defense, and this test confirms it actually catches it.

    Cap is generous (60) so all 6 demo tools get probed; total cost is
    fractions of a cent on gpt-4o-mini.
    """
    result = runner.invoke(
        app,
        [
            "demo",
            "--no-judge",        # focus the test on the agent
            "--agent",           # force on, regardless of auto-detect
            "--json",
            "--no-notice",
            "--max-agent-calls", "60",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)

    # Find the agent's row for check_session.
    agent_rows_for_check_session = [
        r for r in parsed["results"]
        if r["attack_name"] == "adaptive_agent" and r["target_tool"] == "check_session"
    ]
    assert len(agent_rows_for_check_session) == 1, (
        "expected exactly one agent row for check_session; "
        f"got {len(agent_rows_for_check_session)}"
    )

    # The agent should NOT call this clean; it's actively asking for a
    # password. SUCCESS is ideal; UNCERTAIN is acceptable given LLM
    # non-determinism. FAILURE would mean the agent missed it.
    verdict = agent_rows_for_check_session[0]["verdict"]
    assert verdict != "failure", (
        f"agent missed VULN #6: verdict was {verdict!r}, rationale: "
        f"{agent_rows_for_check_session[0]['rationale']!r}"
    )
