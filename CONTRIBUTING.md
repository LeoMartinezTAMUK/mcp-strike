# Contributing to MCP-Strike

Thanks for thinking about contributing. MCP-Strike is small enough that any contribution is meaningful, but the maintainer is solo and part-time, so a few up-front conventions keep reviews fast.

## Quick setup

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/LeoMartinezTAMUK/mcp-strike.git
cd mcp-strike
uv sync --extra dev

# Sanity-check the toolchain
uv run ruff check .
uv run pytest -v
uv run mcp-strike demo --no-judge --no-agent
```

If `mcp-strike demo` prints a scan table, your environment is good.

## Project conventions

- **Python 3.10+**, with type hints on all public functions.
- **Lint:** `ruff check .` must be clean. Auto-fix with `ruff check --fix .`.
- **Type-check:** `uv run mypy src/mcp_strike` must be clean. CI gates on this for the 3.10 cell.
- **Tests:** `pytest -v` must be green before any PR is mergeable. Add tests with new code — see existing patterns in `tests/`.
- **Coverage:** optional locally, but useful — `uv run pytest --cov` prints the per-file coverage with missing-line ranges. CI tracks but doesn't gate on a floor yet.
- **Clarity > cleverness.** Every line should be one a new contributor can understand on first read. We avoid dense one-liners and undocumented metaprogramming.
- **Small, reviewable commits.** Imperative commit messages: "add stdio HTTP transport", not "added stuff".

## How to add a new static attack

1. Drop a new module in `src/mcp_strike/attacks/`. Copy the shape of `description_injection.py` (passive) or `path_traversal.py` (active).
2. Subclass `BaseAttack`, set `name` (unique, lowercase, underscore-separated) and `stage`, and implement `async def execute(target) -> list[AttackResult]`.
3. Decorate the class with `@register_attack` (imported from `mcp_strike.attacks.registry`).
4. Add the module to the side-effect import block in `src/mcp_strike/attacks/__init__.py`.
5. Add a test file `tests/test_attack_<your_attack>.py`. Use the existing tests as templates — they spawn the demo server, run the attack, and assert on findings.
6. If your attack catches a vulnerability the demo server doesn't already expose, add a planted-vuln tool to `src/mcp_strike/demo_server/server.py` so the test has something to fire on. Comment it as `VULN #N` consistent with the others.

## How to add a new LLM-backend (judge or agent)

The `judge/` and `agent/` modules currently support OpenAI only. To add Anthropic, Vertex, etc.:

1. For the judge: implement a new class subclassing `BaseJudge` (see `judge/openai_judge.py` for the shape — `from_env`, `async def judge(...)`).
2. For the agent: implement `from_env` + `attack_one_tool` / `attack_all_tools` with similar signatures.
3. Wire model selection through `RunConfig` and the CLI (mirror `--judge-model` / `--agent-model`).
4. Unit-test with a fake client (see the `_FakeOpenAI` pattern in `tests/test_judge_openai.py`).
5. Gate any real-API integration test on the relevant env var so CI without keys still passes.

## Cost discipline

LLM calls cost money. Defaults: cheap model (`gpt-4o-mini`), per-run call caps, deterministic pre-filters before any LLM call. Don't ship a feature that quietly makes O(N) LLM calls without a cap.

## Reporting a security issue

If you find a vulnerability in MCP-Strike itself (not in the demo server, where vulns are planted on purpose), please email the maintainer rather than opening a public issue. Coordinated disclosure preferred.

## License

By contributing, you agree your contributions are licensed under the same MIT terms as the project. See [`LICENSE`](LICENSE).
