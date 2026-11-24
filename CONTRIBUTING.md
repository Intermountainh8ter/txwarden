# Contributing

Thanks for looking. TxWarden is small on purpose: a deterministic engine whose verdict a language
model cannot change. Contributions that keep that property are welcome; so are bug reports with a
transaction (calldata plus a recorded session if you can share one) that the engine got wrong.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"        # pytest, pytest-cov, ruff; no API key or network needed
make check                     # lint, tests with coverage, evals, injection eval, docs checks
```

Python 3.10 to 3.13 are supported and run in CI. Zero runtime dependencies is a design rule:
do not add one to `[project].dependencies`.

## The loop

| Command | What it does |
|---|---|
| `make lint` | `ruff check .` (rules are pinned in `pyproject.toml`, so results do not drift with ruff's defaults) |
| `make test` | everything under `tests/` except the opt-in live tests |
| `make cov` | the same with coverage; fails under 90% |
| `make evals` | the labelled eval set with the CI gates, dev and held-out |
| `make sweep` | threshold frontier (unsafe ALLOW vs over-BLOCK) |
| `make injection` | prompt-injection invariant; exits 1 if the verdict can be moved |
| `make docs` | regenerate `docs/RULES.md` and the generated README blocks |
| `make docs-check` | fail if those are stale (CI runs this) |
| `make diagrams` | re-render `docs/diagrams/*.mmd` to SVG (needs node) |

The README's numbers (test count, coverage, eval tables, sweeps, injection table, the CLI output)
are **generated**. Do not edit between the `<!-- BEGIN ... -->` markers; run `make docs` after
`make cov` and commit the result.

## Adding a rule

1. **Register it** in `src/txwarden/rules.py`: id (`UPPER_SNAKE`), severity, category, title, a
   precise description of what fires it, a `docs` paragraph (why it matters, what to do, known false
   positives), and the `PolicyConfig` fields that influence it. Severity decides the verdict:
   CRITICAL blocks, HIGH warns, MEDIUM/INFO only report.
2. **Emit it** from a check in `src/txwarden/risk.py` (`@check("RULE_ID", ...)`). Add a policy knob
   to `PolicyConfig` if it has a threshold or a switch; knobs must be listed in the registry entry.
3. **Test it** in `tests/test_rules.py`: add a scenario to `SCENARIOS` (or `BUNDLE_SCENARIOS`) and a
   test for each knob and each exemption. Meta-tests fail if a registered rule has no scenario, if a
   finding uses an unregistered id, or if a rule cannot be disabled.
4. **Evaluate it**: add a template to `evals/build_cases.py` with the verdict a careful reviewer
   would give, and the rule id in `EXPECT_RULES`. The label comes from the template, never from
   running the engine; do not import `txwarden` in the generator (a test enforces this). Then
   `make cases evals`.
5. **Document it**: `make docs`.

Rules that depend on chain data need a field on `SimResult` (see `incomplete`, `output_recipients`)
and both simulators must fill it; when the data is unavailable the simulator says so in
`SimResult.incomplete` instead of leaving the rule silent.

## Adding a selector or protocol

Add a row to `abi._REGISTRY_ROWS` (the signature is verified against Keccak-256 by a test), then
teach `effects.extract_effects` what it implies. Add an encode/decode test with hand-assembled
words if the layout is non-trivial (see the Universal Router `PERMIT2_PERMIT` golden vector).

## Tests: what we expect

* Fix the code or fix the test, but **do not loosen an assertion to make it pass**. Check the claim
  against the specification or the arithmetic first (two tests in this repo were wrong, and a real
  bug hid behind a third).
* Randomised tests use a seeded `random.Random` and put the case index and parameters in the
  assertion message. No flaky tests.
* Network access is never required. Anything that talks to a node goes through the in-memory
  `FakeChain` or the `tests/fake_rpc.py` HTTP server. Live tests live in `tests/test_live.py`, are
  marked `live`, and skip unless `TXWARDEN_LIVE_RPC` is set.
* Historical-state and replay tests use `tests/fake_history.py` (a fake archive node: one
  `FakeChain` per block, a transaction index, optional pruning, a fake clock) and
  `tests/replay_world.py` (labelled synthetic cases, one per outcome). Hashes in tests are
  `fake_hash(n)` (`0x000...0n`). Never put a real transaction hash or an endpoint URL in the
  repository (a test enforces the first); `docs/LIVE_REPLAY.md` has generated blocks, so run
  `make docs` after changing a replay option or reason code.
* Recorded sessions in `tests/fixtures/rpc_*.json` are derived data: `python -m tests.make_fixtures`.
  Trace fixtures (`trace_*.json`) are hand-written and say so.

## Style

Plain, typed, standard library only. Comments say why, not what. No placeholder code, no TODOs in
the tree: finish the slice you take. Commit messages explain the reason for the change.

## Reporting a vulnerability

If you find a way to make the engine return ALLOW for a transaction that should not be, or to make
the language model move the verdict, please report it privately to the maintainer (a private
security advisory on the hosting repository, if enabled) rather than in a public issue, and include
the transaction and simulation JSON.

## Publishing to PyPI

Maintainer steps. Nothing is published until you do them; the workflow in `.github/workflows/publish.yml`
only runs when a GitHub Release is published.

1. On pypi.org, add a *pending trusted publisher* for the project name `txwarden`: owner `Intermountainh8ter`,
   repository `txwarden`, workflow `publish.yml`, environment `pypi`. (No API token is needed or stored.)
2. In this repository's Settings, create an environment named `pypi` (optionally with required reviewers).
3. Make sure `version` in `pyproject.toml` is the version you want, and that CI is green on `main`.
4. Create a GitHub Release whose tag is `v<version>` (for example `v0.2.0`). The workflow builds the
   sdist and wheel, runs `twine check`, and uploads them.
5. A PyPI version can never be re-uploaded, so check the built files first with `python -m build`
   and `twine check dist/*`.
