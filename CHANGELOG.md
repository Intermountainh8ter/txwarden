# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change behaviour).

## [Unreleased]

### Added
- **Block pinning.** `AnvilSimulator(block=...)` accepts `"latest"` (default, request bytes
  unchanged), an integer or a `0x` string and sends it with every state read (`eth_call`,
  `eth_estimateGas` when pinned, `eth_getBlockByNumber`, `eth_getCode`, `eth_getBalance`,
  `eth_getTransactionCount`, `eth_simulateV1`, `debug_traceCall`). To replay a transaction mined in
  block `N`, pin to `N - 1`; intra-block ordering effects are not reproduced.
- **Historical replay harness.** `txwarden replay CASES` reads labelled (`sandwiched` /
  `ordinary`) transaction hashes from a CSV or JSONL file, fetches each transaction, simulates it at
  the pinned block, assesses it and appends one line per case to a results file. Cases that cannot
  be analysed are recorded `unsupported` or `error` with a reason and never counted. Resume,
  `--limit`, a token-bucket `--rps`, exponential backoff on HTTP 429/5xx, an on-disk response cache,
  `--budget-calls` / `--budget-units` with configurable unit costs, and `--estimate`.
- `txwarden replay-report RESULTS.jsonl`: detection and false-positive rates with 95% Wilson
  intervals computed from the results file alone, denominators, per-rule hit counts, lists of missed
  and flagged cases; refuses MOCK results and fewer than 30 analysable cases per label unless
  `--allow-mock` / `--allow-small`, and stamps what it renders.
- The RPC URL for `replay` is read only from an environment variable (default
  `TXWARDEN_LIVE_RPC`, `--rpc-env NAME`); there is no `--rpc` flag, and the URL (path and query
  included) is kept out of output, results, cache files and exception text.
- `docs/LIVE_REPLAY.md`, a README section "Real-chain replay" whose status line is generated
  (it says "Real-chain results: NOT YET RUN" until a non-MOCK results file is under `results/`),
  generated option and reason-code tables, an opt-in live replay smoke test.
- Tests: a fake archive node (`tests/fake_history.py`), synthetic labelled replay cases and
  suites for pinning, the loader, the transport layers, the runner, secret redaction and the report.

### Changed
- `http_transport` errors name only `scheme://host` instead of the full URL (identical for URLs
  without a path), no longer quote a malformed URL, and carry `Retry-After` on `RpcError`.
- Pruned or non-archive nodes ("pruned", "state is not available", "unknown block", "block not
  found") are classified as infrastructure failures, never as reverts.

## [0.2.0] - 2026-10-14

### Added
- **55 rules** in a registry (`rules.py`) with description, "why it matters" text and policy knobs;
  `txwarden explain <RULE>`, `txwarden rules [--category --verdict --json --markdown]`, generated
  `docs/RULES.md`. New rules: `CALL_TO_NON_CONTRACT`, `SWAP_RECIPIENT_MISMATCH`,
  `UNTRUSTED_PULL_IN_TRACE`, `TRANSFER_TO_TOKEN_CONTRACT`, `TRANSFER_TO_BURN_ADDRESS`,
  `SIMULATION_UNAVAILABLE`, `ANALYSIS_INCOMPLETE`, `CHECKS_SKIPPED`, `ENGINE_ERROR`; Permit2
  allowance expiry is checked with `PERMIT_FAR_DEADLINE`.
- Generic ABI codec and calldata decoder (`abi.py`): static and dynamic types, nested tuples and
  arrays, 67 selectors, Universal Router commands (including sub-plans), multicall and
  Multicall3, pure-Python Keccak-256 and EIP-55 (`keccak.py`).
- Uniswap V3 concentrated-liquidity swap math with tick crossing (`amm_v3.py`) and multi-hop V2
  routes; one profit-maximising sandwich optimiser shared by all three pool models.
- `StaticSimulator` (review without an RPC), `RecordingTransport` / replay, and
  `txwarden review --record/--replay`.
- Bundle review (`txwarden batch`): approve-then-pull, add-then-remove liquidity, cumulative
  drain, mixed chain ids.
- Address book (about 30 mainnet entries), address-poisoning lookalike check, TOML configuration
  (`tomllib` on 3.11+, built-in subset parser on 3.10).
- MCP server over stdio without an SDK (`txwarden mcp`, `txwarden-mcp`).
- Call-tree analysis: delegatecall, selfdestruct, create, denylist, and token pulls out of the
  sender's account found inside the tree.
- Evals: 2660 synthetic labelled cases in 92 categories with a dev/held-out split, banded
  gray-area categories, expected rule ids, threshold sweeps (`--sweep`), CI gates, and a
  prompt-injection evaluation against a model that obeys every injected instruction.
- Tests: from 24 to several hundred, with seeded randomised invariants, an HTTP JSON-RPC server
  for the real transport path and subprocess tests for the CLI and MCP server (exact counts and
  coverage are in the README, generated from a real run).
- Docs: architecture, threat model, rule reference, usage and troubleshooting flowcharts, launch
  copy and FAQ. Makefile, Dockerfile, pre-commit config, CI on Python 3.10-3.13.

### Changed
- Fail closed throughout: an unreachable RPC or unsupported `eth_call` is BLOCK
  (`SIMULATION_UNAVAILABLE`, previously reported as a revert); a crashing rule is BLOCK
  (`ENGINE_ERROR`); swaps and liquidity removals that cannot be priced are WARN
  (`ANALYSIS_INCOMPLETE`). `disabled_rules` rejects unknown ids and fail-closed rules.
- An allowance of 2^128 or more is "unlimited" (was 2^255 or the uint160 maximum for Permit2).
- Revoking an allowance (or signing a zero-value permit) is never a finding about the spender,
  even a denylisted one.
- The agent keeps every finding behind its verdict when the model re-simulates.
- The CLI keeps working when the language model is unavailable: it prints the deterministic
  verdict and says why there is no explanation.
- Sandwich estimation for V3 and multi-hop routes now maximises profit like the single-hop case
  instead of using the largest feasible front-run.
- `ruff` rule selection is pinned in `pyproject.toml`.

### Fixed
- Fallback TOML parser mis-counted brackets inside strings (found by a randomised test).
- Universal Router `PAY_PORTION` was recorded as a transfer of `bips` tokens.
- V3 output formulas lost about 1e-7 of precision on tiny trades (cancellation).
- `--fixture` errors said `error: 'success'`; they now name the missing calldata.
- Transaction input errors name the missing field or the malformed address.
- `txwarden-mcp` prints a config error on stderr and exits 3 instead of a traceback.

### Known limitations
See the README. In short: synthetic evals only, the live-node path has not been run against a real
node, transactions only (no EIP-712 review), and a fixed registry of known calldata.

## [0.1.0] - baseline

- LLM agent with a deterministic risk engine (approvals, transfers, constant-product swaps,
  sandwich estimate), fixture and Anvil simulators, 24 tests, 122 synthetic eval cases scoring
  accuracy 0.984 (BLOCK precision 1.000, recall 0.958, unsafe ALLOW 0).
