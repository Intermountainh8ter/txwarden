# TxWarden

Pre-signature transaction reviewer for Ethereum. An LLM agent orchestrates a fork simulation and a
**deterministic** risk engine, then explains the result in plain language. The model cannot approve
or downgrade a verdict, and the agent fails closed if the model skips the assessment.

```
user intent + tx ──► agent (LLM, tool use)
                       ├─ simulate_transaction ─► Simulator (Anvil fork eth_call | fixtures)
                       └─ assess_risk ──────────► risk engine (rules + AMM sandwich math)
                                                    └─► ALLOW | WARN | BLOCK   (LLM cannot override)
```

## Design decisions

- **Verdict is code, not prose.** The LLM explains; `risk.assess()` decides. Prompt injection in
  calldata or token metadata cannot talk the guard into approving. Tested in
  `tests/test_agent.py` (model says "go ahead", verdict stays BLOCK).
- **Fail closed.** No assessment recorded -> BLOCK.
- **Sandwich exposure is computed, not guessed.** `amm.estimate_sandwich` bisects for the largest
  front-run that still lets the victim clear `min_out` on a constant-product pool, then prices the
  attacker's round trip including fees.
- **Zero runtime dependencies.** The Anthropic SDK is an optional extra (`pip install .[llm]`);
  tests and evals use a scripted LLM and fixtures, so CI needs no API key.

## Rules

| Rule | Severity |
|---|---|
| Unlimited approval to unknown spender / denylisted spender or target | CRITICAL -> BLOCK |
| Slippage tolerance >= 5%, price impact >= 20%, sandwich extraction >= 100 bps | CRITICAL -> BLOCK |
| Bounded approval to unknown spender, tolerance >= 0.75%, impact >= 5%, extraction >= 30 bps, >= 90% of balance to a new address, revert | HIGH -> WARN |
| Unlimited approval to trusted spender | MEDIUM (noted, ALLOW) |

## Eval

```
python evals/build_cases.py > evals/cases.jsonl   # seeded, reproducible
python evals/run_evals.py --show-errors
```

Current result on 122 synthetic labelled cases: **accuracy 0.984, BLOCK precision 1.000, BLOCK
recall 0.958, unsafe ALLOW 0**. The two misses are boundary cases (slippage between 3% and 5%
that the labeller called BLOCK and the engine calls WARN).

What this does and does not show:
- The set is **synthetic**. Labels come from scenario templates, not from running the engine, but
  the same author wrote both, so treat the number as a regression guard, not real-world accuracy.
- The first run scored 0.781. It exposed that loose slippage on small trades in deep pools is *not*
  profitably sandwichable (attacker fees on the large front-run exceed the gain), so the sandwich
  rule alone never fired. I added the explicit slippage-tolerance rule rather than weakening the
  labels. Two label-generator bugs (ranges that didn't match their stated class) were also fixed
  after that run. Both changes are visible in git history if you keep the repo history.

## Limitations

- `AnvilSimulator` is unit-tested against a mocked JSON-RPC transport only. It has not been run
  against a live fork in this repo's CI. It decodes ERC-20 `approve`/`transfer` and Uniswap V2
  `swapExactTokensForTokens` calldata; other calls are checked for revert/gas only.
- Single-hop V2 pools only. No V3 concentrated liquidity, multi-hop paths, or private-mempool
  considerations.
- Allow/deny lists are user-supplied; there is no built-in threat intelligence feed.

## Usage

```
pip install -e ".[dev,llm]"
pytest -q
anvil --fork-url $ETH_RPC_URL &
txwarden tx.json --intent "swap 1 ETH for USDC" --trust-spender 0x7a25...488d
txwarden tx.json --no-llm     # deterministic findings only, no API key needed
```
`TXWARDEN_MODEL` overrides the model id.
