# Architecture

TxWarden is a pipeline of pure, separately testable stages. A language model may sit beside it as
an explainer, but nothing the model does is an input to the verdict.

```
   tx {sender,to,data,value,chain_id}
        |
        v
  +------------+    +--------------+    +-----------------+    +----------------------+
  |  abi.py    | -> | effects.py   | -> | simulator.py    | -> | risk.py              |
  | decode     |    | what the     |    | what the chain  |    | facts (AMM math)     |
  | calldata   |    | call asks    |    | says: revert,   |    | + 18 checks          |
  | (67 sels,  |    | for: approvals,   | gas, balances,  |    | -> findings          |
  |  UR cmds,  |    | permits,     |    | pool state,     |    | -> worst severity    |
  |  multicall)|    | transfers,   |    | accounts, trace,|    | -> ALLOW|WARN|BLOCK   |
  +------------+    | swaps, LP    |    | honeypot probe  |    +----------+-----------+
                    +--------------+    +-----------------+               |
                                                                          v
                                 batch.py (cross-tx rules)         cli.py / mcp_server.py / agent.py
```

## Modules

| Module | Role | Notes |
|---|---|---|
| `keccak.py` | Pure-Python Keccak-256, EIP-55 checksums | no dependency; tests check the permutation against `hashlib.sha3_256` |
| `abi.py` | ABI codec and calldata decoder | static/dynamic types, nested tuples and arrays; selector registry (67 selectors); Universal Router command table (31); never raises on hostile input (returns `kind="malformed"`) |
| `effects.py` | Static effects of a decoded call | approvals, operator approvals, permits, transfers, swap and liquidity intents, who receives output; `trace_transfers` finds token pulls inside a call tree |
| `models.py` | Plain dataclasses | `Tx`, `SimResult`, `Finding`, call frames; JSON round-trippable so simulations can be recorded and replayed |
| `simulator.py` | Backends | `AnvilSimulator` (JSON-RPC; `block=` pins every state read to a block), `FixtureSimulator` (tests/evals), `StaticSimulator` (no RPC); `RecordingTransport` / `replay_transport` for sessions; `http_transport` never puts the endpoint URL in a message |
| `amm.py`, `amm_v3.py` | Pool math | constant product (single and multi-hop) and Uniswap V3 with tick crossing; price impact; sandwich estimation (bisect the largest admissible front-run, then maximise profit) |
| `rules.py` | The rule registry | id, severity, category, description, operator docs, policy knobs. Data only |
| `risk.py` | The engine | `PolicyConfig`; `compute_facts` (expensive, policy independent); 18 check functions; `assess` |
| `batch.py` | Bundles | per-transaction assessment plus cross-transaction rules |
| `addressbook.py` | Labels and lookalikes | about 30 built-in mainnet entries; the prefix/suffix lookalike test |
| `config.py` | TOML configuration | `tomllib` on 3.11+, a small subset parser on 3.10 |
| `agent.py`, `llm.py` | Optional explainer | tool-using agent; `AnthropicLLM` is an optional extra, `ScriptedLLM` is the test double |
| `cli.py`, `mcp_server.py` | Interfaces | `txwarden ...`; MCP server over stdio without an SDK |
| `ruledocs.py` | Documentation generator | `txwarden explain`, `docs/RULES.md`, README rule table |
| `replay.py` | Historical replay | case-file loader (`tx_hash`, `label`), the runner (`txwarden replay`: transaction -> pinned simulation -> verdict -> one results line), results files, reason codes |
| `replay_rpc.py` | Replay RPC plumbing | token-bucket rate limit, exponential backoff, per-request unit costs and budgets, on-disk cache keyed by (method, params, pinned block) |
| `replay_report.py` | Replay statistics | Wilson intervals, headline rates computed from a results file alone, the MOCK / small-sample refusals, the README status text |
| `redact.py` | Credential redaction | `redact_url` (scheme and host only) and `Redactor` (removes every piece of a known endpoint URL from text) |

## Data flow in one review

1. **Decode.** `abi.decode_call` turns calldata into a tree of `DecodedCall`s. Multicall,
   Multicall3 and Universal Router commands (including sub-plans) are expanded; nesting is capped.
2. **Effects.** `effects.extract_effects` maps each node to approvals, permits, transfers, swap
   intents (V2 single/multi-hop, V3 single/path, exact in/out), liquidity intents and the set of
   addresses that end up holding the output. This is *what the transaction asks for*.
3. **Simulate.** `AnvilSimulator` dry-runs the call (`eth_call`, `eth_estimateGas`), then enriches
   the result, each step optional: account probes (`eth_getCode`, nonce, balance), pool state for
   the first swap (V2 reserves, V3 `slot0`, liquidity and a bounded scan of initialised ticks), LP
   totals, the call tree (`debug_traceCall`, with `trace_transfers` adding token pulls from the
   sender's account), and a buy-then-sell honeypot probe (`eth_simulateV1`, falling back to router
   quotes). Anything unavailable is recorded in `SimResult.incomplete`, never guessed.
4. **Facts.** `risk.compute_facts` prices each swap once: clean output, tolerance, impact, and the
   best sandwich. Threshold sweeps in the evals re-run only the next step.
5. **Rules.** `risk.apply_rules` runs every registered check against a `PolicyConfig` and returns
   findings. A check that raises produces an `ENGINE_ERROR` finding.
6. **Verdict.** CRITICAL -> BLOCK, HIGH -> WARN, otherwise ALLOW; the worst finding decides.
7. **Bundles.** `batch.assess_bundle` does steps 1-6 per transaction, then looks across them
   (approve then pull, add then remove liquidity, cumulative drain, mixed chain ids).

## Historical replay

`txwarden replay` runs the same pipeline over labelled historical transactions, with one change:
the simulator is pinned (`AnvilSimulator(block=N-1)`) to the state at the end of the block before
the one that mined the transaction. For each case it reads the transaction from the node, skips
what the decoder cannot call a swap, simulates, assesses, and appends one line to a results file.

* **A case is analysed or it is not; it is never half counted.** Anything that stops a clean
  analysis (not a swap, no pool state, a revert at the pinned block, a missing transaction, any
  failed RPC call, even in an optional probe) is recorded as `unsupported` or `error` with a
  reason code and no verdict. The report counts only analysed cases in a rate and shows the rest as
  denominators.
* **Cost is controlled at the transport.** Every attempt, retries included, passes through the
  budget check, the token bucket and the counter; a response cache keyed by (method, params,
  pinned block) makes reruns free. `BudgetExceeded` is deliberately not a `RuntimeError` so the
  simulator's tolerance for failing optional probes cannot swallow it.
* **The endpoint URL is a secret.** It is read from an environment variable, shown only as
  `scheme://host`, and scrubbed from every message, result and cache file; `http_transport`
  already names only the host in its errors.
* **MOCK is a property of the data.** The in-repo fake node announces itself in
  `web3_clientVersion`; results from it are stamped MOCK in the header and the file name and the
  report refuses them.

The approximation is stated in the docs of `AnvilSimulator`: state at the end of block `N-1` does
not contain the attacker's front-run or anything else earlier in block `N`. See
[LIVE_REPLAY.md](LIVE_REPLAY.md).

## Trust boundaries

* **Trusted:** the code in `src/txwarden` except `agent.py`'s model call, and the user's policy.
* **Untrusted data:** everything from the chain or the request. Token names, revert reasons,
  labels, decoded strings and calldata are attacker-controlled. They are never parsed as
  instructions by the engine, and the agent wraps them in tool results that say so.
* **Untrusted model:** the verdict is the maximum over `assess()` results *recorded by the tool
  layer*. The two decision tools take no arguments (anything the model passes is ignored), the
  verdict is not read from the model's text, and a model that never calls `assess_risk` yields
  BLOCK. `review.model_contradicts_verdict` flags an explanation that says "go ahead" over a BLOCK.
* **Trusted by assumption:** the RPC endpoint. A node that lies defeats the simulation.

## Fail-closed behaviour

| Situation | Result | Where |
|---|---|---|
| RPC unreachable, HTTP 4xx/5xx, non-JSON body, timeout, pruned state, `eth_call` unsupported | BLOCK `SIMULATION_UNAVAILABLE` | `simulator.RpcError.infrastructure`, `risk._unavailable` |
| A check function raises, or pool math chokes on hostile numbers | BLOCK `ENGINE_ERROR` | `risk.apply_rules`, `risk.assess` |
| Bundle analysis raises | BLOCK `ENGINE_ERROR` | `batch.assess_bundle` |
| Swap or liquidity removal that cannot be priced (static mode, pool not found, unsupported route, second swap) | WARN `ANALYSIS_INCOMPLETE` | simulators set `SimResult.incomplete` |
| Optional probes unavailable (trace, honeypot, account probes) | INFO `CHECKS_SKIPPED` | informational only |
| The model never calls `assess_risk`, or the tool errors | BLOCK | `agent.TxWardenAgent.review` |
| MCP tool raises | `isError: true` and `"verdict": "BLOCK"` | `mcp_server.call_tool` |
| Language model unavailable | deterministic verdict still printed, with a note | `cli.cmd_review` |
| Replay case that cannot be analysed (not a swap, no pool state, revert at the pinned block, any failed RPC call) | recorded `unsupported` / `error`, no verdict, excluded from every rate | `replay.Replayer.analyse` |
| Replay budget spent | stop before the request that would exceed it; the case in progress is not recorded | `replay_rpc.Budget`, `replay.Replayer._loop` |
| `disabled_rules` names an unknown rule or a fail-closed rule | configuration error | `PolicyConfig.__post_init__` |

The converse is also deliberate: a revert is a HIGH finding (WARN), not a BLOCK, because a
reverting transaction costs gas rather than funds.

## The AMM math

* **Constant product:** `out = dx*(1-f)*y / (x + dx*(1-f))`. Reserves include the fee, as in V2.
* **Uniswap V3:** within a tick range the pool is a constant-product curve on the virtual
  reserves `L/sqrtP` and `L*sqrtP`; at an initialised tick `liquidityNet` is applied (negated when
  moving down) and the loop continues. Output uses cancellation-free forms. Partial fills are
  reported (`remaining`), which is what `LIQUIDITY_EXHAUSTED` reads.
* **Sandwich estimate:** the victim's output is decreasing in the attacker's front-run, so the
  largest admissible front-run is found by bisection; the attacker's profit is concave on a
  constant-product curve (piecewise smooth across V3 ticks), so a grid plus ternary search finds
  the best front-run. A trade whose own price push is below twice the fee is not sandwichable at
  any size, and is reported as such. The same optimiser serves V2, multi-hop and V3, and a test
  asserts they agree on equivalent pools.
* **Honest scope:** one pool, before gas and competition, single block. See
  [THREAT_MODEL.md](THREAT_MODEL.md).

## Extending it

* **A new rule:** register it in `rules.py` (id, severity, text, knobs), emit it from a check in
  `risk.py`, add a scenario to `tests/test_rules.py`, add an eval category and expected rule in
  `evals/build_cases.py`, then run `make docs`. A meta-test fails if any registered rule lacks a
  scenario or any emitted id is unregistered. [CONTRIBUTING.md](../CONTRIBUTING.md) has the
  checklist.
* **A new selector:** add a row to `abi._REGISTRY_ROWS`; a test recomputes every selector with
  Keccak-256 and checks the parameter count. Teach `effects.extract_effects` what it implies.
* **A new simulator:** implement `simulate(tx) -> SimResult`. The engine only reads `SimResult`.
* **A different model:** implement `llm.LLM.create`. The agent will not let it change the verdict.
