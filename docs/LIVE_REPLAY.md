# Live replay: checking TxWarden against real historical swaps

<!-- BEGIN replay-status -->
**Real-chain results: NOT YET RUN.** No non-MOCK results file is committed under `results/`. Every number elsewhere in this README comes from synthetic data or from the in-memory fake node.
<!-- END replay-status -->

When this harness was written it had been built and tested against in-memory fakes only (a fake
archive node, also served over HTTP) and never run against a real Ethereum node. This page is the
walkthrough for doing that run yourself with a hosted mainnet endpoint, and for reading what comes
out.

The question the harness answers: on transactions that someone has labelled `sandwiched` or
`ordinary`, how often does the rule engine say WARN or BLOCK? It does not change the engine, it
does not tune any threshold, and it cannot say how much money a verdict would have saved.

## How a replay works

For each labelled hash `txwarden replay`:

1. fetches the transaction (`eth_getTransactionByHash`): sender, `to`, calldata, value, chain id
   and the block `N` it was mined in;
2. decides whether it is a swap the decoder knows. If not, the case is recorded as `unsupported`
   and costs one request;
3. simulates it with `AnvilSimulator(block=N-1)`: every state read (`eth_call`,
   `eth_estimateGas`, `eth_getCode`, `eth_getBalance`, `eth_getTransactionCount`,
   `eth_getBlockByNumber`, `eth_simulateV1`, `debug_traceCall`) is made against the state at the
   end of block `N-1`;
4. runs the normal `assess` with your policy and appends one JSON line to the results file.

**Why N-1, and what it costs.** The state at the end of block `N-1` approximates what a wallet saw
when the user signed: any front-run sits inside block `N` and is invisible there. It is only an
approximation. Transactions that came *before* the victim inside block `N` (other swaps on the
same pool, an approval the victim relied on, the attacker's own front-run) have not happened in
that snapshot, so **intra-block ordering effects are not reproduced**. A transaction that depended
on them may revert at the pinned block (recorded as `unsupported`, reason `reverts_at_pin`) or
price differently from how it really executed.

## What you need

* A mainnet endpoint whose plan serves **archive state**. State older than roughly the most recent
  128 blocks is archive state, and every case in a historical replay is older than that, so a
  full (non-archive) plan answers `missing trie node` or similar. The harness reports that as
  `archive_state_unavailable`.
* `debug_traceCall` and `eth_simulateV1` are optional. Without them the call-tree and honeypot
  checks are skipped (`degraded` in each result line says which) and the swap and sandwich rules
  still run. The harness asks a node once per run and remembers a "method not found" answer.
* A case file you supply (below). This repository ships no transaction hashes.

## Step by step

### 1. Create the endpoint and check the plan

In the Chainstack console create an Ethereum **Mainnet** node and copy its HTTPS endpoint. Before
you spend anything, confirm on the plan page that it includes archive state for old blocks and
`debug_traceCall`. (Both requirements are stated from the provider's documentation as relayed to
whoever wrote this harness; they were not re-read from the environment it was built in. Treat
the console as the authority.)

### 2. Put the full URL in an environment variable

The URL contains your API key. The harness reads it from one environment variable and from
nowhere else: there is no `--rpc` flag on `replay`, and a URL typed on the command line is
refused without being repeated.

```bash
read -rs TXWARDEN_LIVE_RPC && export TXWARDEN_LIVE_RPC     # paste the URL, press Enter; nothing is shown
```

Do not write it into a file, a script, a `.env` that is committed, a CI log or a command line (shell
history and `ps` would keep it). To use another variable name: `--rpc-env NAME`. The tool never
prints the URL, the path or the query: messages, the results file, the cache and the report name
at most `scheme://host`. If your provider puts the key in the **host name** instead of the path,
that host is what is shown on the terminal; do not share terminal output in that case.

If you run inside a restricted sandbox or container with an egress allow-list, the endpoint's host
(the part after `endpoint:` in the first lines of output) must be allow-listed or every request
fails with `cannot reach`.

### 3. Prepare the labelled cases

A CSV or JSONL file, one row per transaction.

| column | required | meaning |
|---|---|---|
| `tx_hash` | yes | `0x` followed by 64 hex characters |
| `label` | yes | `sandwiched` or `ordinary` |
| `source` | no | where the label came from (kept in the results) |
| `notes` | no | free text |

The loader rejects malformed hashes, duplicates (even across upper and lower case) and any other
label, lists every problem with its line number, and prints the count per label. Extra columns
are ignored. **The rows below are an EXAMPLE of the format with obviously fake hashes; they do not
exist on any chain:**

```csv
tx_hash,label,source,notes
0x0000000000000000000000000000000000000000000000000000000000000001,sandwiched,EXAMPLE,fake hash for illustration only
0x0000000000000000000000000000000000000000000000000000000000000002,ordinary,EXAMPLE,fake hash for illustration only
```

Where labelled cases can come from is for you to decide. Candidates to look at are the public
MEV-measurement sites and datasets ZeroMEV and EigenPhi, and datasets produced by
`mev-inspect`-style tooling. **None of these was checked from the environment this harness was built
in** (it has no network access), so nothing here claims anything about their coverage, accuracy,
licences or export formats, and no hashes are supplied. Check what a source actually labels
before you trust it.

Build the `ordinary` set deliberately. If sandwiched cases are all large trades on one router and
the ordinary cases are a random sample of everything, the two populations differ in more than the
attack and the comparison measures that difference. Sample ordinary swaps from the same period,
router and pool mix.

Check the file without touching the network:

```bash
txwarden replay cases.csv --validate-only
```

### 4. Calibrate with `--estimate`

```bash
txwarden replay cases.csv --estimate
```

Runs the first 3 cases, prints the requests and units each one took, a projection to the whole
file, and an upper bound, and writes no results file. A swap costs a dozen or more requests (the
transaction, the pool, account probes, the honeypot probe, the trace); a non-swap costs one. Three
cases is a rough guide, and the projection moves with your mix. The cost model's defaults are 1
unit per request, 2 for `debug_*`/`trace_*` requests, and 2 for state reads older than 128
blocks; a request that is both is priced as the sum of the surcharges (`--cost-combine max`
prices it as the larger). **Those figures come from the provider's documentation and must be
verified in the provider console**; change them with `--cost-per-call`, `--cost-debug-trace`,
`--cost-archive`, `--archive-window` and `--cost-combine`. If the estimate shows
`archive_state_unavailable`, stop: the plan cannot do historical replay.

### 5. Run with a budget

```bash
txwarden replay cases.csv --out results/replay.jsonl --budget-calls 5000
```

`--budget-calls N` stops cleanly *before* sending a request that would be the N+1st; `--budget-units
U` does the same for billing units. Retries after a 429 or 5xx count like any other request. When
the budget stops the run the case in progress is not recorded, and everything it already fetched
is in the cache. **Rerun the same command to resume:** hashes already in the output file are
skipped, so nothing is paid for twice. Related options: `--limit N` (at most N new cases this run),
`--rps` (default 10; the requests are spaced evenly), `--max-retries` (exponential backoff 1, 2,
4, ... up to 60 seconds, honouring `Retry-After`), `--retry-errors` (redo the cases recorded as
`error`, for example after upgrading the plan), `--max-consecutive-errors` (default 10: stop
rather than burn budget on a dead endpoint), `--config` (policy and simulator settings; set
`[simulator] honeypot = false` and `trace = false` to cut the cost per swap, at the price of
skipping those checks).

The on-disk cache (`--cache-dir`, default `.txwarden-replay-cache`) is keyed by method,
parameters and pinned block, holds no endpoint, and is per chain id. Rerunning costs nothing for
anything already fetched; `--no-cache` turns it off. Lookups that can change (an unknown or
pending transaction, `latest`) are never cached.

### 6. Produce the report

```bash
txwarden replay-report results/replay.jsonl --out results/replay-report.md
```

### 7. Commit the results

When you are satisfied, commit the results file under `results/` and run `make docs`. The
README's status line flips from "Real-chain results: NOT YET RUN" to the numbers the report
computes from that file, and a test keeps the two in agreement. Do not commit a file whose name or
header says MOCK. The results file contains the real hashes you labelled; that is intended, and it
is the one place they belong in this repository.

## What the report says, and refuses

* **Detection rate:** among `sandwiched` cases that were analysed, the share whose verdict is
  WARN or BLOCK (BLOCK alone is shown too). **False-positive rate:** the same on `ordinary` cases.
  Each has a 95% Wilson interval.
* **Denominators:** `unsupported` and `error` cases are counted per label and per reason and never
  as detected, missed, correct or wrong. A report on 200 cases of which 40 were analysable is a
  report on 40.
* **Per-rule hit counts** (a `*` marks rules that decided a verdict somewhere), **the list of
  missed sandwiched cases** (hash, block, rules that fired) and **the list of flagged ordinary
  cases**, so you can open the transactions and see why.
* **Refusals.** Results written against the in-repo fake node carry `mock` in their header and
  are refused unless `--allow-mock` (and then stamped MOCK in the title and file name). Fewer than
  30 analysable cases for either label is refused unless `--allow-small` (stamped SMALL SAMPLE).
  A file without a header is refused because it cannot be told apart from a fake.

## What the numbers do not show

* **Few cases.** Thirty analysable cases per label is a floor for printing a headline, not a
  sample large enough to be confident. Read the interval, not the point estimate.
* **Label noise.** Sandwich datasets have their own false positives and misses, and an unnoticed
  attack can sit among the "ordinary" cases. Label error moves both rates.
* **Selection bias.** Cases picked because they are notable are not a random sample of swaps, and
  only swaps the decoder recognises and the node could serve at the pinned block are analysed.
* **Block-boundary state.** State at the end of `N-1`, not the state the transaction saw inside
  block `N` (see above). The sandwich rules estimate what a swap *permits*; they do not observe
  what happened.
* **Any WARN or BLOCK counts as detection.** A swap flagged for an unrelated reason (a loose
  slippage setting, a fresh recipient) is a detection in these numbers. The per-rule table shows
  which rules did the work.
* **Defaults, not tuning.** Thresholds are the author's defaults; nothing was fitted to these
  cases. Do not tune them on the same file you report.

## Reading the files

Results are JSON Lines. The first line is the header (`"type": "header"`: `mock`, node client
version, chain id, head block, input file name and SHA-256, a hash of the policy and simulator
settings, the cost model), then one `"type": "case"` line per case, and a `"type": "run"` line each
time a run ends (`completed`, `limit`, `budget`, `errors`, `interrupted`, `aborted`). A hash that
appears twice (a retried error) counts as its last line.

A case line holds `tx_hash`, `label`, `status` (`analysed`, `unsupported` or `error`), `block`,
`pinned_block`, `verdict` (only when analysed), `rules` (every rule that fired), `alerting_rules`
(those that decide a verdict), `degraded` (checks that could not run), `reason_code` and `reason`
(when not analysed), `rpc_calls` (requests sent), `cache_hits`, `units`, `methods` and `elapsed_s`.

Reason codes:

<!-- BEGIN replay-reasons -->
| Code | Status | Meaning |
|---|---|---|
| `not_a_swap` | unsupported | The calldata is not a swap the decoder recognises: an approval, a transfer, an aggregator route or an unknown router. |
| `contract_creation` | unsupported | The transaction creates a contract, so there is no swap to analyse. |
| `pool_state_unavailable` | unsupported | The pool could not be found or priced at the pinned block: no pair, an unsupported route, or more than one swap in the transaction. |
| `reverts_at_pin` | unsupported | Simulated at the end of block N-1 the transaction reverts; it most likely depended on earlier transactions in block N. |
| `tx_not_found` | error | The endpoint does not know the hash: wrong chain, a mistyped hash, or a node that has pruned it. |
| `pending` | error | The transaction is not mined (the node reports no block number). |
| `bad_response` | error | The node's answer was not a transaction object the harness can read, or the block is 0. |
| `rpc_error` | error | An RPC call failed during the case (connection, HTTP 4xx/5xx other than 429, a node error). Even a failed optional probe invalidates the case. |
| `rate_limited` | error | The node kept answering 429 or a rate-limit error after all retries. |
| `archive_state_unavailable` | error | The node cannot serve state at the pinned block: the plan lacks archive access or the block is too old. |
| `engine_error` | error | The rule engine raised an error on this case. |
| `internal_error` | error | An unexpected exception in the harness; the text names it. |
<!-- END replay-reasons -->

## Options

<!-- BEGIN replay-options -->
| Option | Argument | Default | Meaning |
|---|---|---|---|
| `cases` (positional) |  |  | CSV or JSONL file with columns tx_hash, label (sandwiched\|ordinary), optional source, notes |
| `--format` | `{csv\|jsonl}` |  | case file format (default: from the file suffix or content) |
| `--out` | `PATH` | `replay_results.jsonl` | results JSONL; appended to and resumed |
| `--rpc-env` | `NAME` | `TXWARDEN_LIVE_RPC` | environment variable holding the endpoint URL |
| `--config` | `FILE` |  | TOML policy/simulator settings (its rpc_url is ignored) |
| `--cache-dir` | `DIR` | `.txwarden-replay-cache` | on-disk response cache |
| `--no-cache` |  |  | do not read or write the cache |
| `--limit` | `N` |  | analyse at most N not-yet-done cases in this run |
| `--rps` | `R` | `10.0` | requests per second ceiling |
| `--budget-calls` | `N` |  | stop cleanly before sending more than N RPC requests in this run |
| `--budget-units` | `U` |  | stop cleanly before spending more than U billing units in this run |
| `--cost-per-call` | `U` | `1.0` | units per request |
| `--cost-debug-trace` | `U` | `2.0` | units per debug_*/trace_* request |
| `--cost-archive` | `U` | `2.0` | units per state read older than the archive window |
| `--cost-combine` | `{sum\|max}` | `sum` | a request that is both debug/trace and archive is priced as the sum of the two surcharges (conservative) or the larger one |
| `--archive-window` | `BLOCKS` | `128` | state older than head minus this needs archive access |
| `--max-retries` | `N` | `5` | retries per request on HTTP 429/5xx, with exponential backoff |
| `--max-consecutive-errors` | `N` | `10` | stop after N cases in a row fail on the RPC; 0 never stops |
| `--retry-errors` |  |  | redo cases the results file records as error |
| `--estimate` |  |  | run the first 3 cases, print measured requests and the projected total, write no results |
| `--validate-only` |  |  | check the case file and print counts per label; no endpoint needed |
| `--mock` |  |  | stamp the results MOCK (done automatically for the in-repo fake node) |
| `--endpoint-label` | `TEXT` | `rpc endpoint` | how the results header names the endpoint (never the URL) |
<!-- END replay-options -->

`replay-report`:

<!-- BEGIN replay-report-options -->
| Option | Argument | Default | Meaning |
|---|---|---|---|
| `results` (positional) |  |  | results JSONL written by `txwarden replay` |
| `--allow-mock` |  |  | render results produced against the in-repo fake node (stamped MOCK) |
| `--allow-small` |  |  | render with fewer than 30 analysable cases per label (stamped SMALL SAMPLE) |
| `--json` |  |  | machine-readable output |
| `--out` | `PATH` |  | write the report here instead of stdout (MOCK / SMALL SAMPLE are added to the file name) |
<!-- END replay-report-options -->

Exit codes: `replay` returns 0 when it finished (or reached `--limit`), 4 when it stopped early
(budget, repeated RPC failures, interrupt) and 3 for input or configuration errors;
`replay-report` returns 0 or 3.

## What had and had not been verified when the harness was added

Verified, against an in-memory fake archive node (also served over real HTTP): block pinning of
every state request, the case loader, resume, `--limit`, budget stops, cache hits, rate limiting
and backoff with a fake clock, HTTP 429 and 5xx handling, unsupported and failed cases, secret
redaction (a fake key put in the URL never appears in output, results, cache files or exception
text), the Wilson interval against hand-computed values, and the report's refusal rules.

**Not verified:** anything against a real node. The response shapes of real clients (revert data,
tracer output, `eth_simulateV1`), the provider's actual pricing and rate limits, which plans serve
which methods, how often real V2/V3 swaps decode and price at the pinned block, and every
detection or false-positive figure. An opt-in smoke test (`TXWARDEN_LIVE_RPC` and
`TXWARDEN_LIVE_REPLAY_CASES` set, `pytest -m live`) exists for your first run; it has not been
run either.
