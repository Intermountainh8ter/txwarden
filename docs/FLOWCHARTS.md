# Flowcharts

Two diagrams: how to use TxWarden, and what to do when it does not do what you expected. The
sources are Mermaid files in `docs/diagrams/` (GitHub renders the blocks below); the SVGs next to
them are produced by `scripts/render_diagrams.sh` and embedded in the README.

## Using TxWarden: install, configure, run, read, act

![Usage flow](diagrams/usage.svg)

<details>
<summary>Mermaid source (docs/diagrams/usage.mmd)</summary>

<!-- BEGIN usage-mmd -->
```mermaid
flowchart TD
    A["1. Install from a checkout<br/>pip install -e .<br/>optional explanation agent: pip install -e '.[llm]'"]
    B["2. Configure txwarden.toml<br/>rpc_url, trusted_spenders, trusted_recipients,<br/>denylist, expected_chain_id"]
    C{"Fork RPC available?"}
    D["3a. Run with the chain<br/>txwarden review tx.json --config txwarden.toml --no-llm<br/>(several txs: txwarden batch bundle.json)"]
    D2["3b. Run statically, no RPC<br/>txwarden review tx.json --no-llm<br/>approvals, permits, transfers fully checked;<br/>swaps and liquidity removal come back WARN<br/>(ANALYSIS_INCOMPLETE)"]
    E["4. Read the verdict line and findings<br/>--json for scripts<br/>txwarden explain RULE for any finding"]
    F{"5. Exit code?"}
    G["0 = ALLOW<br/>Sign if the call matches what you meant to do.<br/>MEDIUM and INFO findings are notes, not stops."]
    H["2 and Verdict: WARN<br/>Understand every finding first. Fix the transaction, or add<br/>the address to trusted_* only after verifying it somewhere else."]
    I["2 and Verdict: BLOCK<br/>Do not sign. If you already signed something similar,<br/>revoke the allowance."]
    J["3 = input or config error<br/>Read the 'error:' line, then see the troubleshooting chart."]
    A --> B --> C
    C -- "yes, e.g. anvil --fork-url $ETH_RPC_URL" --> D
    C -- "no" --> D2
    D --> E
    D2 --> E
    E --> F
    F -- "0" --> G
    F -- "2, WARN" --> H
    F -- "2, BLOCK" --> I
    F -- "3" --> J
    classDef ok fill:#d8f3dc,stroke:#2d6a4f,color:#1b4332
    classDef warn fill:#fff3bf,stroke:#b08900,color:#5c4800
    classDef bad fill:#ffd6d6,stroke:#b00020,color:#5c0011
    classDef neutral fill:#e7f0fa,stroke:#3b6ea5,color:#12263f
    class G ok
    class H warn
    class I,J bad
    class A,B,C,D,D2,E,F neutral
```
<!-- END usage-mmd -->

</details>

Reading the exit code: **0** means ALLOW. **2** means WARN or BLOCK, so look at the `Verdict:` line
(or `"verdict"` in `--json`): BLOCK is "do not sign", WARN is "understand every finding first".
**3** means the input or configuration was wrong and nothing was reviewed.

## Troubleshooting: start from what you see

![Troubleshooting decision tree](diagrams/troubleshooting.svg)

<details>
<summary>Mermaid source (docs/diagrams/troubleshooting.mmd)</summary>

<!-- BEGIN troubleshooting-mmd -->
```mermaid
flowchart LR
    S{{"What do you see?"}}

    S --> A1["error: no fixture for calldata 0x..."]
    A1 --> A2["Fix: pass a SimResult JSON with a success field,<br/>or a table keyed by this exact calldata.<br/>Better: record a real session once with<br/>--rpc URL --record s.json, then --replay s.json"]

    S --> B1["Verdict: BLOCK<br/>SIMULATION_UNAVAILABLE"]
    B1 --> B2{"Message after it"}
    B2 -- "cannot reach ... Connection refused" --> B3["Fix: nothing is listening. Start anvil or correct --rpc / rpc_url.<br/>Test: curl -s -X POST URL --data eth_chainId"]
    B2 -- "HTTP 401, 403 or 429" --> B4["Fix: provider key missing or rate limit hit.<br/>Use another endpoint or your own node"]
    B2 -- "did not return JSON" --> B5["Fix: the URL is a web page, not a JSON-RPC endpoint.<br/>Use the node's RPC URL"]
    B2 -- "missing trie node or header not found" --> B6["Fix: the node has no state for that block.<br/>Use a fork at the latest block or an archive node"]
    B2 -- "no recorded response" --> B7["Fix: the --replay file was recorded for a different tx.<br/>Record again for this one"]

    S --> C1["Finding: REVERT<br/>Transaction reverts: reason"]
    C1 --> C2{"Reason"}
    C2 -- "EXPIRED" --> C3["Fix: the deadline has passed.<br/>Rebuild the transaction"]
    C2 -- "INSUFFICIENT_OUTPUT_AMOUNT, K, STF" --> C4["Fix: price moved or min_out is too tight for this block.<br/>Re-quote; check the fork block is recent"]
    C2 -- "TRANSFER_FROM_FAILED or exceeds allowance" --> C5["Fix: no balance or no prior approval.<br/>Review the approve and the swap together: txwarden batch"]
    C2 -- "no reason, or wrong network" --> C6["Fix: check chain_id, the fork block and that the sender<br/>is funded (anvil_setBalance)"]

    S --> D1["Verdict: WARN or BLOCK<br/>and you want to know why"]
    D1 --> D2["BLOCK = at least one CRITICAL finding: do not sign.<br/>WARN = at least one HIGH finding: understand it first.<br/>Run txwarden explain RULE for the cause and the policy knob.<br/>Do not disable a rule to silence it; trust an address<br/>only after verifying it out of band"]

    S --> E1["Warning: language model unavailable"]
    E1 --> E2{"Reason in brackets"}
    E2 -- "ANTHROPIC_API_KEY is not set" --> E3["Fix: export ANTHROPIC_API_KEY,<br/>or use --no-llm. The verdict is the same either way"]
    E2 -- "anthropic package is not installed" --> E4["Fix: pip install 'txwarden[llm]',<br/>or use --no-llm"]
    E2 -- "request failed" --> E5["Fix: check network and key validity.<br/>The deterministic verdict above it is still valid"]

    S --> F1["error: ... while loading config<br/>(exit code 3)"]
    F1 --> F2{"Message"}
    F2 -- "TOML syntax, line N column M" --> F3["Fix: correct the syntax at that line.<br/>Python 3.10 reads a TOML subset: use [tables],<br/>no inline tables or dotted keys"]
    F2 -- "unknown policy keys" --> F4["Fix: a knob name is misspelled.<br/>txwarden explain RULE lists the real names"]
    F2 -- "disabled_rules names unknown rules,<br/>or cannot be disabled" --> F5["Fix: use ids from txwarden rules.<br/>ENGINE_ERROR and SIMULATION_UNAVAILABLE are not disableable"]
    F2 -- "simulator: unknown keys" --> F6["Fix: allowed keys are the SimulatorOptions fields:<br/>honeypot, trace, account_probe, v3_ticks, ..."]

    S --> G1["MCP client: server disconnected,<br/>timeout or no tools"]
    G1 --> G2["Run it by hand:<br/>printf initialize-request | txwarden-mcp"]
    G2 --> G3{"Result"}
    G3 -- "command not found" --> G4["Fix: use the absolute interpreter in the client config:<br/>/path/to/venv/bin/python -m txwarden.mcp_server"]
    G3 -- "stderr: cannot load config" --> G5["Fix: correct the --config path or its contents;<br/>the server exits with code 3"]
    G3 -- "garbage on stdout" --> G6["Fix: stdout carries only JSON-RPC.<br/>Remove wrappers that print banners, or run python -u"]
    G3 -- "works by hand, fails in the client" --> G7["Fix: the client has a different PATH or venv.<br/>Pass --rpc and --config explicitly in its args"]
    G3 -- "tool result has isError true" --> G8["Not a handshake problem: the tx JSON was bad.<br/>The result still says verdict BLOCK"]

    S --> H1["WARN with ANALYSIS_INCOMPLETE<br/>on a swap"]
    H1 --> H2["Fix: no pool state without a chain.<br/>Pass --rpc to a fork so price impact,<br/>sandwich and honeypot rules can run"]

    classDef start fill:#e7f0fa,stroke:#3b6ea5,color:#12263f
    classDef symptom fill:#fff3bf,stroke:#b08900,color:#5c4800
    classDef fix fill:#d8f3dc,stroke:#2d6a4f,color:#1b4332
    class S start
    class A1,B1,C1,D1,E1,F1,G1,H1 symptom
    class A2,B3,B4,B5,B6,B7,C3,C4,C5,C6,D2,E3,E4,E5,F3,F4,F5,F6,G4,G5,G6,G7,G8,H2 fix
```
<!-- END troubleshooting-mmd -->

</details>

The symptoms are the real messages the tool prints. In plain text:

| What you see | Cause | Fix |
|---|---|---|
| `error: no fixture for calldata 0x...` | the `--fixture` file has no entry for this calldata, or is not a `SimResult` | give it a `SimResult` JSON with a `success` field, or a `{calldata: SimResult}` table; or record a real session with `--rpc URL --record s.json` and `--replay s.json` |
| `Verdict: BLOCK` with `SIMULATION_UNAVAILABLE`, `cannot reach ...` | nothing listens at the RPC URL | start the node (`anvil --fork-url ...`) or correct `--rpc` / `rpc_url`; test with `curl -s -X POST URL -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'` |
| `SIMULATION_UNAVAILABLE`, `HTTP 401/403/429` | provider key missing or rate limit | another endpoint or your own node |
| `SIMULATION_UNAVAILABLE`, `did not return JSON` | the URL is a web page, not a JSON-RPC endpoint | use the node's RPC URL |
| `SIMULATION_UNAVAILABLE`, `missing trie node` / `header not found` | the node has no state for that block | fork at the latest block or use an archive node |
| `SIMULATION_UNAVAILABLE`, `no recorded response` | the `--replay` file was recorded for a different transaction | record again |
| `REVERT` with `EXPIRED` | deadline passed | rebuild the transaction |
| `REVERT` with `INSUFFICIENT_OUTPUT_AMOUNT`, `K`, `STF` | price moved, or `min_out` is too tight at this block | re-quote; check the fork block |
| `REVERT` with `TRANSFER_FROM_FAILED` / allowance | no balance, or the approval is a separate transaction | review them together: `txwarden batch` |
| `REVERT` without a reason | wrong chain id, stale fork, unfunded sender | check `chain_id`, the fork block, `anvil_setBalance` |
| `Verdict: WARN` / `BLOCK`, why? | WARN = at least one HIGH finding, BLOCK = at least one CRITICAL | `txwarden explain RULE`; trust an address only after verifying it elsewhere; do not disable a rule to silence it |
| `ANALYSIS_INCOMPLETE` on a swap | no pool state without a chain | pass `--rpc` to a fork |
| `Warning: language model unavailable (ANTHROPIC_API_KEY is not set)` | no key | `export ANTHROPIC_API_KEY=...` or `--no-llm`; the verdict is identical |
| `... (the `anthropic` package is not installed ...)` | optional extra missing | `pip install 'txwarden[llm]'` or `--no-llm` |
| `error: ... unknown policy keys: [...]` | misspelled knob | `txwarden explain RULE` lists the real names |
| `error: ... disabled_rules names unknown rules` / `cannot be disabled` | typo, or a fail-closed rule | ids from `txwarden rules`; `ENGINE_ERROR` and `SIMULATION_UNAVAILABLE` stay on |
| `error: ... Invalid statement (at line N, column M)` | TOML syntax | fix that line; on Python 3.10 use `[tables]`, no inline tables or dotted keys |
| MCP client: disconnected, timeout, no tools | see below | run `printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n' \| txwarden-mcp` by hand |
| `txwarden-mcp: error: cannot load config` on stderr | bad `--config` | fix the path or the file; the server exits with code 3 |
| MCP works by hand, not in the client | the client's `PATH` or venv differs | use `/path/to/venv/bin/python -m txwarden.mcp_server` and pass `--rpc` / `--config` explicitly |
| MCP tool result has `isError: true` | the transaction JSON was bad (not a handshake problem) | the result still says `"verdict": "BLOCK"`; fix the input |
