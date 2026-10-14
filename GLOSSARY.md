# Glossary

Every abbreviation and piece of jargon used in this repository, in plain words.

## Verdicts and the engine

**ALLOW / WARN / BLOCK** — The three verdicts this tool returns for a
transaction: safe to send, send only if you understand the risk, and do not
send. Decided by fixed rules, not by the language model.

**engine-authoritative** — The design rule that makes this tool work: the
verdict comes from deterministic rules the AI cannot reach or override. The AI
writes the explanation; it does not decide the answer.

**fail-closed** — When something goes wrong, return the *restrictive* answer.
An attacker who disrupts the tool can cause a false BLOCK, never a false ALLOW.

**gray area** — Cases where reasonable reviewers disagree. This repo's lowest
accuracy band, and it says so rather than dropping them.

**right reason** — Whether the *rule that fired* was the expected one, not just
whether the verdict matched. A verdict can be right by accident; this measures
that it was not.

**rule** — One named deterministic check, e.g. unlimited approval to an unknown
spender.

**unsafe ALLOW / over-BLOCK / under-BLOCK** — Allowing something that should
have been flagged; blocking something a reviewer would have allowed; warning
where a reviewer would have blocked. The first is the dangerous one.

## Attacks

**injected directive** — An instruction hidden inside data the assistant reads —
calldata, a token name, an address label, a revert reason — intended to be
obeyed as if the user had said it.

**prompt injection** — The general name for that attack.

**vector** — Where the hidden instruction was planted (`user_intent`,
`calldata_bytes`, `token_name`, `address_label`, `revert_reason`,
`decoded_args`).

**attack script** — What the hidden instruction tried to achieve
(`force_verdict_arg`, `skip_assessment`, `spoof_lookup`, `kitchen_sink`, …).

## Ethereum terms

**approval** — Granting a contract permission to move your tokens. An unlimited
approval to an unknown contract is a common way funds are stolen.

**bundle** — Several transactions submitted to run together.

**calldata** — The raw encoded data of a transaction: which function, which
arguments.

**ERC** — A token or application standard on Ethereum. **ERC-20** is the
fungible-token standard, **ERC-721** the NFT standard.

**ETH / WETH** — Ether, the native currency; and Wrapped Ether, a token version
of it that behaves like an ERC-20.

**EIP — Ethereum Improvement Proposal** — A numbered specification document.

**honeypot** — A token designed so you can buy it but not sell it.

**LP — Liquidity Pool** — A pot of two tokens that traders swap against.

**NFT — Non-Fungible Token** — A token where each unit is distinct.

**permit / Permit2** — Signature-based approvals, which let a contract be
authorised without a separate transaction. Easy to sign without reading.

**revert reason** — The error message a failed transaction returns.

**RPC — Remote Procedure Call** — The network endpoint used to talk to a
blockchain node.

**sandwich** — An attack where someone trades just before and just after your
trade to profit from the price move they caused.

**simulation / trace** — Running a transaction without sending it, to see what
it would do.

**slippage** — How far the price may move against you before a trade is
cancelled.

**swap / swap path** — Exchanging one token for another, and the route of pools
it goes through. **v2** and **v3** are Uniswap versions with different maths.

## Evaluation

**accuracy** — The share of cases where the verdict matched the expected one.

**confusion matrix** — A table of expected verdict against returned verdict, so
you can see *which* mistakes happen, not just how many.

**dev / held-out split** — Cases used while developing, and cases kept back and
scored once. Thresholds are chosen on dev only.

**precision / recall** — Of the things we blocked, how many deserved it; and of
the things that deserved blocking, how many we caught.

**sweep** — Re-running the whole evaluation across a range of threshold values
to see whether the threshold matters. Here, mostly, it does not.

## Machine learning and systems

**AI / LLM — Large Language Model** — The kind of AI that predicts text.

**CI — Continuous Integration** — The automated checks on every change.

**CLI — Command-Line Interface** — The terminal commands this tool provides.

**FAQ** — Frequently Asked Questions.

**HTTP** — The protocol web requests use.

**JSON / JSONL / TOML** — Structured record format; one record per line; and a
configuration file format.

**MCP — Model Context Protocol** — A standard way to expose tools to an AI
assistant. `txwarden-mcp` is this repo's server.

**MIT** — The permissive open-source licence this repo uses.

**SDK — Software Development Kit** — A library for building on this tool.

**SVG** — A vector image format, used for the diagrams in `docs/`.
