# Threat model

What TxWarden defends against, what it only partly covers, and what it does not touch. "Covered"
means a rule exists and is tested on synthetic scenarios; it does not mean the rule catches every
real instance (see the validation gap in the [README](../README.md#limitations)).

## Assets and assumptions

* **Asset:** tokens, NFTs and allowances held by the signing account, and the user's decision at
  the moment of signing.
* **The user's device and keys are not attacked.** A compromised wallet, host or browser can
  alter what is shown to the reviewer or skip the review: out of scope.
* **The RPC endpoint is trusted.** The simulation is only as honest as the node.
* **The policy is the user's.** Trust lists, the address book and the denylist are inputs.
  Social engineering a user into trusting an attacker's address defeats the corresponding rules.
* **Simulation approximates execution** at one block, with one transaction ordering.

## Attacker classes

| # | Attacker class | Typical move | Status | How, and the gap |
|---|---|---|---|---|
| 1 | Approval drainer | unlimited `approve` to an attacker contract, then pull later | **Covered** | `UNLIMITED_APPROVAL_UNKNOWN` (>= 2^128, covers uint256/uint160/uint128 maxima), `APPROVAL_UNKNOWN_SPENDER`, denylist. Gap: a spender you already trust that is later compromised |
| 2 | Permit phisher | gasless EIP-2612 / DAI / Permit2 signature | **Partly** | On-chain `permit` / Permit2 **calls** are decoded and judged (`PERMIT_*`). **Not covered:** the off-chain signature request itself (EIP-712 typed data) is never shown to TxWarden |
| 3 | NFT drainer | `setApprovalForAll` to an unknown operator | **Covered** | `OPERATOR_APPROVAL_*`. Gap: marketplaces you trust |
| 4 | Address poisoning | dust from a lookalike address so you copy the wrong one | **Partly** | `ADDRESS_LOOKALIKE` compares counterparties with your trust lists, address book and sender (first and last 4 hex characters, configurable). Gap: no transaction history, no threat feed; only fires if the real address is known to the policy |
| 5 | Wrong-destination mistakes | tokens sent to the token contract, the burn address, a never-used address, a code-less "contract" | **Covered** | `TRANSFER_TO_TOKEN_CONTRACT`, `TRANSFER_TO_BURN_ADDRESS`, `TRANSFER_TO_FRESH_ADDRESS`, `CALL_TO_NON_CONTRACT` |
| 6 | "Swap" with a hidden recipient | swap or sweep whose output goes to the attacker | **Covered** | `SWAP_RECIPIENT_MISMATCH` over V2/V3 `to`, Universal Router `SWEEP/TRANSFER/PAY_PORTION/UNWRAP/WRAP`, liquidity `to`, NFPM `collect`. False positives for UI fee recipients unless trusted |
| 7 | Opaque claim/airdrop contract | a call whose selector says nothing, which pulls your tokens using an old allowance | **Partly** | `UNTRUSTED_PULL_IN_TRACE` from the call tree (`transferFrom` out of your account), `DELEGATECALL_TO_UNKNOWN`, `SELFDESTRUCT_IN_TRACE`. Needs `debug_traceCall`. Gap: logic that steals in a later transaction; pulls expressed in forms the registry does not decode |
| 8 | Honeypot or rug token | buy works, sell reverts; punitive tax | **Partly** | `HONEYPOT_SELL_REVERTS`, `ROUND_TRIP_LOSS*` from a buy-then-sell probe. Gap: V2 router only; traps keyed on time, block number or address; tokens traded where no V2 pair exists |
| 9 | Liquidity rug | remove most of the pool | **Covered** | `LP_REMOVAL_*`, `BUNDLE_ADD_THEN_REMOVE_LIQUIDITY`. Closing your own pool legitimately looks the same |
| 10 | MEV searcher | sandwich a loose swap | **Partly** | slippage, impact and `SANDWICH_EXPOSURE*` from the pool math. Single pool, before gas and competition; no private-mempool advice; no JIT or back-run analysis |
| 11 | Bad execution (not an attack) | huge price impact, exhausted V3 range | **Covered** | `PRICE_IMPACT_*`, `LIQUIDITY_EXHAUSTED`. Only the first swap in a transaction is priced |
| 12 | Gas griefing | contract that burns gas | **Covered** | `GAS_ABNORMAL`, `GAS_EXTREME` (typical-cost table; coarse) |
| 13 | Split drains | approval and pull in separate transactions, or many small transfers | **Covered for bundles** | `BUNDLE_*` rules, only when the bundle is submitted together. Cross-session splits are invisible |
| 14 | Chain confusion | request built for another network | **Covered** | `CHAIN_ID_MISMATCH`, `BUNDLE_MIXED_CHAIN_IDS` |
| 15 | Prompt injection against the optional LLM | instructions in calldata, token names, labels, revert reasons | **Covered for the verdict**, not for the prose | verdict is code; see the [injection evaluation](../README.md#prompt-injection-evaluation). The explanation can still be wrong; an injected model can force a BLOCK (denial of service) |
| 16 | Simulation-aware contract | behaves differently when it detects a fork or dry run | **Not covered** | A contract can branch on `block.number`, `coinbase`, `tx.origin`, gas or a flag set between review and inclusion |
| 17 | Time-of-check/time-of-use | proxy upgraded, allowance or price changed after the review | **Not covered** | proxies are noted (MEDIUM), nothing re-checks at inclusion |
| 18 | Lying or compromised RPC | node returns a flattering simulation | **Not covered** | use a node you run; compare two providers |
| 19 | Compromised device, malicious extension, supply chain | tampering with TxWarden itself or what it reviews | **Out of scope** | |
| 20 | Social engineering the trust list | "add this address to trusted spenders" | **Out of scope** | the rules assume your lists are honest |
| 21 | Protocol-level exploits | a legitimate protocol is hacked, oracle manipulation, bridge failure | **Not covered** | |
| 22 | Cross-chain and bridge risk | | **Not covered** | |
| 23 | Unrecognised protocols | any contract whose calldata the registry does not know | **Weak** | judged only by simulation, gas, trace-derived pulls; most interactions with unknown protocols pass if they are well behaved |

## Why a deterministic engine, and what that does and does not buy

A language model is useful for explaining a finding and poor as a decision-maker under adversarial
input: the attacker controls the strings the model reads. So the verdict is a pure function of the
transaction, the simulation and the policy. That removes the model from the attack surface of the
*decision*; it does not make the rules right. A rule can be absent, wrong, or tuned badly. The
evals measure agreement with labels written by the same author, which is a regression guard, not
a detection rate.

## Fail-closed, and its cost

Missing or broken analysis is never ALLOW (see the table in
[ARCHITECTURE.md](ARCHITECTURE.md#fail-closed-behaviour)). The price is availability: an
unreachable RPC blocks everything, an unlabelled aggregator trips a warning, and an injected model
can force a BLOCK by refusing to run the engine. The CLI falls back to the deterministic verdict
when the language model is unavailable, so the model's failure never blocks a review.

## What would change the picture

Real transactions with labels (not synthetic), recorded sessions from real nodes across clients,
EIP-712 request review, log and state-diff based effects, simulation against multiple
orderings, and an address history source. None of these exist here. The first has a harness now
(`txwarden replay`, [LIVE_REPLAY.md](LIVE_REPLAY.md)) that has been tested only against fakes; it
replays each swap at the end of the previous block, so it cannot reproduce intra-block ordering,
and the labels, the case selection and the swaps it can decode all shape what it measures.
