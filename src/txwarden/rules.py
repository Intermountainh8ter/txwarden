"""The rule registry: every rule id with its fixed severity, description and operator docs.

This module is data only. ``risk.py`` registers the check functions that emit these ids and a test
asserts that every id here is emitted by exactly the checks that claim it, that every finding uses a
registered id, and that ``docs/RULES.md`` is regenerated from this registry (``scripts/gen_rules_doc.py``).

Severity decides the verdict: CRITICAL -> BLOCK, HIGH -> WARN, MEDIUM/INFO -> ALLOW (the finding is
still reported). Severities are fixed per rule so a rule id always means the same thing; behaviour
is tuned through ``PolicyConfig`` thresholds and trust lists, or a rule is switched off with
``disabled_rules``.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Severity, Verdict


def verdict_for_severity(sev: Severity) -> Verdict:
    if sev >= Severity.CRITICAL:
        return Verdict.BLOCK
    if sev >= Severity.HIGH:
        return Verdict.WARN
    return Verdict.ALLOW


@dataclass(frozen=True)
class RuleSpec:
    id: str
    severity: Severity
    category: str
    title: str
    description: str  # what fires it, precisely
    docs: str = ""  # why it matters, what to do, known false positives
    config: tuple[str, ...] = ()  # PolicyConfig fields that influence it

    @property
    def verdict(self) -> Verdict:
        return verdict_for_severity(self.severity)


RULES: dict[str, RuleSpec] = {}

CRIT, HIGH, MED, INFO = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO


def _r(id: str, sev: Severity, cat: str, title: str, desc: str, docs: str, *config: str) -> None:
    if id in RULES:
        raise ValueError(f"duplicate rule id {id}")
    RULES[id] = RuleSpec(id, sev, cat, title, desc, docs, tuple(config))


# --------------------------------------------------------------------------- target / environment

_r("DENYLISTED_TARGET", CRIT, "target", "Call to a denylisted contract",
   "The transaction's `to` address is on the user's denylist.",
   "Put known drainers, sanctioned addresses and contracts you were phished by on `denylist`. "
   "Do not sign; there is no benign reading of a call to an address you have already marked bad.",
   "denylist")
_r("ADDRESS_LOOKALIKE", CRIT, "target", "Address-poisoning lookalike",
   "A counterparty address (spender, operator, recipient or the call target) is not known to the "
   "user but shares its first `lookalike_prefix` and last `lookalike_suffix` hex characters with an "
   "address that is (trust lists, address book, the sender).",
   "Address poisoning sends dust from a vanity address that matches the start and end of an "
   "address you use, hoping you copy it from your history. Wallets show only those characters, so "
   "the two look identical. Compare the full address. A genuine second address of yours "
   "that happens to collide must be added to the address book to stop the finding.",
   "lookalike_prefix", "lookalike_suffix", "address_book", "trusted_spenders",
   "trusted_recipients")
_r("CHAIN_ID_MISMATCH", CRIT, "simulation", "Chain id mismatch",
   "The transaction's chain id differs from `expected_chain_id` in the policy or, when that is "
   "unset, from the chain the simulator is connected to.",
   "A signature produced for one chain can be replayed or mis-sent on another, and a simulation "
   "on the wrong chain says nothing about what will happen. Reconnect the simulator to the right "
   "network or fix the transaction's chain id.",
   "expected_chain_id")
_r("CALL_TO_NON_CONTRACT", HIGH, "target", "Calldata sent to an address with no code",
   "The transaction carries calldata but `to` has no deployed code (checked with eth_getCode).",
   "A call to an address without code always succeeds and does nothing, while any attached ETH is "
   "simply transferred. Typical causes: a wrong-network address, a mistyped contract, a "
   "contract that was self-destructed. Verify the address on the intended chain.",
   "flag_call_to_non_contract")

# --------------------------------------------------------------------------- approvals

_r("UNLIMITED_APPROVAL_UNKNOWN", CRIT, "approval", "Unlimited approval to unknown spender",
   "An ERC-20 or Permit2 approval of 2**128 raw units or more (larger than any real token's total "
   "supply, so effectively unlimited; covers uint256/uint160/uint128 maxima) to a spender that is "
   "not in `trusted_spenders`.",
   "This is the primary drainer primitive: once granted, the spender can move the whole balance "
   "at any time, including long after you have forgotten the site. Approve an exact amount instead "
   "or trust the spender explicitly after verifying it.",
   "trusted_spenders")
_r("APPROVAL_TO_DENYLISTED", CRIT, "approval", "Approval to denylisted spender",
   "Any approval whose spender is on the denylist.",
   "Do not sign. If you already did, revoke the allowance.", "denylist")
_r("APPROVAL_UNKNOWN_SPENDER", HIGH, "approval", "Bounded approval to unknown spender",
   "A finite, non-zero approval to a spender that is not in `trusted_spenders`.",
   "A bounded approval limits the loss to the amount, but the spender is still someone you have "
   "not vetted. Check the address against the dapp's documentation before signing.",
   "trusted_spenders")
_r("UNLIMITED_APPROVAL_TRUSTED", MED, "approval", "Unlimited approval to trusted spender",
   "Unlimited approval to an address in `trusted_spenders`.",
   "Reported so the explanation can mention it; the verdict stays ALLOW because you trusted the "
   "spender. Prefer exact approvals even for trusted spenders; a trusted contract can be upgraded.",
   "trusted_spenders")
_r("APPROVAL_REVOKED", INFO, "approval", "Approval set to zero",
   "An allowance is being set to zero.",
   "Revocations are safe and encouraged; reported for completeness.")

_r("OPERATOR_APPROVAL_UNKNOWN", CRIT, "operator", "setApprovalForAll to unknown operator",
   "`setApprovalForAll(operator, true)` on an ERC-721/1155 collection where the operator is not in "
   "`trusted_operators` or `trusted_spenders`.",
   "Grants the operator control of every token in the collection, now and in the future. This is "
   "how NFT drainers work, and there is no 'bounded' variant. Only approve marketplaces you chose "
   "to use, and revoke afterwards.",
   "trusted_operators", "trusted_spenders")
_r("OPERATOR_APPROVAL_DENYLISTED", CRIT, "operator", "setApprovalForAll to denylisted operator",
   "The operator of a `setApprovalForAll(…, true)` is on the denylist.",
   "Do not sign.", "denylist")
_r("OPERATOR_APPROVAL_TRUSTED", MED, "operator", "setApprovalForAll to trusted operator",
   "Collection-wide approval to an operator you trust (marketplace or aggregator).",
   "Allowed, but reported: a trusted marketplace can still be compromised or upgraded. Revoke when "
   "you stop trading.", "trusted_operators", "trusted_spenders")
_r("OPERATOR_APPROVAL_REVOKED", INFO, "operator", "Operator approval revoked",
   "`setApprovalForAll(operator, false)`.", "Safe; reported for completeness.")

# --------------------------------------------------------------------------- permits

_r("PERMIT_UNLIMITED_UNKNOWN", CRIT, "permit", "Unlimited permit to unknown spender",
   "An EIP-2612, DAI-style or Permit2 signature granting an unlimited allowance to a spender that "
   "is not trusted.",
   "Permits are gasless and happen off-chain, so a phishing page can collect one without any "
   "on-chain transaction and drain you later. Never sign an unlimited permit for a spender you did "
   "not verify.", "trusted_spenders")
_r("PERMIT_TO_DENYLISTED", CRIT, "permit", "Permit to denylisted spender",
   "A permit whose spender is on the denylist.", "Do not sign.", "denylist")
_r("PERMIT_UNKNOWN_SPENDER", HIGH, "permit", "Bounded permit to unknown spender",
   "A finite permit to a spender that is not trusted.",
   "The loss is bounded by the amount, but a signature cannot be revoked by an on-chain "
   "transaction until it has been used or expired (except by bumping the nonce).",
   "trusted_spenders")
_r("PERMIT_FAR_DEADLINE", HIGH, "permit", "Permit or allowance valid for a very long time",
   "A permit's deadline, or a Permit2 allowance's expiration, is more than "
   "`permit_deadline_warn_s` after the block time (default 30 days) or effectively never expires.",
   "Long-lived signatures get harvested and replayed later, often after the site that asked for "
   "them is compromised. Ask for a short deadline.", "permit_deadline_warn_s")
_r("PERMIT_UNLIMITED_TRUSTED", MED, "permit", "Unlimited permit to trusted spender",
   "An unlimited permit to a trusted spender.",
   "Allowed, but reported; prefer exact amounts.", "trusted_spenders")

# --------------------------------------------------------------------------- transfers

_r("TRANSFER_TO_DENYLISTED", CRIT, "transfer", "Transfer to denylisted address",
   "Funds are sent to an address on the denylist.", "Do not sign.", "denylist")
_r("NEAR_FULL_BALANCE_TO_NEW_ADDRESS", HIGH, "transfer", "Near-full balance to unrecognised address",
   "At least `drain_fraction` (default 90%) of the sender's balance of the token goes to an "
   "address that is not in `trusted_recipients` or the address book.",
   "Emptying a wallet into an address you have never used is what a drain looks like. If it is a "
   "deliberate migration, add the destination to `trusted_recipients` first.",
   "drain_fraction", "trusted_recipients")
_r("TRANSFER_TO_FRESH_ADDRESS", HIGH, "transfer", "Transfer to a never-used address",
   "The recipient has no code, nonce 0 and zero ETH balance.",
   "Fresh addresses are typical of poisoning and typo'd destinations; legitimate new wallets are "
   "usually funded first. Send a small test amount, or add the address to `trusted_recipients`.",
   "flag_fresh_recipients", "trusted_recipients")
_r("TRANSFER_TO_UNKNOWN_CONTRACT", MED, "transfer", "Token transfer to unknown contract",
   "Tokens (not ETH) are sent to a contract that is not in the address book.",
   "Tokens sent directly to a contract are often unrecoverable. Reported, not blocked, because "
   "deposits into vaults and bridges do this legitimately.", "flag_contract_recipients")
_r("TRANSFER_TO_TOKEN_CONTRACT", HIGH, "transfer", "Tokens sent to the token's own contract",
   "The recipient of a token transfer is the token contract itself.",
   "Almost no token can return tokens sent to its own address; the funds are lost. Usually a "
   "copy-paste of the wrong field in a wallet UI.")
_r("TRANSFER_TO_BURN_ADDRESS", HIGH, "transfer", "Transfer to the zero or dead address",
   "The recipient is 0x000…000 or 0x000…dEaD.",
   "Funds sent there are unrecoverable. Intentional burns are rare; confirm the intent.")
_r("SWAP_RECIPIENT_MISMATCH", HIGH, "transfer", "Swap or router output sent to a third party",
   "The recipient of a swap (`to`), of a Universal Router SWEEP/TRANSFER/PAY_PORTION/UNWRAP/WRAP, of "
   "added or removed V2 liquidity, or of an NFPM `collect` is not the sender, the router itself, a "
   "trusted recipient or a labelled address.",
   "A drainer can ask you to swap your own tokens and route the proceeds to the attacker, which "
   "looks like an ordinary swap in most wallet UIs. Swap UIs that route a fee portion to their own "
   "address also trip this; add that address to `trusted_recipients`.",
   "flag_swap_recipient_mismatch", "trusted_recipients", "address_book")

# --------------------------------------------------------------------------- swaps

_r("PRICE_IMPACT_EXTREME", CRIT, "swap", "Extreme price impact",
   "Execution price is at least `impact_block_bps` (default 20%) worse than the pool's spot price.",
   "The trade is moving the pool so much that most of the value is lost to the curve. Split it, "
   "use a deeper pool, or use a limit order.", "impact_block_bps")
_r("PRICE_IMPACT_HIGH", HIGH, "swap", "High price impact",
   "Price impact is at least `impact_warn_bps` (default 5%).",
   "A large share of the trade is paid to the curve rather than a fair price.", "impact_warn_bps")
_r("SLIPPAGE_TOLERANCE_EXTREME", CRIT, "swap", "Extreme slippage tolerance",
   "`min_out` is at least `slippage_block` (default 5%) below the simulated output.",
   "Anything between the simulated output and your floor can be taken by a searcher sandwiching "
   "the trade. Tighten the tolerance.", "slippage_block")
_r("SLIPPAGE_TOLERANCE_LOOSE", HIGH, "swap", "Loose slippage tolerance",
   "`min_out` is at least `slippage_warn` (default 0.75%) below the simulated output.",
   "A looser floor leaves room for MEV extraction; tighten it or use a private mempool.",
   "slippage_warn")
_r("SANDWICH_EXPOSURE_SEVERE", CRIT, "swap", "Severe sandwich exposure",
   "A searcher can extract at least `sandwich_block_bps` (default 1%) of the input by front- and "
   "back-running within the slippage floor, computed by optimising the front-run size on the "
   "pool curve (V2, multi-hop V2 and V3 with ticks).",
   "This is an estimate for a single-pool sandwich before gas and competition; real extraction "
   "can be lower (gas, competition) or higher (multi-block strategies). Tighten the floor or use "
   "a protected RPC.", "sandwich_block_bps")
_r("SANDWICH_EXPOSURE", HIGH, "swap", "Sandwich exposure",
   "The extractable amount is at least `sandwich_warn_bps` (default 0.3%).",
   "See SANDWICH_EXPOSURE_SEVERE.", "sandwich_warn_bps")
_r("LIQUIDITY_EXHAUSTED", CRIT, "swap", "Pool cannot fill the trade",
   "The Uniswap V3 pool runs out of in-range liquidity before the input is consumed "
   "(fill fraction below `min_fill_fraction`).",
   "The swap would revert or be partially filled. Reduce the size or route differently.",
   "min_fill_fraction")

# --------------------------------------------------------------------------- simulation health

_r("REVERT", HIGH, "simulation", "Transaction reverts in simulation",
   "The simulated call reverted (the revert reason is included when the node returns one).",
   "Signing a transaction that reverts wastes gas and may indicate the wrong network, stale "
   "parameters or a trap. Read the reason; do not sign until it simulates successfully.")
_r("ETH_REJECTED_BY_CONTRACT", HIGH, "simulation", "Contract rejects plain ETH",
   "The call reverts, ETH is attached, and the target also reverts on a plain value transfer.",
   "The contract has no payable receive/fallback, so the attached ETH cannot be accepted. Send "
   "the ETH through a function that accepts it, or to a different address.")
_r("GAS_EXTREME", CRIT, "simulation", "Extreme gas usage",
   "Estimated gas exceeds `gas_block_absolute` (default 10,000,000).",
   "Looping drainers and griefing contracts burn gas to extract value from the signer. Legitimate "
   "wallet interactions almost never approach this.", "gas_block_absolute")
_r("GAS_ABNORMAL", HIGH, "simulation", "Abnormal gas usage",
   "Estimated gas exceeds `gas_abnormal_multiple` (default 5x) times the typical cost of this "
   "kind of call (table in `risk.TYPICAL_GAS`, 250k for unrecognised calls).",
   "A simple approval that costs 900k gas is doing something else. Investigate with a trace.",
   "gas_abnormal_multiple")
_r("SIMULATION_UNAVAILABLE", CRIT, "simulation", "Simulation could not be performed",
   "The simulator reported an infrastructure error (RPC unreachable, timeout, HTTP error, "
   "malformed response, pruned state).",
   "TxWarden fails closed: with no analysis there is nothing to base ALLOW on. Fix connectivity "
   "(see the troubleshooting guide), then re-run.")
_r("ANALYSIS_INCOMPLETE", HIGH, "simulation", "Swap or liquidity analysis could not run",
   "The call is a swap or liquidity removal but the pool state needed to evaluate price impact, "
   "sandwich exposure or the removed share was not available (no RPC configured, pool not found, "
   "or an unsupported route such as a multi-hop V3 path).",
   "The rules that would have checked this trade could not run, so the result is WARN rather than "
   "ALLOW. Configure an RPC, or disable the rule if you accept static-only review.")
_r("CHECKS_SKIPPED", INFO, "simulation", "Some optional checks did not run",
   "The simulator reported checks it could not perform (account probes, honeypot probe, call "
   "trace, or all chain-state checks in static mode).",
   "Transparency only: the verdict is computed from what was available. Use a node that supports "
   "`debug_traceCall` and `eth_simulateV1` for full coverage.")
_r("ENGINE_ERROR", CRIT, "simulation", "A rule check crashed",
   "An internal check raised an exception while evaluating this transaction.",
   "Fail closed: an engine fault must never turn into ALLOW. Please report it with the "
   "transaction and simulation JSON.")

# --------------------------------------------------------------------------- trace

_r("SELFDESTRUCT_IN_TRACE", CRIT, "trace", "SELFDESTRUCT in call tree",
   "The call tree contains a SELFDESTRUCT frame.",
   "Self-destructing contracts are used to hide code and sweep balances. Legitimate flows that "
   "touch user funds rarely need it.")
_r("DELEGATECALL_TO_UNKNOWN", CRIT, "trace", "Nested delegatecall to unknown code",
   "A contract below the top level delegatecalls into code that is not in the address book, "
   "`trusted_implementations` or `trusted_spenders`.",
   "Delegatecall runs foreign code against the caller's storage and balances. A drainer "
   "wrapped in a proxy uses it to hide the sweep logic. Add known libraries to "
   "`trusted_implementations`.", "flag_unknown_delegatecall", "trusted_implementations",
   "address_book")
_r("UNTRUSTED_PULL_IN_TRACE", HIGH, "trace", "Untrusted contract moves your tokens to a third party",
   "A transfer out of the sender's account (``transferFrom``, a Permit2 pull) is initiated by a "
   "contract that is not trusted or labelled, and its recipient is neither the sender, that "
   "contract, nor a known address. Found both in the decoded call and in the call tree "
   "(``debug_traceCall``), where opaque contracts hide it.",
   "This is how an 'airdrop claim' or 'verify wallet' contract empties an account using an "
   "allowance granted earlier. Unlabelled aggregators and vaults trip it too; add them to "
   "`trusted_spenders` once vetted.", "trusted_spenders", "trusted_recipients", "address_book")
_r("PROXY_DELEGATECALL_UNKNOWN_IMPL", MED, "trace", "Proxy delegates to unlabelled implementation",
   "The target itself delegatecalls to an implementation that is not labelled.",
   "Normal for upgradeable proxies; reported so the implementation can be reviewed.",
   "flag_unknown_delegatecall")
_r("CONTRACT_CREATION_IN_TRACE", HIGH, "trace", "Contract created during the call",
   "CREATE or CREATE2 inside a transaction.",
   "Fresh contracts can't be vetted by address. Expected for factories and account abstraction; "
   "unexpected for an approval or swap.", "flag_contract_creation")
_r("DENYLISTED_IN_TRACE", CRIT, "trace", "Denylisted address touched in call tree",
   "A frame below the top level calls a denylisted address.",
   "Do not sign; the transaction interacts with a known-bad address indirectly.", "denylist")

# --------------------------------------------------------------------------- honeypot

_r("HONEYPOT_SELL_REVERTS", CRIT, "honeypot", "Token can be bought but not sold",
   "The buy-then-sell probe succeeds on the buy and reverts on the sell, including the "
   "fee-on-transfer sell variant.",
   "Classic honeypot: the token lets you in and not out. Run on a node with `eth_simulateV1`; "
   "with only router quotes the probe cannot see transfer-restriction logic.")
_r("ROUND_TRIP_LOSS_SEVERE", CRIT, "honeypot", "Severe round-trip loss",
   "Buying then immediately selling loses at least `honeypot_loss_block` (default 25%) of the "
   "input.",
   "A transfer tax or rigged pool takes the difference. Ordinary round trips lose about twice the "
   "pool fee plus impact.", "honeypot_loss_block")
_r("ROUND_TRIP_LOSS", HIGH, "honeypot", "Round-trip loss (fee on transfer)",
   "The round trip loses at least `honeypot_loss_warn` (default 5%), more than fees and impact "
   "explain.", "Likely a fee-on-transfer token; the effective price is worse than quoted.",
   "honeypot_loss_warn")

# --------------------------------------------------------------------------- liquidity

_r("LP_REMOVAL_MAJORITY", CRIT, "liquidity", "Removes the majority of a pool's liquidity",
   "The call withdraws at least `lp_removal_block_fraction` (default 50%) of the pool.",
   "Rug pulls look like this. So does closing your own single-LP pool; if that is the case, "
   "disable the rule for this transaction.", "lp_removal_block_fraction")
_r("LP_REMOVAL_LARGE", HIGH, "liquidity", "Removes a large share of a pool's liquidity",
   "The call withdraws at least `lp_removal_warn_fraction` (default 20%) of the pool.",
   "Large removals precede or accompany rugs; check who holds the position.",
   "lp_removal_warn_fraction")

# --------------------------------------------------------------------------- bundles

_r("BUNDLE_APPROVE_THEN_PULL", CRIT, "bundle", "Approval then pull by the same unknown spender",
   "One transaction in the bundle approves (or permits) an unknown spender and a later one calls "
   "that spender, has it as the transferFrom operator, or has it in the call tree.",
   "Drainer flows split the approval from the pull so each step looks harmless in isolation. "
   "Review the bundle as a whole; do not sign.", "trusted_spenders")
_r("BUNDLE_ADD_THEN_REMOVE_LIQUIDITY", CRIT, "bundle", "Add then remove liquidity in one bundle",
   "Liquidity is added to and removed from the same pool within the bundle.",
   "Launch-and-rug choreography; also a pointless way to burn gas for a normal user.")
_r("BUNDLE_CUMULATIVE_DRAIN", HIGH, "bundle", "Bundle drains the balance cumulatively",
   "Individual transfers stay under `drain_fraction` but together they exceed it for a token.",
   "Splitting a drain into several smaller transfers evades the per-transaction check.",
   "drain_fraction")
_r("BUNDLE_MIXED_CHAIN_IDS", CRIT, "bundle", "Bundle mixes chain ids",
   "The transactions in the bundle target different chain ids.",
   "A bundle is one decision; mixed chains usually mean a mis-assembled or malicious request.")
