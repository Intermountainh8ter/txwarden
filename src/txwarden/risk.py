"""Deterministic risk engine. The LLM never overrides the verdict computed here.

Structure:

- ``RULES`` is the registry: every rule id with its fixed severity, category, description and the
  ``PolicyConfig`` fields that influence it. ``docs/RULES.md`` and ``txwarden explain`` are
  generated from it, and a test asserts that every finding emitted anywhere uses a registered id.
- ``compute_facts`` does the expensive, policy-independent measurements (AMM simulation, sandwich
  bisection) once per transaction.
- ``apply_rules`` runs the cheap checks against a ``PolicyConfig``. Threshold sweeps in the evals
  re-run only this step.
- ``assess`` = facts + rules + verdict. CRITICAL -> BLOCK, HIGH -> WARN, otherwise ALLOW.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, fields
from typing import Any

from .addressbook import lookalike
from .amm import (
    amount_out,
    amount_out_path,
    estimate_sandwich,
    estimate_sandwich_path,
    price_impact_bps,
    price_impact_bps_path,
)
from .amm_v3 import V3Pool, estimate_sandwich_v3, price_impact_bps_v3, swap_exact_in
from .models import Finding, Severity, SimResult, Tx, Verdict

UNLIMITED = 2**255
PERMIT2_UNLIMITED = 2**160 - 1
FAR_FUTURE = 2**40  # a deadline past this is "effectively never expires" (year ~36812)
DAY = 86_400

# Typical gas for a call kind; used by the gas-griefing rule.
TYPICAL_GAS: dict[str, int] = {
    "empty": 21_000,
    "erc20_approve": 46_000,
    "erc20_transfer": 65_000,
    "erc20_transfer_from": 80_000,
    "erc20_permit": 80_000,
    "set_approval_for_all": 50_000,
    "erc721_safe_transfer_from": 90_000,
    "erc721_safe_transfer_from_data": 90_000,
    "erc1155_safe_transfer_from": 90_000,
    "permit2_permit": 70_000,
    "permit2_approve": 50_000,
    "permit2_permit_transfer_from": 110_000,
    "weth_deposit": 45_000,
    "weth_withdraw": 40_000,
    "v2_swap_exact_tokens_for_tokens": 160_000,
    "v2_swap_exact_eth_for_tokens": 150_000,
    "v2_swap_exact_tokens_for_eth": 170_000,
    "v3_exact_input_single": 180_000,
    "v3_exact_input": 260_000,
    "universal_router_execute": 300_000,
    "multicall": 400_000,
}
DEFAULT_TYPICAL_GAS = 250_000


# --------------------------------------------------------------------------- policy

@dataclass
class PolicyConfig:
    # trust lists
    trusted_spenders: set[str] = field(default_factory=set)
    trusted_recipients: set[str] = field(default_factory=set)
    denylist: set[str] = field(default_factory=set)
    trusted_operators: set[str] = field(default_factory=set)
    trusted_implementations: set[str] = field(default_factory=set)
    address_book: dict[str, str] = field(default_factory=dict)  # address -> label
    expected_chain_id: int | None = None
    # swaps
    sandwich_warn_bps: float = 30.0
    sandwich_block_bps: float = 100.0
    impact_warn_bps: float = 500.0
    impact_block_bps: float = 2000.0
    slippage_warn: float = 0.0075  # tolerance below the simulated output
    slippage_block: float = 0.05
    min_fill_fraction: float = 0.999  # V3: below this the pool cannot absorb the trade
    # transfers
    drain_fraction: float = 0.9
    flag_fresh_recipients: bool = True
    flag_contract_recipients: bool = True
    # permits
    permit_deadline_warn_s: int = 30 * DAY
    # lookalikes
    lookalike_prefix: int = 4
    lookalike_suffix: int = 4
    # honeypot / fee-on-transfer
    honeypot_loss_warn: float = 0.05
    honeypot_loss_block: float = 0.25
    # gas
    gas_abnormal_multiple: float = 5.0
    gas_block_absolute: int = 10_000_000
    # trace
    flag_unknown_delegatecall: bool = True
    flag_contract_creation: bool = True
    # liquidity removal
    lp_removal_warn_fraction: float = 0.2
    lp_removal_block_fraction: float = 0.5
    # rule switches
    disabled_rules: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        for name in ("trusted_spenders", "trusted_recipients", "denylist", "trusted_operators",
                     "trusted_implementations", "disabled_rules"):
            setattr(self, name, {str(a).lower() for a in getattr(self, name)})
        self.disabled_rules = {r.upper() for r in self.disabled_rules}
        self.address_book = {str(a).lower(): str(n) for a, n in self.address_book.items()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicyConfig:
        known = {f.name for f in fields(cls)}
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        kw: dict[str, Any] = {}
        for f in fields(cls):
            if f.name not in d:
                continue
            v = d[f.name]
            if f.name == "address_book":
                kw[f.name] = dict(v)
            elif f.default_factory is set:
                kw[f.name] = set(v)
            else:
                kw[f.name] = v
        return cls(**kw)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in fields(self):
            v = getattr(self, f.name)
            out[f.name] = sorted(v) if isinstance(v, set) else v
        return out

    def known_addresses(self, tx: Tx | None = None) -> set[str]:
        """Addresses the user recognises: trust lists, address book, their own account."""
        out = (self.trusted_spenders | self.trusted_recipients | self.trusted_operators
               | self.trusted_implementations | set(self.address_book))
        if tx is not None:
            out.add(tx.sender.lower())
        return out

    def is_trusted_spender(self, a: str) -> bool:
        return a.lower() in self.trusted_spenders

    def is_trusted_operator(self, a: str) -> bool:
        a = a.lower()
        return a in self.trusted_operators or a in self.trusted_spenders


# --------------------------------------------------------------------------- rule registry

@dataclass(frozen=True)
class RuleSpec:
    id: str
    severity: Severity
    category: str
    title: str
    description: str
    config: tuple[str, ...] = ()

    @property
    def verdict(self) -> Verdict:
        return verdict_for_severity(self.severity)


def verdict_for_severity(sev: Severity) -> Verdict:
    if sev >= Severity.CRITICAL:
        return Verdict.BLOCK
    if sev >= Severity.HIGH:
        return Verdict.WARN
    return Verdict.ALLOW


RULES: dict[str, RuleSpec] = {}
_CHECKS: list[tuple[str, tuple[str, ...], Callable[[RuleContext], None]]] = []


def _r(id: str, sev: Severity, cat: str, title: str, desc: str, *config: str) -> None:
    RULES[id] = RuleSpec(id, sev, cat, title, desc, tuple(config))


CRIT, HIGH, MED, INFO = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.INFO

_r("DENYLISTED_TARGET", CRIT, "target", "Call to a denylisted contract",
   "The transaction's `to` address is on the user's denylist.", "denylist")
_r("ADDRESS_LOOKALIKE", CRIT, "target", "Address-poisoning lookalike",
   "A counterparty address is not in the user's books but shares its leading and trailing hex "
   "characters with one that is (or with the sender). This is the signature of address-poisoning "
   "phishing, where a truncated wallet display makes the two indistinguishable.",
   "lookalike_prefix", "lookalike_suffix", "address_book", "trusted_spenders",
   "trusted_recipients")
_r("CHAIN_ID_MISMATCH", CRIT, "simulation", "Chain id mismatch",
   "The transaction's chain id differs from the chain the simulator is connected to, or from "
   "`expected_chain_id` in the policy. A signature meant for one chain must not be produced "
   "against another.", "expected_chain_id")

_r("UNLIMITED_APPROVAL_UNKNOWN", CRIT, "approval", "Unlimited approval to unknown spender",
   "An ERC-20 approval of 2**255 or more (or the uint160 maximum via Permit2) to a spender that is "
   "not in `trusted_spenders`. This is the primary drainer primitive.", "trusted_spenders")
_r("APPROVAL_TO_DENYLISTED", CRIT, "approval", "Approval to denylisted spender",
   "Any approval whose spender is on the denylist.", "denylist")
_r("APPROVAL_UNKNOWN_SPENDER", HIGH, "approval", "Bounded approval to unknown spender",
   "A finite approval to a spender that is not in `trusted_spenders`.", "trusted_spenders")
_r("UNLIMITED_APPROVAL_TRUSTED", MED, "approval", "Unlimited approval to trusted spender",
   "Noted for the explanation; does not change the verdict.", "trusted_spenders")
_r("APPROVAL_REVOKED", INFO, "approval", "Approval set to zero", "An allowance is being revoked.")

_r("OPERATOR_APPROVAL_UNKNOWN", CRIT, "operator", "setApprovalForAll to unknown operator",
   "Grants an operator control over every token of an ERC-721/1155 collection. Unknown "
   "operators are blocked outright; this is how NFT drainers work.", "trusted_operators",
   "trusted_spenders")
_r("OPERATOR_APPROVAL_DENYLISTED", CRIT, "operator", "setApprovalForAll to denylisted operator",
   "The operator is on the denylist.", "denylist")
_r("OPERATOR_APPROVAL_TRUSTED", MED, "operator", "setApprovalForAll to trusted operator",
   "Collection-wide approval to a marketplace or operator the user trusts.", "trusted_operators")
_r("OPERATOR_APPROVAL_REVOKED", INFO, "operator", "Operator approval revoked",
   "`setApprovalForAll(operator, false)`.")

_r("PERMIT_UNLIMITED_UNKNOWN", CRIT, "permit", "Unlimited permit to unknown spender",
   "An EIP-2612, DAI or Permit2 signature granting an unlimited allowance to an unknown spender. "
   "Permits are gasless and off-chain, so a phishing site can collect one without a transaction.",
   "trusted_spenders")
_r("PERMIT_TO_DENYLISTED", CRIT, "permit", "Permit to denylisted spender", "", "denylist")
_r("PERMIT_UNKNOWN_SPENDER", HIGH, "permit", "Bounded permit to unknown spender", "",
   "trusted_spenders")
_r("PERMIT_FAR_DEADLINE", HIGH, "permit", "Permit deadline far in the future",
   "The permit stays valid for longer than `permit_deadline_warn_s` (default 30 days) or never "
   "expires. Long-lived signatures are harvested and replayed later.", "permit_deadline_warn_s")
_r("PERMIT_UNLIMITED_TRUSTED", MED, "permit", "Unlimited permit to trusted spender", "",
   "trusted_spenders")

_r("TRANSFER_TO_DENYLISTED", CRIT, "transfer", "Transfer to denylisted address", "", "denylist")
_r("NEAR_FULL_BALANCE_TO_NEW_ADDRESS", HIGH, "transfer", "Near-full balance to unrecognised address",
   "At least `drain_fraction` of the sender's balance goes to an address that is not in "
   "`trusted_recipients` or the address book.", "drain_fraction", "trusted_recipients")
_r("TRANSFER_TO_FRESH_ADDRESS", HIGH, "transfer", "Transfer to a never-used address",
   "The recipient has no code, no nonce and no balance. Fresh addresses are typical of "
   "poisoning and typo'd destinations; legitimate new wallets are usually funded first.",
   "flag_fresh_recipients", "trusted_recipients")
_r("TRANSFER_TO_UNKNOWN_CONTRACT", MED, "transfer", "Token transfer to unknown contract",
   "Tokens sent directly to a contract that is not in the address book are often "
   "unrecoverable. Noted, not blocked.", "flag_contract_recipients")

_r("PRICE_IMPACT_EXTREME", CRIT, "swap", "Extreme price impact",
   "Execution price is at least `impact_block_bps` worse than spot.", "impact_block_bps")
_r("PRICE_IMPACT_HIGH", HIGH, "swap", "High price impact", "", "impact_warn_bps")
_r("SLIPPAGE_TOLERANCE_EXTREME", CRIT, "swap", "Extreme slippage tolerance",
   "`min_out` is at least `slippage_block` below the simulated output; anything in between can "
   "be taken by a sandwich.", "slippage_block")
_r("SLIPPAGE_TOLERANCE_LOOSE", HIGH, "swap", "Loose slippage tolerance", "", "slippage_warn")
_r("SANDWICH_EXPOSURE_SEVERE", CRIT, "swap", "Severe sandwich exposure",
   "A searcher can extract at least `sandwich_block_bps` of the input by front- and back-running "
   "within the slippage floor (computed by bisection on the pool curve).", "sandwich_block_bps")
_r("SANDWICH_EXPOSURE", HIGH, "swap", "Sandwich exposure", "", "sandwich_warn_bps")
_r("LIQUIDITY_EXHAUSTED", CRIT, "swap", "Pool cannot fill the trade",
   "The Uniswap V3 pool runs out of in-range liquidity before the input is consumed.",
   "min_fill_fraction")

_r("REVERT", HIGH, "simulation", "Transaction reverts in simulation", "")
_r("ETH_REJECTED_BY_CONTRACT", HIGH, "simulation", "Contract rejects plain ETH",
   "The call reverts and the target also reverts on a plain value transfer: it has no payable "
   "receive/fallback, so the attached ETH cannot be accepted.")
_r("GAS_EXTREME", CRIT, "simulation", "Extreme gas usage",
   "Estimated gas exceeds `gas_block_absolute`. Looping drainers and griefing contracts burn "
   "gas to extract value from the signer.", "gas_block_absolute")
_r("GAS_ABNORMAL", HIGH, "simulation", "Abnormal gas usage",
   "Estimated gas exceeds `gas_abnormal_multiple` times what this kind of call typically costs.",
   "gas_abnormal_multiple")

_r("SELFDESTRUCT_IN_TRACE", CRIT, "trace", "SELFDESTRUCT in call tree", "")
_r("DELEGATECALL_TO_UNKNOWN", CRIT, "trace", "Nested delegatecall to unknown code",
   "A contract below the top level delegatecalls into code that is not in the address book or "
   "`trusted_implementations`. Delegatecall runs foreign code with the caller's storage.",
   "flag_unknown_delegatecall", "trusted_implementations", "address_book")
_r("PROXY_DELEGATECALL_UNKNOWN_IMPL", MED, "trace", "Proxy delegates to unlabelled implementation",
   "The target itself delegatecalls to an implementation that is not labelled. Normal for "
   "proxies; noted so the implementation can be reviewed.", "flag_unknown_delegatecall")
_r("CONTRACT_CREATION_IN_TRACE", HIGH, "trace", "Contract created during the call",
   "CREATE/CREATE2 inside a transaction the user did not describe as a deployment.",
   "flag_contract_creation")
_r("DENYLISTED_IN_TRACE", CRIT, "trace", "Denylisted address touched in call tree", "", "denylist")

_r("HONEYPOT_SELL_REVERTS", CRIT, "honeypot", "Token can be bought but not sold",
   "The buy-then-sell probe succeeds on the buy and reverts on the sell, including the "
   "fee-on-transfer sell variant. Classic honeypot.")
_r("ROUND_TRIP_LOSS_SEVERE", CRIT, "honeypot", "Severe round-trip loss",
   "Buying then immediately selling loses at least `honeypot_loss_block` of the input: a "
   "transfer tax or rigged pool.", "honeypot_loss_block")
_r("ROUND_TRIP_LOSS", HIGH, "honeypot", "Round-trip loss (fee on transfer)",
   "Round trip loses at least `honeypot_loss_warn`, more than fees and impact explain.",
   "honeypot_loss_warn")

_r("LP_REMOVAL_MAJORITY", CRIT, "liquidity", "Removes the majority of a pool's liquidity",
   "The call withdraws at least `lp_removal_block_fraction` of the pool. Rug pulls look like "
   "this; so does closing your own single-LP pool, which a trusted recipient makes legitimate.",
   "lp_removal_block_fraction")
_r("LP_REMOVAL_LARGE", HIGH, "liquidity", "Removes a large share of a pool's liquidity", "",
   "lp_removal_warn_fraction")

_r("BUNDLE_APPROVE_THEN_PULL", CRIT, "bundle", "Approval then pull by the same unknown spender",
   "One transaction in the bundle approves an unknown spender and a later one calls that spender "
   "or lets it transferFrom the user. Drainer flows split the approval from the pull so each "
   "step looks harmless.", "trusted_spenders")
_r("BUNDLE_ADD_THEN_REMOVE_LIQUIDITY", CRIT, "bundle", "Add then remove liquidity in one bundle",
   "Liquidity is added and withdrawn from the same pool within the bundle: launch-and-rug.")
_r("BUNDLE_CUMULATIVE_DRAIN", HIGH, "bundle", "Bundle drains the balance cumulatively",
   "Individual transfers stay under `drain_fraction` but together they exceed it.",
   "drain_fraction")
_r("BUNDLE_MIXED_CHAIN_IDS", CRIT, "bundle", "Bundle mixes chain ids", "")


def check(*rule_ids: str):
    """Register a check function that may emit the listed rule ids."""
    for r in rule_ids:
        if r not in RULES:
            raise KeyError(f"check references unregistered rule {r}")

    def deco(fn: Callable[[RuleContext], None]):
        _CHECKS.append((fn.__name__, rule_ids, fn))
        return fn

    return deco


# --------------------------------------------------------------------------- facts

@dataclass(frozen=True)
class SwapMetrics:
    kind: str  # v2 | v2_path | v3
    amount_in: float
    min_out: float
    clean_out: float
    tolerance: float
    impact_bps: float
    sandwich_feasible: bool
    sandwich_bps: float
    sandwich_profit: float
    sandwich_frontrun: float
    fill_fraction: float = 1.0
    ticks_crossed: int = 0


@dataclass
class Facts:
    swaps: list[SwapMetrics] = field(default_factory=list)


def _tolerance(min_out: float, clean: float) -> float:
    return max(0.0, 1.0 - min_out / clean) if clean > 0 else 0.0


def compute_facts(tx: Tx, sim: SimResult) -> Facts:
    facts = Facts()
    if not sim.success:
        return facts
    if sim.swap:
        s = sim.swap
        clean = amount_out(s.amount_in, s.reserve_in, s.reserve_out, s.fee)
        est = estimate_sandwich(s)
        facts.swaps.append(SwapMetrics(
            "v2", s.amount_in, s.min_out, clean, _tolerance(s.min_out, clean),
            price_impact_bps(s), est.feasible,
            est.attacker_profit / s.amount_in * 1e4 if s.amount_in > 0 else 0.0,
            est.attacker_profit, est.attacker_frontrun))
    if sim.path_swap:
        p = sim.path_swap
        clean = amount_out_path(p.amount_in, p.hops)
        est = estimate_sandwich_path(p)
        facts.swaps.append(SwapMetrics(
            "v2_path", p.amount_in, p.min_out, clean, _tolerance(p.min_out, clean),
            price_impact_bps_path(p), est.feasible,
            est.attacker_profit / p.amount_in * 1e4 if p.amount_in > 0 else 0.0,
            est.attacker_profit, est.attacker_frontrun))
    if sim.swap_v3:
        v = sim.swap_v3
        res = swap_exact_in(V3Pool.from_swap(v), v.amount_in, v.zero_for_one)
        clean = res.amount_out
        est = estimate_sandwich_v3(v)
        fill = res.amount_in_consumed / v.amount_in if v.amount_in > 0 else 1.0
        facts.swaps.append(SwapMetrics(
            "v3", v.amount_in, v.min_out, clean, _tolerance(v.min_out, clean),
            price_impact_bps_v3(v), est.feasible,
            est.attacker_profit / v.amount_in * 1e4 if v.amount_in > 0 else 0.0,
            est.attacker_profit, est.attacker_frontrun, fill, res.ticks_crossed))
    return facts


# --------------------------------------------------------------------------- rule context

@dataclass
class RuleContext:
    tx: Tx
    sim: SimResult
    facts: Facts
    policy: PolicyConfig
    findings: list[Finding] = field(default_factory=list)

    def emit(self, rule: str, message: str, data: dict[str, Any] | None = None) -> None:
        spec = RULES[rule]
        self.findings.append(Finding(rule, spec.severity, message, data or {}))

    def is_known(self, address: str) -> bool:
        return address.lower() in self.policy.known_addresses(self.tx)

    def label(self, address: str) -> str:
        a = address.lower()
        name = self.policy.address_book.get(a) or self.sim.labels.get(a)
        return f"{a} ({name})" if name else a


def is_unlimited(amount: int, via: str = "") -> bool:
    if via == "permit2":
        return amount >= PERMIT2_UNLIMITED
    return amount >= UNLIMITED


# --------------------------------------------------------------------------- checks

@check("DENYLISTED_TARGET")
def _target(ctx: RuleContext) -> None:
    if ctx.tx.to.lower() in ctx.policy.denylist:
        ctx.emit("DENYLISTED_TARGET", f"Target {ctx.tx.to} is denylisted", {"address": ctx.tx.to})


@check("CHAIN_ID_MISMATCH")
def _chain(ctx: RuleContext) -> None:
    expected = ctx.policy.expected_chain_id
    if expected is not None and ctx.tx.chain_id != expected:
        ctx.emit("CHAIN_ID_MISMATCH",
                 f"Transaction chain id {ctx.tx.chain_id} != policy expected {expected}",
                 {"tx_chain_id": ctx.tx.chain_id, "expected": expected})
    elif ctx.sim.chain_id is not None and ctx.sim.chain_id != ctx.tx.chain_id:
        ctx.emit("CHAIN_ID_MISMATCH",
                 f"Transaction chain id {ctx.tx.chain_id} != simulated chain {ctx.sim.chain_id}",
                 {"tx_chain_id": ctx.tx.chain_id, "sim_chain_id": ctx.sim.chain_id})


@check("UNLIMITED_APPROVAL_UNKNOWN", "APPROVAL_TO_DENYLISTED", "APPROVAL_UNKNOWN_SPENDER",
       "UNLIMITED_APPROVAL_TRUSTED", "APPROVAL_REVOKED")
def _approvals(ctx: RuleContext) -> None:
    pol = ctx.policy
    for a in ctx.sim.approvals:
        spender = a.spender.lower()
        data = {"spender": spender, "token": a.token, "amount": a.amount, "via": a.via}
        if spender in pol.denylist:
            ctx.emit("APPROVAL_TO_DENYLISTED", f"Approval to denylisted {spender}", data)
        elif a.amount == 0:
            ctx.emit("APPROVAL_REVOKED", f"Allowance for {ctx.label(spender)} set to zero", data)
        elif is_unlimited(a.amount, a.via):
            if pol.is_trusted_spender(spender):
                ctx.emit("UNLIMITED_APPROVAL_TRUSTED",
                         f"Unlimited approval to trusted spender {ctx.label(spender)}", data)
            else:
                ctx.emit("UNLIMITED_APPROVAL_UNKNOWN",
                         f"Unlimited approval to unknown spender {ctx.label(spender)}", data)
        elif not pol.is_trusted_spender(spender):
            ctx.emit("APPROVAL_UNKNOWN_SPENDER",
                     f"Bounded approval to unknown spender {ctx.label(spender)}", data)


@check("OPERATOR_APPROVAL_UNKNOWN", "OPERATOR_APPROVAL_DENYLISTED", "OPERATOR_APPROVAL_TRUSTED",
       "OPERATOR_APPROVAL_REVOKED")
def _operators(ctx: RuleContext) -> None:
    pol = ctx.policy
    for o in ctx.sim.operator_approvals:
        op = o.operator.lower()
        data = {"operator": op, "token": o.token, "standard": o.standard}
        if not o.approved:
            ctx.emit("OPERATOR_APPROVAL_REVOKED", f"Operator approval for {op} revoked", data)
        elif op in pol.denylist:
            ctx.emit("OPERATOR_APPROVAL_DENYLISTED", f"setApprovalForAll to denylisted {op}", data)
        elif pol.is_trusted_operator(op):
            ctx.emit("OPERATOR_APPROVAL_TRUSTED",
                     f"Collection-wide approval to trusted operator {ctx.label(op)}", data)
        else:
            ctx.emit("OPERATOR_APPROVAL_UNKNOWN",
                     f"setApprovalForAll grants unknown operator {ctx.label(op)} control of every "
                     f"token in {o.token}", data)


@check("PERMIT_UNLIMITED_UNKNOWN", "PERMIT_TO_DENYLISTED", "PERMIT_UNKNOWN_SPENDER",
       "PERMIT_FAR_DEADLINE", "PERMIT_UNLIMITED_TRUSTED")
def _permits(ctx: RuleContext) -> None:
    pol = ctx.policy
    now = ctx.sim.block_timestamp
    for p in ctx.sim.permits:
        spender = p.spender.lower()
        via = "permit2" if p.kind == "permit2" else ""
        data = {"spender": spender, "token": p.token, "amount": p.amount, "deadline": p.deadline,
                "kind": p.kind}
        if spender in pol.denylist:
            ctx.emit("PERMIT_TO_DENYLISTED", f"Permit to denylisted {spender}", data)
        elif is_unlimited(p.amount, via):
            if pol.is_trusted_spender(spender):
                ctx.emit("PERMIT_UNLIMITED_TRUSTED",
                         f"Unlimited {p.kind} permit to trusted {ctx.label(spender)}", data)
            else:
                ctx.emit("PERMIT_UNLIMITED_UNKNOWN",
                         f"Unlimited {p.kind} permit to unknown spender {ctx.label(spender)}", data)
        elif p.amount > 0 and not pol.is_trusted_spender(spender):
            ctx.emit("PERMIT_UNKNOWN_SPENDER",
                     f"{p.kind} permit of {p.amount} to unknown spender {ctx.label(spender)}", data)
        if p.amount == 0:
            continue
        if p.deadline >= FAR_FUTURE:
            ctx.emit("PERMIT_FAR_DEADLINE", "Permit never expires", data)
        elif now is not None and p.deadline - now > pol.permit_deadline_warn_s:
            days = (p.deadline - now) / DAY
            ctx.emit("PERMIT_FAR_DEADLINE", f"Permit valid for {days:.0f} days",
                     {**data, "valid_for_s": p.deadline - now})


@check("TRANSFER_TO_DENYLISTED", "NEAR_FULL_BALANCE_TO_NEW_ADDRESS", "TRANSFER_TO_FRESH_ADDRESS",
       "TRANSFER_TO_UNKNOWN_CONTRACT")
def _transfers(ctx: RuleContext) -> None:
    pol = ctx.policy
    sender = ctx.tx.sender.lower()
    for t in ctx.sim.transfers:
        r = t.recipient.lower()
        data = {"recipient": r, "token": t.token, "amount": t.amount, "kind": t.kind}
        if r in pol.denylist:
            ctx.emit("TRANSFER_TO_DENYLISTED", f"Transfer to denylisted {r}", data)
            continue
        if r == sender or t.sender.lower() != sender:
            continue
        if r in pol.trusted_recipients or r in pol.address_book:
            continue
        bal = t.sender_balance_before
        if bal and t.amount / bal >= pol.drain_fraction:
            ctx.emit("NEAR_FULL_BALANCE_TO_NEW_ADDRESS",
                     f"{t.amount / bal:.0%} of balance sent to unrecognised {r}",
                     {**data, "fraction": t.amount / bal})
        acct = ctx.sim.accounts.get(r)
        if acct is None:
            continue
        if pol.flag_fresh_recipients and acct.is_fresh:
            ctx.emit("TRANSFER_TO_FRESH_ADDRESS",
                     f"Recipient {r} has never been used (no code, nonce 0, zero balance)", data)
        elif pol.flag_contract_recipients and acct.is_contract and t.kind != "eth":
            ctx.emit("TRANSFER_TO_UNKNOWN_CONTRACT",
                     f"{t.kind} tokens sent to unlabelled contract {r}", data)


@check("ADDRESS_LOOKALIKE")
def _lookalikes(ctx: RuleContext) -> None:
    pol = ctx.policy
    known = pol.known_addresses(ctx.tx)
    candidates = ctx.sim.all_counterparties() | {ctx.tx.to.lower()}
    seen: set[str] = set()
    for cand in sorted(candidates):
        if cand in known or cand in seen:
            continue
        for ref in sorted(known):
            if lookalike(cand, ref, pol.lookalike_prefix, pol.lookalike_suffix):
                seen.add(cand)
                ctx.emit("ADDRESS_LOOKALIKE",
                         f"{cand} resembles known address {ctx.label(ref)} but is not it",
                         {"address": cand, "resembles": ref,
                          "label": pol.address_book.get(ref, "")})
                break


@check("PRICE_IMPACT_EXTREME", "PRICE_IMPACT_HIGH", "SLIPPAGE_TOLERANCE_EXTREME",
       "SLIPPAGE_TOLERANCE_LOOSE", "SANDWICH_EXPOSURE_SEVERE", "SANDWICH_EXPOSURE",
       "LIQUIDITY_EXHAUSTED")
def _swaps(ctx: RuleContext) -> None:
    pol = ctx.policy
    for m in ctx.facts.swaps:
        base = {"pool": m.kind}
        if m.fill_fraction < pol.min_fill_fraction:
            ctx.emit("LIQUIDITY_EXHAUSTED",
                     f"Pool fills only {m.fill_fraction:.1%} of the input",
                     {**base, "fill_fraction": m.fill_fraction, "ticks_crossed": m.ticks_crossed})
        if m.impact_bps >= pol.impact_block_bps:
            ctx.emit("PRICE_IMPACT_EXTREME", f"Price impact {m.impact_bps:.0f} bps",
                     {**base, "bps": m.impact_bps})
        elif m.impact_bps >= pol.impact_warn_bps:
            ctx.emit("PRICE_IMPACT_HIGH", f"Price impact {m.impact_bps:.0f} bps",
                     {**base, "bps": m.impact_bps})
        if m.tolerance >= pol.slippage_block:
            ctx.emit("SLIPPAGE_TOLERANCE_EXTREME", f"Slippage tolerance {m.tolerance:.1%}",
                     {**base, "tolerance": m.tolerance})
        elif m.tolerance >= pol.slippage_warn:
            ctx.emit("SLIPPAGE_TOLERANCE_LOOSE", f"Slippage tolerance {m.tolerance:.1%}",
                     {**base, "tolerance": m.tolerance})
        if m.sandwich_feasible:
            data = {**base, "extractable_bps": m.sandwich_bps, "frontrun": m.sandwich_frontrun,
                    "profit": m.sandwich_profit}
            if m.sandwich_bps >= pol.sandwich_block_bps:
                ctx.emit("SANDWICH_EXPOSURE_SEVERE",
                         f"Slippage floor permits ~{m.sandwich_bps:.0f} bps extraction", data)
            elif m.sandwich_bps >= pol.sandwich_warn_bps:
                ctx.emit("SANDWICH_EXPOSURE",
                         f"Slippage floor permits ~{m.sandwich_bps:.0f} bps extraction", data)


@check("REVERT", "ETH_REJECTED_BY_CONTRACT")
def _revert(ctx: RuleContext) -> None:
    sim = ctx.sim
    if sim.success:
        return
    ctx.emit("REVERT", f"Transaction reverts: {sim.revert_reason or 'unknown'}",
             {"reason": sim.revert_reason})
    if ctx.tx.value > 0 and sim.eth_receive_reverts:
        ctx.emit("ETH_REJECTED_BY_CONTRACT",
                 f"{ctx.tx.to} has no payable receive/fallback; {ctx.tx.value} wei cannot be sent",
                 {"value": ctx.tx.value})


@check("GAS_EXTREME", "GAS_ABNORMAL")
def _gas(ctx: RuleContext) -> None:
    sim, pol = ctx.sim, ctx.policy
    if not sim.success or sim.gas_used <= 0:
        return
    typical = TYPICAL_GAS.get(sim.call_kind or "", DEFAULT_TYPICAL_GAS)
    data = {"gas_used": sim.gas_used, "typical": typical, "call_kind": sim.call_kind}
    if sim.gas_used >= pol.gas_block_absolute:
        ctx.emit("GAS_EXTREME", f"Gas estimate {sim.gas_used:,} exceeds {pol.gas_block_absolute:,}",
                 data)
    elif sim.gas_used > pol.gas_abnormal_multiple * typical:
        ctx.emit("GAS_ABNORMAL",
                 f"Gas estimate {sim.gas_used:,} is {sim.gas_used / typical:.1f}x the typical "
                 f"{typical:,} for {sim.call_kind or 'this call'}", data)


@check("SELFDESTRUCT_IN_TRACE", "DELEGATECALL_TO_UNKNOWN", "PROXY_DELEGATECALL_UNKNOWN_IMPL",
       "CONTRACT_CREATION_IN_TRACE", "DENYLISTED_IN_TRACE")
def _trace(ctx: RuleContext) -> None:
    tree, pol = ctx.sim.call_tree, ctx.policy
    if tree is None:
        return
    known_code = set(pol.address_book) | pol.trusted_implementations | pol.trusted_spenders
    for depth, frame in tree.walk():
        to = frame.to.lower()
        data = {"depth": depth, "from": frame.sender, "to": to, "kind": frame.kind}
        if frame.kind == "SELFDESTRUCT":
            ctx.emit("SELFDESTRUCT_IN_TRACE", f"{frame.sender} self-destructs during the call", data)
        if to in pol.denylist and depth > 0:
            ctx.emit("DENYLISTED_IN_TRACE", f"Call tree touches denylisted {to}", data)
        if frame.kind in ("CREATE", "CREATE2") and pol.flag_contract_creation:
            ctx.emit("CONTRACT_CREATION_IN_TRACE",
                     f"{frame.kind} by {frame.sender} at depth {depth}", data)
        if frame.kind in ("DELEGATECALL", "CALLCODE") and pol.flag_unknown_delegatecall:
            if to == frame.sender.lower() or to in known_code:
                continue
            if frame.sender.lower() == ctx.tx.to.lower() and depth == 1:
                ctx.emit("PROXY_DELEGATECALL_UNKNOWN_IMPL",
                         f"{ctx.tx.to} delegatecalls unlabelled implementation {to}", data)
            else:
                ctx.emit("DELEGATECALL_TO_UNKNOWN",
                         f"{frame.sender} delegatecalls unknown code {to} at depth {depth}", data)


@check("HONEYPOT_SELL_REVERTS", "ROUND_TRIP_LOSS_SEVERE", "ROUND_TRIP_LOSS")
def _honeypot(ctx: RuleContext) -> None:
    hp, pol = ctx.sim.honeypot, ctx.policy
    if hp is None or not hp.buy_ok:
        return
    data = {"mode": hp.mode, "loss_fraction": hp.loss_fraction, "bought": hp.bought,
            "returned": hp.returned, "taxes_observable": hp.taxes_observable}
    if not hp.sell_ok:
        ctx.emit("HONEYPOT_SELL_REVERTS",
                 f"Token can be bought but the sell reverts: {hp.sell_revert_reason or 'unknown'}",
                 {**data, "reason": hp.sell_revert_reason})
    elif hp.loss_fraction >= pol.honeypot_loss_block:
        ctx.emit("ROUND_TRIP_LOSS_SEVERE",
                 f"Buy-then-sell loses {hp.loss_fraction:.0%} of the input", data)
    elif hp.loss_fraction >= pol.honeypot_loss_warn:
        ctx.emit("ROUND_TRIP_LOSS", f"Buy-then-sell loses {hp.loss_fraction:.1%} of the input",
                 data)


@check("LP_REMOVAL_MAJORITY", "LP_REMOVAL_LARGE")
def _liquidity(ctx: RuleContext) -> None:
    pol = ctx.policy
    for e in ctx.sim.lp_events:
        if e.action != "remove":
            continue
        frac = e.fraction
        if frac is None:
            continue
        data = {"pool": e.pool, "fraction": frac, "protocol": e.protocol}
        if frac >= pol.lp_removal_block_fraction:
            ctx.emit("LP_REMOVAL_MAJORITY", f"Removes {frac:.0%} of pool {e.pool} liquidity", data)
        elif frac >= pol.lp_removal_warn_fraction:
            ctx.emit("LP_REMOVAL_LARGE", f"Removes {frac:.0%} of pool {e.pool} liquidity", data)


# --------------------------------------------------------------------------- entry points

def apply_rules(tx: Tx, sim: SimResult, facts: Facts, policy: PolicyConfig) -> list[Finding]:
    ctx = RuleContext(tx, sim, facts, policy)
    for _name, _ids, fn in _CHECKS:
        fn(ctx)
    if policy.disabled_rules:
        return [f for f in ctx.findings if f.rule not in policy.disabled_rules]
    return ctx.findings


def verdict_from(findings: list[Finding]) -> Verdict:
    worst = max((f.severity for f in findings), default=Severity.INFO)
    return verdict_for_severity(worst)


def assess(tx: Tx, sim: SimResult, policy: PolicyConfig | None = None
           ) -> tuple[Verdict, list[Finding]]:
    policy = policy or PolicyConfig()
    findings = apply_rules(tx, sim, compute_facts(tx, sim), policy)
    return verdict_from(findings), findings


def checks_for_rule(rule_id: str) -> list[str]:
    return [name for name, ids, _ in _CHECKS if rule_id in ids]
