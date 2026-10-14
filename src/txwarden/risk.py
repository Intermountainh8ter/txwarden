"""Deterministic risk engine. The LLM never overrides the verdict computed here.

Structure:

- ``rules.RULES`` is the registry (re-exported here): every rule id with its fixed severity,
  category, description, operator docs and the ``PolicyConfig`` fields that influence it.
  ``docs/RULES.md`` and ``txwarden explain`` are generated from it, and a test asserts that every
  finding emitted anywhere uses a registered id.
- ``compute_facts`` does the expensive, policy-independent measurements (AMM simulation, sandwich
  bisection) once per transaction.
- ``apply_rules`` runs the cheap checks against a ``PolicyConfig``. Threshold sweeps in the evals
  re-run only this step.
- ``assess`` = facts + rules + verdict. CRITICAL -> BLOCK, HIGH -> WARN, otherwise ALLOW.
  A check that raises becomes an ``ENGINE_ERROR`` finding (BLOCK): the engine fails closed.
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
from .rules import RULES, RuleSpec, verdict_for_severity

__all__ = [
    "BURN_ADDRESSES",
    "FAIL_CLOSED_RULES",
    "RULES",
    "PolicyConfig",
    "RuleSpec",
    "apply_rules",
    "assess",
    "check",
    "checks_for_rule",
    "compute_facts",
    "verdict_for_severity",
    "verdict_from",
]

UNLIMITED = 2**255  # the usual "max approval" value (type(uint256).max, or 2**255 in some wallets)
PERMIT2_UNLIMITED = 2**160 - 1  # Permit2's "infinite" allowance (uint160 max)
# Any allowance at or above this is treated as unlimited: 2**128 raw units is more than the total
# supply of any real token (even a 1e18-supply token with 18 decimals is ~2**120), so a "bounded"
# approval this large is as dangerous as an infinite one. Protocols use uint96/uint128/uint160
# maxima as "infinite" for the same reason; only uint96 max stays below the line.
UNLIMITED_THRESHOLD = 2**128
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

# Rules that exist so that missing or broken analysis can never become ALLOW.
FAIL_CLOSED_RULES = frozenset({"ENGINE_ERROR", "SIMULATION_UNAVAILABLE"})
# `SimResult.incomplete` markers that mean "a trade-risk analysis could not run" (-> WARN).
HARD_INCOMPLETE = frozenset({"swap_state", "lp_state"})
BURN_ADDRESSES = frozenset({"0x" + "00" * 20, "0x" + "00" * 18 + "dead"})


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
    flag_swap_recipient_mismatch: bool = True
    # target
    flag_call_to_non_contract: bool = True
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
        unknown = self.disabled_rules - set(RULES)
        if unknown:
            raise ValueError(f"disabled_rules names unknown rules: {sorted(unknown)}")
        locked = self.disabled_rules & FAIL_CLOSED_RULES
        if locked:
            raise ValueError(f"rules {sorted(locked)} cannot be disabled: they implement "
                             "fail-closed behaviour")
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


# --------------------------------------------------------------------------- check registry

_CHECKS: list[tuple[str, tuple[str, ...], Callable[[RuleContext], None]]] = []


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


def is_unlimited(amount: int) -> bool:
    return amount >= UNLIMITED_THRESHOLD


# --------------------------------------------------------------------------- checks

@check("DENYLISTED_TARGET")
def _target(ctx: RuleContext) -> None:
    if ctx.tx.to.lower() in ctx.policy.denylist:
        ctx.emit("DENYLISTED_TARGET", f"Target {ctx.tx.to} is denylisted", {"address": ctx.tx.to})


@check("CALL_TO_NON_CONTRACT")
def _non_contract(ctx: RuleContext) -> None:
    if not ctx.policy.flag_call_to_non_contract or len(ctx.tx.data) <= 2:
        return
    acct = ctx.sim.accounts.get(ctx.tx.to.lower())
    if acct is not None and not acct.is_contract:
        ctx.emit("CALL_TO_NON_CONTRACT",
                 f"Calldata sent to {ctx.tx.to}, which has no code; the call will do nothing",
                 {"address": ctx.tx.to, "value": ctx.tx.value})


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


def _far_deadline(ctx: RuleContext, deadline: int, what: str, data: dict[str, Any]) -> None:
    now = ctx.sim.block_timestamp
    if deadline >= FAR_FUTURE:
        ctx.emit("PERMIT_FAR_DEADLINE", f"{what} never expires", data)
    elif now is not None and deadline - now > ctx.policy.permit_deadline_warn_s:
        days = (deadline - now) / DAY
        ctx.emit("PERMIT_FAR_DEADLINE", f"{what} valid for {days:.0f} days",
                 {**data, "valid_for_s": deadline - now})


@check("UNLIMITED_APPROVAL_UNKNOWN", "APPROVAL_TO_DENYLISTED", "APPROVAL_UNKNOWN_SPENDER",
       "UNLIMITED_APPROVAL_TRUSTED", "APPROVAL_REVOKED", "PERMIT_FAR_DEADLINE")
def _approvals(ctx: RuleContext) -> None:
    pol = ctx.policy
    for a in ctx.sim.approvals:
        spender = a.spender.lower()
        data = {"spender": spender, "token": a.token, "amount": a.amount, "via": a.via}
        if a.amount == 0:  # revoking is good, even from a denylisted spender
            ctx.emit("APPROVAL_REVOKED", f"Allowance for {ctx.label(spender)} set to zero", data)
        elif spender in pol.denylist:
            ctx.emit("APPROVAL_TO_DENYLISTED", f"Approval to denylisted {spender}", data)
        elif is_unlimited(a.amount):
            if pol.is_trusted_spender(spender):
                ctx.emit("UNLIMITED_APPROVAL_TRUSTED",
                         f"Unlimited approval to trusted spender {ctx.label(spender)}", data)
            else:
                ctx.emit("UNLIMITED_APPROVAL_UNKNOWN",
                         f"Unlimited approval to unknown spender {ctx.label(spender)}", data)
        elif not pol.is_trusted_spender(spender):
            ctx.emit("APPROVAL_UNKNOWN_SPENDER",
                     f"Bounded approval to unknown spender {ctx.label(spender)}", data)
        if a.via == "permit2" and a.amount > 0 and a.expiration is not None:
            _far_deadline(ctx, a.expiration, "Permit2 allowance", {**data, "expiration": a.expiration})


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
    for p in ctx.sim.permits:
        spender = p.spender.lower()
        data = {"spender": spender, "token": p.token, "amount": p.amount, "deadline": p.deadline,
                "kind": p.kind}
        if p.amount == 0:  # a zero-value permit revokes; nothing to review
            continue
        if spender in pol.denylist:
            ctx.emit("PERMIT_TO_DENYLISTED", f"Permit to denylisted {spender}", data)
        elif is_unlimited(p.amount):
            if pol.is_trusted_spender(spender):
                ctx.emit("PERMIT_UNLIMITED_TRUSTED",
                         f"Unlimited {p.kind} permit to trusted {ctx.label(spender)}", data)
            else:
                ctx.emit("PERMIT_UNLIMITED_UNKNOWN",
                         f"Unlimited {p.kind} permit to unknown spender {ctx.label(spender)}", data)
        elif not pol.is_trusted_spender(spender):
            ctx.emit("PERMIT_UNKNOWN_SPENDER",
                     f"{p.kind} permit of {p.amount} to unknown spender {ctx.label(spender)}", data)
        _far_deadline(ctx, p.deadline, "Permit", data)


@check("TRANSFER_TO_DENYLISTED", "TRANSFER_TO_BURN_ADDRESS", "TRANSFER_TO_TOKEN_CONTRACT",
       "NEAR_FULL_BALANCE_TO_NEW_ADDRESS", "TRANSFER_TO_FRESH_ADDRESS",
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
        if r in BURN_ADDRESSES:
            ctx.emit("TRANSFER_TO_BURN_ADDRESS", f"Funds sent to the burn address {r}", data)
            continue
        if t.sender.lower() != sender:
            continue
        if t.kind != "eth" and r == t.token.lower():
            ctx.emit("TRANSFER_TO_TOKEN_CONTRACT",
                     f"Tokens sent to the token contract {r} itself; they are unrecoverable", data)
            continue
        if r == sender or r in pol.trusted_recipients or r in pol.address_book:
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


@check("UNTRUSTED_PULL_IN_TRACE")
def _pulls(ctx: RuleContext) -> None:
    sender = ctx.tx.sender.lower()
    for t in ctx.sim.transfers:
        op = (t.operator or "").lower()
        r = t.recipient.lower()
        if not op or op == sender or t.sender.lower() != sender or t.kind == "eth":
            continue
        if r in (sender, op) or ctx.is_known(op) or ctx.is_known(r) or r in ctx.policy.denylist:
            continue
        ctx.emit("UNTRUSTED_PULL_IN_TRACE",
                 f"Untrusted contract {op} moves your {t.kind} tokens to {r}",
                 {"operator": op, "recipient": r, "token": t.token, "amount": t.amount})


@check("SWAP_RECIPIENT_MISMATCH", "TRANSFER_TO_DENYLISTED", "TRANSFER_TO_BURN_ADDRESS")
def _output_recipients(ctx: RuleContext) -> None:
    pol = ctx.policy
    router = ctx.tx.to.lower()
    for r in dict.fromkeys(a.lower() for a in ctx.sim.output_recipients):
        data = {"recipient": r, "router": router}
        if r in pol.denylist:
            ctx.emit("TRANSFER_TO_DENYLISTED", f"Swap output routed to denylisted {r}", data)
        elif r in BURN_ADDRESSES:
            ctx.emit("TRANSFER_TO_BURN_ADDRESS", f"Swap output routed to the burn address {r}", data)
        elif pol.flag_swap_recipient_mismatch and r != router and not ctx.is_known(r):
            ctx.emit("SWAP_RECIPIENT_MISMATCH",
                     f"Output of this call goes to {r}, not to you", data)


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


@check("SIMULATION_UNAVAILABLE")
def _unavailable(ctx: RuleContext) -> None:
    if ctx.sim.error:
        ctx.emit("SIMULATION_UNAVAILABLE", f"Simulation unavailable: {ctx.sim.error}",
                 {"error": ctx.sim.error})


@check("ANALYSIS_INCOMPLETE", "CHECKS_SKIPPED")
def _incomplete(ctx: RuleContext) -> None:
    sim = ctx.sim
    if sim.error:
        return
    hard = [x for x in sim.incomplete if x.split(":", 1)[0] in HARD_INCOMPLETE]
    soft = [x for x in sim.incomplete if x.split(":", 1)[0] not in HARD_INCOMPLETE]
    if hard and sim.success:
        ctx.emit("ANALYSIS_INCOMPLETE",
                 f"Pool state unavailable; could not evaluate: {', '.join(hard)}", {"missing": hard})
    if soft:
        ctx.emit("CHECKS_SKIPPED", f"Checks that did not run: {', '.join(soft)}",
                 {"skipped": soft})


@check("REVERT", "ETH_REJECTED_BY_CONTRACT")
def _revert(ctx: RuleContext) -> None:
    sim = ctx.sim
    if sim.success or sim.error:
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
    for name, _ids, fn in _CHECKS:
        try:
            fn(ctx)
        except Exception as e:  # noqa: PERF203 - a crashing check must never silently become ALLOW
            ctx.emit("ENGINE_ERROR", f"check {name} failed: {type(e).__name__}: {e}",
                     {"check": name, "error": f"{type(e).__name__}: {e}"})
    if policy.disabled_rules:
        return [f for f in ctx.findings if f.rule not in policy.disabled_rules]
    return ctx.findings


def verdict_from(findings: list[Finding]) -> Verdict:
    worst = max((f.severity for f in findings), default=Severity.INFO)
    return verdict_for_severity(worst)


def assess(tx: Tx, sim: SimResult, policy: PolicyConfig | None = None
           ) -> tuple[Verdict, list[Finding]]:
    policy = policy or PolicyConfig()
    try:
        facts, fact_error = compute_facts(tx, sim), None
    except Exception as e:  # AMM math on hostile numbers (inf/NaN/overflow)
        facts, fact_error = Facts(), f"{type(e).__name__}: {e}"
    findings = apply_rules(tx, sim, facts, policy)
    if fact_error:
        findings.append(Finding("ENGINE_ERROR", RULES["ENGINE_ERROR"].severity,
                                f"swap analysis failed: {fact_error}",
                                {"check": "compute_facts", "error": fact_error}))
    return verdict_from(findings), findings


def checks_for_rule(rule_id: str) -> list[str]:
    return [name for name, ids, _ in _CHECKS if rule_id in ids]
