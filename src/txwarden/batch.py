"""Bundle analysis: several transactions the user is asked to sign together.

Each transaction gets the normal per-transaction assessment; on top of that, cross-transaction
rules look for drainer flows that are only visible when the steps are seen side by side.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .models import Finding, SimResult, Tx, Verdict, worst_verdict
from .risk import RULES, PolicyConfig, assess, verdict_from


@dataclass
class TxReview:
    index: int
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "verdict": self.verdict.value,
                "findings": [f.to_dict() for f in self.findings]}


@dataclass
class BundleReview:
    verdict: Verdict
    per_tx: list[TxReview]
    bundle_findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "per_tx": [t.to_dict() for t in self.per_tx],
                "bundle_findings": [f.to_dict() for f in self.bundle_findings]}


def _finding(rule: str, msg: str, data: dict[str, Any]) -> Finding:
    return Finding(rule, RULES[rule].severity, msg, data)


def bundle_rules(txs: list[Tx], sims: list[SimResult], policy: PolicyConfig) -> list[Finding]:
    out: list[Finding] = []
    if not txs:
        return out
    user = txs[0].sender.lower()

    # BUNDLE_MIXED_CHAIN_IDS
    chains = {tx.chain_id for tx in txs}
    if len(chains) > 1:
        out.append(_finding("BUNDLE_MIXED_CHAIN_IDS",
                            f"Bundle spans chain ids {sorted(chains)}", {"chain_ids": sorted(chains)}))

    # BUNDLE_APPROVE_THEN_PULL: approval/permit to unknown spender, then that spender acts.
    granted: dict[str, int] = {}  # spender -> index of first grant
    for i, sim in enumerate(sims):
        for a in sim.approvals:
            s = a.spender.lower()
            if a.amount > 0 and not policy.is_trusted_spender(s):
                granted.setdefault(s, i)
        for p in sim.permits:
            s = p.spender.lower()
            if p.amount > 0 and not policy.is_trusted_spender(s):
                granted.setdefault(s, i)
    for j, (tx, sim) in enumerate(zip(txs, sims)):
        for spender, i in granted.items():
            if j <= i:
                continue
            pulls = tx.to.lower() == spender or any(
                t.operator and t.operator.lower() == spender and t.sender.lower() == user
                for t in sim.transfers)
            if not pulls and sim.call_tree is not None:
                pulls = any(f.sender.lower() == spender for _, f in sim.call_tree.walk())
            if pulls:
                out.append(_finding(
                    "BUNDLE_APPROVE_THEN_PULL",
                    f"tx #{i} grants unknown spender {spender}; tx #{j} lets it pull funds",
                    {"spender": spender, "grant_index": i, "pull_index": j}))

    # BUNDLE_ADD_THEN_REMOVE_LIQUIDITY
    added: dict[str, int] = {}
    for i, sim in enumerate(sims):
        for e in sim.lp_events:
            if e.action == "add":
                added.setdefault(e.pool.lower(), i)
    for j, sim in enumerate(sims):
        out.extend(
            _finding("BUNDLE_ADD_THEN_REMOVE_LIQUIDITY",
                     f"tx #{added[e.pool.lower()]} adds liquidity to {e.pool}; tx #{j} removes it",
                     {"pool": e.pool, "add_index": added[e.pool.lower()], "remove_index": j})
            for e in sim.lp_events
            if e.action == "remove" and e.pool.lower() in added and added[e.pool.lower()] < j)

    # BUNDLE_CUMULATIVE_DRAIN: sum of outgoing transfers per token vs the balance before.
    totals: dict[str, float] = defaultdict(float)
    balances: dict[str, int] = {}
    individual_drain: set[str] = set()
    for sim in sims:
        for t in sim.transfers:
            r = t.recipient.lower()
            if t.sender.lower() != user or r == user or r in policy.trusted_recipients \
                    or r in policy.address_book:
                continue
            if not t.sender_balance_before:
                continue
            tok = t.token.lower()
            totals[tok] += t.amount
            balances[tok] = max(balances.get(tok, 0), t.sender_balance_before)
            if t.amount / t.sender_balance_before >= policy.drain_fraction:
                individual_drain.add(tok)
    for tok, total in totals.items():
        bal = balances[tok]
        frac = total / bal if bal else 0.0
        if frac >= policy.drain_fraction and tok not in individual_drain:
            out.append(_finding(
                "BUNDLE_CUMULATIVE_DRAIN",
                f"Bundle sends {frac:.0%} of the {tok} balance to unrecognised addresses",
                {"token": tok, "fraction": frac}))
    return [f for f in out if f.rule not in policy.disabled_rules]


def assess_bundle(txs: list[Tx], sims: list[SimResult], policy: PolicyConfig | None = None
                  ) -> BundleReview:
    if len(txs) != len(sims):
        raise ValueError("one SimResult per Tx required")
    policy = policy or PolicyConfig()
    per_tx = []
    for i, (tx, sim) in enumerate(zip(txs, sims)):
        v, f = assess(tx, sim, policy)
        per_tx.append(TxReview(i, v, f))
    try:
        extra = bundle_rules(txs, sims, policy)
    except Exception as e:  # cross-transaction analysis must fail closed like single-tx analysis
        extra = [_finding("ENGINE_ERROR", f"bundle analysis failed: {type(e).__name__}: {e}",
                          {"check": "bundle_rules", "error": f"{type(e).__name__}: {e}"})]
    verdict = worst_verdict(*(t.verdict for t in per_tx), verdict_from(extra))
    return BundleReview(verdict, per_tx, extra)
