"""Deterministic risk engine. The LLM never overrides the verdict computed here."""
from __future__ import annotations

from dataclasses import dataclass, field

from .amm import amount_out, estimate_sandwich, price_impact_bps
from .models import Finding, Severity, SimResult, Tx, Verdict

UNLIMITED = 2**255


@dataclass
class PolicyConfig:
    trusted_spenders: set[str] = field(default_factory=set)
    trusted_recipients: set[str] = field(default_factory=set)
    denylist: set[str] = field(default_factory=set)
    sandwich_warn_bps: float = 30.0
    sandwich_block_bps: float = 100.0
    impact_warn_bps: float = 500.0
    impact_block_bps: float = 2000.0
    drain_fraction: float = 0.9
    slippage_warn: float = 0.0075  # tolerance below the simulated output
    slippage_block: float = 0.05

    def __post_init__(self) -> None:
        self.trusted_spenders = {a.lower() for a in self.trusted_spenders}
        self.trusted_recipients = {a.lower() for a in self.trusted_recipients}
        self.denylist = {a.lower() for a in self.denylist}


def assess(tx: Tx, sim: SimResult, policy: PolicyConfig | None = None) -> tuple[Verdict, list[Finding]]:
    policy = policy or PolicyConfig()
    findings: list[Finding] = []

    if not sim.success:
        findings.append(
            Finding("REVERT", Severity.HIGH, f"Transaction reverts: {sim.revert_reason or 'unknown'}")
        )

    if tx.to.lower() in policy.denylist:
        findings.append(Finding("DENYLISTED_TARGET", Severity.CRITICAL, f"Target {tx.to} is denylisted"))

    for a in sim.approvals:
        spender = a.spender.lower()
        if spender in policy.denylist:
            findings.append(
                Finding("APPROVAL_TO_DENYLISTED", Severity.CRITICAL, f"Approval to denylisted {spender}")
            )
        elif a.amount >= UNLIMITED:
            if spender in policy.trusted_spenders:
                findings.append(
                    Finding("UNLIMITED_APPROVAL_TRUSTED", Severity.MEDIUM,
                            f"Unlimited approval to trusted spender {spender}")
                )
            else:
                findings.append(
                    Finding("UNLIMITED_APPROVAL_UNKNOWN", Severity.CRITICAL,
                            f"Unlimited approval to unknown spender {spender}")
                )
        elif spender not in policy.trusted_spenders:
            findings.append(
                Finding("APPROVAL_UNKNOWN_SPENDER", Severity.HIGH,
                        f"Bounded approval to unknown spender {spender}")
            )

    for t in sim.transfers:
        r = t.recipient.lower()
        if r in policy.denylist:
            findings.append(
                Finding("TRANSFER_TO_DENYLISTED", Severity.CRITICAL, f"Transfer to denylisted {r}")
            )
        elif r not in policy.trusted_recipients and t.sender.lower() == tx.sender.lower():
            bal = t.sender_balance_before
            if bal and t.amount / bal >= policy.drain_fraction:
                findings.append(
                    Finding("NEAR_FULL_BALANCE_TO_NEW_ADDRESS", Severity.HIGH,
                            f"{t.amount / bal:.0%} of balance sent to unrecognised {r}",
                            {"fraction": t.amount / bal})
                )

    if sim.swap and sim.success:
        impact = price_impact_bps(sim.swap)
        if impact >= policy.impact_block_bps:
            findings.append(Finding("PRICE_IMPACT_EXTREME", Severity.CRITICAL,
                                    f"Price impact {impact:.0f} bps", {"bps": impact}))
        elif impact >= policy.impact_warn_bps:
            findings.append(Finding("PRICE_IMPACT_HIGH", Severity.HIGH,
                                    f"Price impact {impact:.0f} bps", {"bps": impact}))

        clean = amount_out(sim.swap.amount_in, sim.swap.reserve_in, sim.swap.reserve_out, sim.swap.fee)
        tol = max(0.0, 1.0 - sim.swap.min_out / clean) if clean > 0 else 0.0
        if tol >= policy.slippage_block:
            findings.append(Finding("SLIPPAGE_TOLERANCE_EXTREME", Severity.CRITICAL,
                                    f"Slippage tolerance {tol:.1%}", {"tolerance": tol}))
        elif tol >= policy.slippage_warn:
            findings.append(Finding("SLIPPAGE_TOLERANCE_LOOSE", Severity.HIGH,
                                    f"Slippage tolerance {tol:.1%}", {"tolerance": tol}))

        est = estimate_sandwich(sim.swap)
        if est.feasible:
            bps = est.attacker_profit / sim.swap.amount_in * 1e4
            data = {"extractable_bps": bps, "frontrun": est.attacker_frontrun,
                    "profit": est.attacker_profit}
            if bps >= policy.sandwich_block_bps:
                findings.append(Finding("SANDWICH_EXPOSURE_SEVERE", Severity.CRITICAL,
                                        f"Slippage floor permits ~{bps:.0f} bps extraction", data))
            elif bps >= policy.sandwich_warn_bps:
                findings.append(Finding("SANDWICH_EXPOSURE", Severity.HIGH,
                                        f"Slippage floor permits ~{bps:.0f} bps extraction", data))

    worst = max((f.severity for f in findings), default=Severity.INFO)
    if worst >= Severity.CRITICAL:
        return Verdict.BLOCK, findings
    if worst >= Severity.HIGH:
        return Verdict.WARN, findings
    return Verdict.ALLOW, findings
