"""Constant-product AMM math and a closed-form-free sandwich estimator."""
from __future__ import annotations

from dataclasses import dataclass

from .models import Swap


def amount_out(dx: float, reserve_in: float, reserve_out: float, fee: float = 0.003) -> float:
    if dx <= 0:
        return 0.0
    dx_eff = dx * (1.0 - fee)
    return dx_eff * reserve_out / (reserve_in + dx_eff)


def price_impact_bps(swap: Swap) -> float:
    """Impact vs. the pre-trade spot price, in basis points (fee included)."""
    spot_out = swap.amount_in * swap.reserve_out / swap.reserve_in
    got = amount_out(swap.amount_in, swap.reserve_in, swap.reserve_out, swap.fee)
    return max(0.0, (1.0 - got / spot_out)) * 1e4


@dataclass(frozen=True)
class SandwichEstimate:
    feasible: bool
    attacker_frontrun: float  # token_in spent by the attacker in the front-run
    attacker_profit: float  # token_in units, before gas
    victim_out_attacked: float
    victim_out_clean: float


def estimate_sandwich(swap: Swap, attacker_capital_multiple: float = 10.0) -> SandwichEstimate:
    """Largest front-run that still lets the victim clear ``min_out``, and its profit.

    The attacker buys token_out with ``a`` token_in, the victim trades, then the attacker
    sells the same token_out back. Victim output is monotonically decreasing in ``a``, so the
    largest feasible ``a`` is found by bisection. Attacker capital is capped at
    ``attacker_capital_multiple * reserve_in``.
    """
    x, y, f = swap.reserve_in, swap.reserve_out, swap.fee
    clean = amount_out(swap.amount_in, x, y, f)
    if clean < swap.min_out:
        return SandwichEstimate(False, 0.0, 0.0, clean, clean)

    def victim_out(a: float) -> float:
        out_a = amount_out(a, x, y, f)
        return amount_out(swap.amount_in, x + a, y - out_a, f)

    lo, hi = 0.0, attacker_capital_multiple * x
    if victim_out(hi) >= swap.min_out:
        a = hi
    else:
        for _ in range(200):
            mid = (lo + hi) / 2.0
            if victim_out(mid) >= swap.min_out:
                lo = mid
            else:
                hi = mid
        a = lo

    out_a = amount_out(a, x, y, f)
    x1, y1 = x + a, y - out_a
    out_v = amount_out(swap.amount_in, x1, y1, f)
    x2, y2 = x1 + swap.amount_in, y1 - out_v
    back = amount_out(out_a, y2, x2, f)  # sell token_out back for token_in
    profit = back - a
    return SandwichEstimate(profit > 0, a, max(profit, 0.0), out_v, clean)
