"""Constant-product AMM math: single-hop and multi-hop routes, price impact, sandwich estimates.

The sandwich estimator first finds, by bisection, the largest front-run that still lets the
victim clear ``min_out`` (the victim's output is monotonically decreasing in the attacker's
size). The attacker's profit is concave in the front-run size, so a ternary search over
``[0, a_max]`` then picks the profit-maximising front-run: a searcher is not obliged to use all
of the slippage room if a smaller sandwich pays better. Profit is the attacker's token_in round
trip including pool fees. A trade whose own price push is below twice the pool fee is not
sandwichable at any size, which the search reports as infeasible.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .models import Hop, PathSwap, Swap

BISECT_ITERS = 80
SEARCH_ITERS = 60


def amount_out(dx: float, reserve_in: float, reserve_out: float, fee: float = 0.003) -> float:
    if dx <= 0 or reserve_in <= 0 or reserve_out <= 0:
        return 0.0
    dx_eff = dx * (1.0 - fee)
    return dx_eff * reserve_out / (reserve_in + dx_eff)


def amount_in_for_out(dy: float, reserve_in: float, reserve_out: float,
                      fee: float = 0.003) -> float:
    """Inverse of ``amount_out``: token_in required to receive exactly ``dy``. inf if impossible."""
    if dy <= 0:
        return 0.0
    if dy >= reserve_out:
        return float("inf")
    return reserve_in * dy / ((reserve_out - dy) * (1.0 - fee))


def price_impact_bps(swap: Swap) -> float:
    """Impact vs. the pre-trade spot price, in basis points (fee included)."""
    if swap.reserve_in <= 0 or swap.reserve_out <= 0 or swap.amount_in <= 0:
        return 0.0
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


def _bisect_frontrun(victim_out: Callable[[float], float], min_out: float, cap: float) -> float:
    """Largest ``a`` in [0, cap] with ``victim_out(a) >= min_out`` (``victim_out`` decreasing)."""
    if victim_out(cap) >= min_out:
        return cap
    lo, hi = 0.0, cap
    for _ in range(BISECT_ITERS):
        mid = (lo + hi) / 2.0
        if victim_out(mid) >= min_out:
            lo = mid
        else:
            hi = mid
    return lo


def _best_frontrun(profit: Callable[[float], float], a_max: float) -> float:
    """argmax of a concave ``profit`` over [0, a_max] (ternary search), including the endpoint."""
    if a_max <= 0:
        return 0.0
    lo, hi = 0.0, a_max
    for _ in range(SEARCH_ITERS):
        m1 = lo + (hi - lo) / 3.0
        m2 = hi - (hi - lo) / 3.0
        if profit(m1) < profit(m2):
            lo = m1
        else:
            hi = m2
    a = (lo + hi) / 2.0
    return a_max if profit(a_max) >= profit(a) else a


def optimal_sandwich(victim_out: Callable[[float], float], back_run: Callable[[float], float],
                     min_out: float, cap: float) -> tuple[float, float]:
    """(front-run size, profit) for the best sandwich that keeps ``victim_out >= min_out``."""
    a_max = _bisect_frontrun(victim_out, min_out, cap)
    a = _best_frontrun(lambda a: back_run(a) - a, a_max)
    return a, back_run(a) - a


def estimate_sandwich(swap: Swap, attacker_capital_multiple: float = 10.0) -> SandwichEstimate:
    """Largest front-run that still lets the victim clear ``min_out``, and its profit.

    The attacker buys token_out with ``a`` token_in, the victim trades, then the attacker
    sells the same token_out back. Attacker capital is capped at
    ``attacker_capital_multiple * reserve_in``.
    """
    x, y, f = swap.reserve_in, swap.reserve_out, swap.fee
    clean = amount_out(swap.amount_in, x, y, f)
    if clean < swap.min_out or clean <= 0:
        return SandwichEstimate(False, 0.0, 0.0, clean, clean)

    def run(a: float) -> tuple[float, float]:
        out_a = amount_out(a, x, y, f)
        x1, y1 = x + a, y - out_a
        out_v = amount_out(swap.amount_in, x1, y1, f)
        x2, y2 = x1 + swap.amount_in, y1 - out_v
        back = amount_out(out_a, y2, x2, f)  # sell token_out back for token_in
        return out_v, back

    a, profit = optimal_sandwich(lambda a: run(a)[0], lambda a: run(a)[1], swap.min_out,
                                 attacker_capital_multiple * x)
    out_v = run(a)[0]
    return SandwichEstimate(profit > 0, a, max(profit, 0.0), out_v, clean)


# --------------------------------------------------------------------------- multi-hop

def _route(amount: float, hops: list[list[float]]) -> float:
    """Push ``amount`` through ``hops`` (mutable [reserve_in, reserve_out, fee] lists)."""
    for h in hops:
        out = amount_out(amount, h[0], h[1], h[2])
        h[0] += amount
        h[1] -= out
        amount = out
    return amount


def _mutable(hops: tuple[Hop, ...]) -> list[list[float]]:
    return [[h.reserve_in, h.reserve_out, h.fee] for h in hops]


def amount_out_path(amount_in: float, hops: tuple[Hop, ...]) -> float:
    return _route(amount_in, _mutable(hops))


def spot_out_path(amount_in: float, hops: tuple[Hop, ...]) -> float:
    rate = 1.0
    for h in hops:
        if h.reserve_in <= 0:
            return 0.0
        rate *= h.reserve_out / h.reserve_in
    return amount_in * rate


def price_impact_bps_path(swap: PathSwap) -> float:
    spot = spot_out_path(swap.amount_in, swap.hops)
    if spot <= 0:
        return 0.0
    got = amount_out_path(swap.amount_in, swap.hops)
    return max(0.0, 1.0 - got / spot) * 1e4


def estimate_sandwich_path(swap: PathSwap, attacker_capital_multiple: float = 10.0
                           ) -> SandwichEstimate:
    """Sandwich across the whole route: attacker front-runs the full path and unwinds in reverse."""
    if not swap.hops:
        return SandwichEstimate(False, 0.0, 0.0, 0.0, 0.0)
    clean = amount_out_path(swap.amount_in, swap.hops)
    if clean < swap.min_out or clean <= 0:
        return SandwichEstimate(False, 0.0, 0.0, clean, clean)

    def run(a: float) -> tuple[float, float]:
        state = _mutable(swap.hops)
        out_a = _route(a, state)
        out_v = _route(swap.amount_in, state)
        reverse = [[h[1], h[0], h[2]] for h in reversed(state)]
        back = _route(out_a, reverse)
        return out_v, back

    a = _bisect_frontrun(lambda a: run(a)[0], swap.min_out,
                         attacker_capital_multiple * swap.hops[0].reserve_in)
    out_v, back = run(a)
    profit = back - a
    return SandwichEstimate(profit > 0, a, max(profit, 0.0), out_v, clean)
