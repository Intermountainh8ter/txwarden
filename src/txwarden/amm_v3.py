"""Uniswap V3 concentrated-liquidity swap math.

Mirrors ``SwapMath.computeSwapStep`` and the tick-crossing loop of ``UniswapV3Pool.swap`` in
floating point: within one tick range the pool behaves like a constant-product curve on the
*virtual* reserves ``x = L / sqrtP`` and ``y = L * sqrtP``; when the price reaches an
initialised tick, ``liquidityNet`` of that tick is applied and the loop continues.

Conventions (as in the contracts): ``sqrt_price = sqrt(token1 / token0)``;
``zero_for_one`` means token0 in, token1 out, which pushes the price *down*.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, replace

from .amm import SandwichEstimate, optimal_sandwich
from .models import V3Swap, V3Tick

MIN_TICK = -887272
MAX_TICK = 887272
Q96 = 2**96
_EPS = 1e-12


def tick_to_sqrt_price(tick: int) -> float:
    return math.pow(1.0001, tick / 2.0)


def sqrt_price_to_tick(sqrt_price: float) -> int:
    if sqrt_price <= 0:
        raise ValueError("sqrt price must be positive")
    return math.floor(2.0 * math.log(sqrt_price) / math.log(1.0001))


def sqrt_price_x96_to_float(sqrt_price_x96: int) -> float:
    return sqrt_price_x96 / Q96


def virtual_reserves(sqrt_price: float, liquidity: float) -> tuple[float, float]:
    """(token0, token1) virtual reserves of the active range."""
    if sqrt_price <= 0:
        return 0.0, 0.0
    return liquidity / sqrt_price, liquidity * sqrt_price


@dataclass(frozen=True)
class V3Pool:
    sqrt_price: float
    liquidity: float
    fee: float = 0.003
    ticks: tuple[V3Tick, ...] = ()

    @classmethod
    def from_swap(cls, s: V3Swap) -> V3Pool:
        return cls(s.sqrt_price, s.liquidity, s.fee, tuple(sorted(s.ticks, key=lambda t: t.tick)))


@dataclass(frozen=True)
class V3SwapResult:
    amount_in_consumed: float
    amount_out: float
    sqrt_price_after: float
    liquidity_after: float
    ticks_crossed: int
    remaining: float = 0.0  # token_in the pool could not absorb (partial fill)

    @property
    def fully_filled(self) -> bool:
        return self.remaining <= 0


def _boundaries(pool: V3Pool, zero_for_one: bool) -> list[tuple[float, float]]:
    """(sqrt_price_at_tick, liquidity delta to apply when crossed) in the direction of travel."""
    out = []
    if zero_for_one:
        for t in reversed(pool.ticks):
            sp = tick_to_sqrt_price(t.tick)
            if sp < pool.sqrt_price * (1 - _EPS):
                out.append((sp, -t.liquidity_net))
    else:
        for t in pool.ticks:
            sp = tick_to_sqrt_price(t.tick)
            if sp > pool.sqrt_price * (1 + _EPS):
                out.append((sp, t.liquidity_net))
    return out


def swap_exact_in(pool: V3Pool, amount_in: float, zero_for_one: bool) -> V3SwapResult:
    """Exact-input swap across as many ticks as needed. Partial fills are reported, not raised."""
    if amount_in <= 0 or pool.sqrt_price <= 0:
        return V3SwapResult(0.0, 0.0, pool.sqrt_price, pool.liquidity, 0, max(amount_in, 0.0))
    sqrt_p, liq = pool.sqrt_price, max(pool.liquidity, 0.0)
    remaining, out, crossed = amount_in, 0.0, 0
    gamma = 1.0 - pool.fee
    bounds = _boundaries(pool, zero_for_one)
    idx = 0
    for _ in range(len(bounds) + 2):
        if remaining <= 0:
            break
        boundary = bounds[idx] if idx < len(bounds) else None
        if liq <= 0:
            if boundary is None:
                break  # liquidity exhausted and no more initialised ticks
            sqrt_p = boundary[0]
            liq = max(liq + boundary[1], 0.0)
            crossed += 1
            idx += 1
            continue
        eff = remaining * gamma
        if zero_for_one:
            target = boundary[0] if boundary else 0.0
            max_in = liq * (sqrt_p - target) / (sqrt_p * target) if target > 0 else math.inf
            if boundary is not None and eff >= max_in:
                out += liq * (sqrt_p - target)
                remaining -= max_in / gamma
                sqrt_p = target
                liq = max(liq + boundary[1], 0.0)
                crossed += 1
                idx += 1
            else:
                denom = liq + eff * sqrt_p
                # L * (sqrtP - sqrtP') written without the subtraction, which loses ~1e-7 of
                # relative precision when the trade is tiny against the pool's liquidity
                out += eff * sqrt_p * sqrt_p * liq / denom
                sqrt_p = liq * sqrt_p / denom
                remaining = 0.0
        else:
            target = boundary[0] if boundary else math.inf
            max_in = liq * (target - sqrt_p) if boundary else math.inf
            if boundary is not None and eff >= max_in:
                out += liq * (target - sqrt_p) / (sqrt_p * target)
                remaining -= max_in / gamma
                sqrt_p = target
                liq = max(liq + boundary[1], 0.0)
                crossed += 1
                idx += 1
            else:
                new_sqrt = sqrt_p + eff / liq
                out += eff / (sqrt_p * new_sqrt)  # == L * (sqrtP' - sqrtP) / (sqrtP * sqrtP')
                sqrt_p = new_sqrt
                remaining = 0.0
    remaining = max(remaining, 0.0)
    return V3SwapResult(amount_in - remaining, out, sqrt_p, liq, crossed, remaining)


def apply(pool: V3Pool, result: V3SwapResult) -> V3Pool:
    """Pool state after a swap (tick table is unchanged by swaps)."""
    return replace(pool, sqrt_price=result.sqrt_price_after, liquidity=result.liquidity_after)


def spot_out(pool: V3Pool, amount_in: float, zero_for_one: bool) -> float:
    price = pool.sqrt_price * pool.sqrt_price  # token1 per token0
    return amount_in * price if zero_for_one else amount_in / price


def price_impact_bps_v3(swap: V3Swap) -> float:
    pool = V3Pool.from_swap(swap)
    spot = spot_out(pool, swap.amount_in, swap.zero_for_one)
    if spot <= 0:
        return 0.0
    got = swap_exact_in(pool, swap.amount_in, swap.zero_for_one).amount_out
    return max(0.0, 1.0 - got / spot) * 1e4


def estimate_sandwich_v3(swap: V3Swap, attacker_capital_multiple: float = 10.0
                         ) -> SandwichEstimate:
    """Front-run / back-run through the same pool; capital capped by the active range's reserves."""
    pool = V3Pool.from_swap(swap)
    clean_res = swap_exact_in(pool, swap.amount_in, swap.zero_for_one)
    clean = clean_res.amount_out
    if clean < swap.min_out or clean <= 0 or pool.liquidity <= 0:
        return SandwichEstimate(False, 0.0, 0.0, clean, clean)
    x_virt, y_virt = virtual_reserves(pool.sqrt_price, pool.liquidity)
    cap = attacker_capital_multiple * (x_virt if swap.zero_for_one else y_virt)

    def run(a: float) -> tuple[float, float, float]:
        """(victim output, attacker proceeds, attacker input actually consumed)."""
        front = swap_exact_in(pool, a, swap.zero_for_one)
        p1 = apply(pool, front)
        victim = swap_exact_in(p1, swap.amount_in, swap.zero_for_one)
        p2 = apply(p1, victim)
        back = swap_exact_in(p2, front.amount_out, not swap.zero_for_one)
        return victim.amount_out, back.amount_out, front.amount_in_consumed

    def net(a: float) -> float:
        _, proceeds, spent = run(a)
        return proceeds - spent

    a, profit = optimal_sandwich(lambda a: run(a)[0], net, swap.min_out, cap)
    out_v = run(a)[0]
    return SandwichEstimate(profit > 0, a, max(profit, 0.0), out_v, clean)
