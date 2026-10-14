import math

import pytest

from txwarden.amm import amount_out, estimate_sandwich
from txwarden.amm_v3 import (
    Q96,
    V3Pool,
    apply,
    estimate_sandwich_v3,
    price_impact_bps_v3,
    sqrt_price_to_tick,
    sqrt_price_x96_to_float,
    swap_exact_in,
    tick_to_sqrt_price,
    virtual_reserves,
)
from txwarden.models import Swap, V3Swap, V3Tick

X, Y = 1000.0, 2_000_000.0
L = math.sqrt(X * Y)
SP = math.sqrt(Y / X)
TICK = sqrt_price_to_tick(SP)


def test_tick_price_round_trip():
    for t in (-887272, -1000, 0, 1, 76012, 887272):
        assert sqrt_price_to_tick(tick_to_sqrt_price(t) * (1 + 1e-9)) == t
    assert tick_to_sqrt_price(0) == 1.0
    assert sqrt_price_x96_to_float(Q96) == 1.0
    with pytest.raises(ValueError):
        sqrt_price_to_tick(0)


def test_virtual_reserves_recover_constant_product_pool():
    x, y = virtual_reserves(SP, L)
    assert x == pytest.approx(X) and y == pytest.approx(Y)
    assert virtual_reserves(0, L) == (0.0, 0.0)


@pytest.mark.parametrize("amount,zero_for_one", [(1.0, True), (50.0, True), (5000.0, False),
                                                 (300_000.0, False)])
def test_full_range_v3_equals_v2(amount, zero_for_one):
    pool = V3Pool(SP, L, 0.003)
    res = swap_exact_in(pool, amount, zero_for_one)
    expected = amount_out(amount, X, Y) if zero_for_one else amount_out(amount, Y, X)
    assert res.amount_out == pytest.approx(expected, rel=1e-9)
    assert res.fully_filled and res.ticks_crossed == 0


def test_price_moves_in_the_right_direction():
    pool = V3Pool(SP, L)
    assert swap_exact_in(pool, 10.0, True).sqrt_price_after < SP
    assert swap_exact_in(pool, 10.0, False).sqrt_price_after > SP


def test_zero_or_negative_input_is_a_noop():
    pool = V3Pool(SP, L)
    res = swap_exact_in(pool, 0.0, True)
    assert res.amount_out == 0 and res.sqrt_price_after == SP


def test_crossing_lower_tick_removes_liquidity_and_reports_partial_fill():
    # one position covering [TICK-100, TICK+100]; nothing outside
    pool = V3Pool(SP, L, 0.003, (V3Tick(TICK - 100, L), V3Tick(TICK + 100, -L)))
    res = swap_exact_in(pool, 1e6, True)
    assert res.ticks_crossed == 1
    assert res.liquidity_after == pytest.approx(0.0)
    assert res.remaining > 0 and not res.fully_filled
    assert res.sqrt_price_after == pytest.approx(tick_to_sqrt_price(TICK - 100))
    # the output equals the token1 held by the position between the two prices
    assert res.amount_out == pytest.approx(L * (SP - tick_to_sqrt_price(TICK - 100)), rel=1e-9)


def test_crossing_into_deeper_range_uses_new_liquidity():
    ticks = (V3Tick(TICK - 300, 2 * L), V3Tick(TICK - 100, -L), V3Tick(TICK + 100, -L))
    pool = V3Pool(SP, L, 0.003, ticks)
    small = swap_exact_in(pool, 3.0, True)
    assert small.ticks_crossed == 0 and small.liquidity_after == pytest.approx(L)
    mid = swap_exact_in(pool, 20.0, True)
    assert mid.ticks_crossed == 1 and mid.liquidity_after == pytest.approx(2 * L)
    assert mid.fully_filled
    # more liquidity below means less impact than a single-range pool would show for the tail
    single = V3Pool(SP, L, 0.003, (V3Tick(TICK - 100, L), V3Tick(TICK + 100, -L)))
    assert mid.amount_out > swap_exact_in(single, 20.0, True).amount_out


def test_crossing_upward_adds_liquidity_net():
    ticks = (V3Tick(TICK - 100, L), V3Tick(TICK + 100, 3 * L), V3Tick(TICK + 400, -4 * L))
    pool = V3Pool(SP, L, 0.003, ticks)
    res = swap_exact_in(pool, 60_000.0, False)
    assert res.ticks_crossed >= 1 and res.liquidity_after == pytest.approx(4 * L)


def test_empty_liquidity_jumps_to_next_tick():
    pool = V3Pool(SP, 0.0, 0.003, (V3Tick(TICK - 100, L), V3Tick(TICK + 100, -L)))
    res = swap_exact_in(pool, 1.0, True)
    assert res.ticks_crossed == 1 and res.amount_out == 0 and res.remaining == pytest.approx(1.0)


def test_apply_updates_pool_state():
    pool = V3Pool(SP, L)
    res = swap_exact_in(pool, 10.0, True)
    p2 = apply(pool, res)
    assert p2.sqrt_price == res.sqrt_price_after and p2.ticks == pool.ticks


def test_fee_reduces_output():
    a = swap_exact_in(V3Pool(SP, L, 0.0005), 10.0, True).amount_out
    b = swap_exact_in(V3Pool(SP, L, 0.01), 10.0, True).amount_out
    assert a > b


def test_price_impact_increases_with_size_and_is_zero_for_zero():
    small = price_impact_bps_v3(V3Swap(1.0, 0, SP, L))
    big = price_impact_bps_v3(V3Swap(100.0, 0, SP, L))
    assert 0 < small < big
    assert price_impact_bps_v3(V3Swap(1.0, 0, 0.0, L)) == 0.0


def test_v3_sandwich_matches_v2_on_equivalent_pool():
    clean = amount_out(20.0, X, Y)
    v3 = estimate_sandwich_v3(V3Swap(20.0, clean * 0.98, SP, L))
    v2 = estimate_sandwich(Swap(20.0, clean * 0.98, X, Y))
    assert v3.feasible and v3.attacker_profit == pytest.approx(v2.attacker_profit, rel=1e-2)
    assert v3.victim_out_attacked >= clean * 0.98 - 1e-6


def test_v3_sandwich_zero_tolerance_unprofitable_and_unreachable_floor_infeasible():
    clean = swap_exact_in(V3Pool(SP, L), 20.0, True).amount_out
    assert estimate_sandwich_v3(V3Swap(20.0, clean, SP, L)).attacker_profit == pytest.approx(0, abs=1e-6)
    assert not estimate_sandwich_v3(V3Swap(20.0, clean * 2, SP, L)).feasible
    assert not estimate_sandwich_v3(V3Swap(20.0, 0, SP, 0.0)).feasible


def test_v3_sandwich_one_for_zero_direction():
    """token1 -> token0 on the equivalent V2 pool (reserves swapped) must agree on feasibility.

    A sandwich is only profitable when the victim's own price push exceeds twice the pool fee:
    5_000 token1 into a 2_000_000 reserve pushes the price 0.5% < 0.6%, so it is NOT sandwichable
    at any size; 40_000 (2%) is.
    """
    for amount, profitable in ((5000.0, False), (40_000.0, True)):
        clean = swap_exact_in(V3Pool(SP, L), amount, False).amount_out
        v3 = estimate_sandwich_v3(V3Swap(amount, clean * 0.97, SP, L, zero_for_one=False))
        v2 = estimate_sandwich(Swap(amount, amount_out(amount, Y, X) * 0.97, Y, X))
        assert v3.feasible is profitable and v2.feasible is profitable
        if profitable:
            assert v3.attacker_profit == pytest.approx(v2.attacker_profit, rel=1e-2)
            assert v3.victim_out_attacked >= clean * 0.97 - 1e-9


def test_v3_sandwich_below_twice_fee_push_is_infeasible_in_both_directions():
    for zero_for_one, amount in ((True, 2.0), (False, 4000.0)):  # 0.2% of the reserve
        clean = swap_exact_in(V3Pool(SP, L), amount, zero_for_one).amount_out
        est = estimate_sandwich_v3(V3Swap(amount, clean * 0.9, SP, L, zero_for_one=zero_for_one))
        assert not est.feasible and est.attacker_profit == 0.0
        assert est.attacker_frontrun == 0.0  # the optimiser reports "do nothing", not a_max


def test_v3_sandwich_with_ticks_is_bounded_by_range():
    """A position covering +/-2000 ticks (~ +/-10% in sqrt price) holds ~105 token0 of capacity.

    The attacker cannot push the price through the lower bound without exhausting the range,
    after which the victim would receive nothing; the front-run must therefore stay inside it.
    """
    ticks = (V3Tick(TICK - 2000, L), V3Tick(TICK + 2000, -L))
    pool = V3Pool(SP, L, 0.003, ticks)
    capacity = L * (SP - tick_to_sqrt_price(TICK - 2000)) / (SP * tick_to_sqrt_price(TICK - 2000))
    assert 100 < capacity < 110
    clean = swap_exact_in(pool, 20.0, True).amount_out
    est = estimate_sandwich_v3(V3Swap(20.0, clean * 0.9, SP, L, ticks=ticks))
    assert est.feasible and est.attacker_profit > 0
    assert est.victim_out_attacked >= clean * 0.9 - 1e-9
    assert est.attacker_frontrun + 20.0 <= capacity  # attacker + victim both fit in the range
    # the same trade in a position that is too narrow for it is reported as an unfilled trade
    narrow = V3Pool(SP, L, 0.003, (V3Tick(TICK - 100, L), V3Tick(TICK + 100, -L)))
    assert not swap_exact_in(narrow, 20.0, True).fully_filled


def test_v3_sandwich_optimiser_beats_the_largest_feasible_front_run():
    """Profit is maximised, not just taken at the slippage limit (regression: V3 used a_max)."""
    clean = swap_exact_in(V3Pool(SP, L), 5.0, True).amount_out
    swap = V3Swap(5.0, clean * 0.5, SP, L)  # very loose floor: a_max is far past the optimum
    est = estimate_sandwich_v3(swap)
    pool = V3Pool(SP, L, 0.003)

    def profit(a: float) -> float:
        front = swap_exact_in(pool, a, True)
        p1 = apply(pool, front)
        p2 = apply(p1, swap_exact_in(p1, 5.0, True))
        return swap_exact_in(p2, front.amount_out, False).amount_out - a

    assert est.attacker_profit == pytest.approx(profit(est.attacker_frontrun))
    for factor in (0.25, 0.5, 2.0, 4.0, 100.0):
        assert est.attacker_profit >= profit(est.attacker_frontrun * factor) - 1e-12


# --------------------------------------------------------------------------- integer oracle

def _ref_exact_in_one_range(sqrt_x96: int, liq: int, amount_in: int, fee_pips: int,
                            zero_for_one: bool) -> tuple[int, int]:
    """Uniswap V3 ``SwapMath.computeSwapStep`` (exact input, no tick boundary hit) in the
    contracts' own integer arithmetic: ``SqrtPriceMath.getNextSqrtPriceFromInput`` followed by
    ``getAmount{0,1}Delta`` with round-down. Returns (next sqrtPriceX96, amount out)."""
    less_fee = amount_in * (10**6 - fee_pips) // 10**6
    if zero_for_one:
        num = liq << 96
        denom = num + less_fee * sqrt_x96
        nxt = -(-num * sqrt_x96 // denom)  # mulDivRoundingUp
        return nxt, liq * (sqrt_x96 - nxt) // Q96
    nxt = sqrt_x96 + (less_fee << 96) // liq
    return nxt, (liq << 96) * (nxt - sqrt_x96) // nxt // sqrt_x96


@pytest.mark.parametrize("zero_for_one,amount_in,fee_pips", [
    (True, 10**11, 3000), (True, 5 * 10**12, 500), (True, 10**5, 10000),
    (False, 10**18, 3000), (False, 25 * 10**18, 500), (False, 10**9, 100),
])
def test_float_swap_matches_contract_integer_math(zero_for_one, amount_in, fee_pips):
    """USDC(6)/WETH(18)-like pool: token0 = USDC, price ~ 2000 USDC/ETH, L = 2e18."""
    sqrt_x96 = int(math.sqrt(1e18 / 2000e6) * Q96)
    liq = 2 * 10**18
    ref_next, ref_out = _ref_exact_in_one_range(sqrt_x96, liq, amount_in, fee_pips, zero_for_one)
    pool = V3Pool(sqrt_x96 / Q96, float(liq), fee_pips / 1e6)
    res = swap_exact_in(pool, float(amount_in), zero_for_one)
    assert res.sqrt_price_after == pytest.approx(ref_next / Q96, rel=1e-9)
    assert res.amount_out == pytest.approx(ref_out, rel=1e-9, abs=1.0)
    assert res.ticks_crossed == 0 and res.fully_filled


def test_tick_crossing_matches_integer_math_step_by_step():
    """Walk a two-range pool with the contracts' loop: stop at the tick, apply -liquidityNet,
    continue with the remaining input. The float implementation must land on the same output."""
    sqrt_x96 = int(math.sqrt(1e18 / 2000e6) * Q96)
    liq_a, liq_b = 10**18, 3 * 10**18
    cur_tick = sqrt_price_to_tick(sqrt_x96 / Q96)
    boundary_tick = cur_tick - 600
    boundary_x96 = int(tick_to_sqrt_price(boundary_tick) * Q96)
    fee_pips, amount_in = 3000, 10**13

    # step 1: token0 needed to reach the boundary within range A (rounded up, as in the contract)
    to_boundary = -(-(liq_a << 96) * (sqrt_x96 - boundary_x96) // boundary_x96 // sqrt_x96)
    gross_to_boundary = -(-to_boundary * 10**6 // (10**6 - fee_pips))
    assert amount_in > gross_to_boundary  # the swap must cross
    out1 = liq_a * (sqrt_x96 - boundary_x96) // Q96
    _next2, out2 = _ref_exact_in_one_range(boundary_x96, liq_b, amount_in - gross_to_boundary,
                                           fee_pips, True)

    # liquidityNet is what is ADDED when crossing the tick left-to-right: B below, A above
    ticks = (V3Tick(boundary_tick, liq_a - liq_b), V3Tick(cur_tick + 10_000, -liq_a))
    pool = V3Pool(sqrt_x96 / Q96, float(liq_a), fee_pips / 1e6, ticks)
    res = swap_exact_in(pool, float(amount_in), True)
    assert res.ticks_crossed == 1 and res.liquidity_after == pytest.approx(liq_b)
    assert res.amount_out == pytest.approx(out1 + out2, rel=1e-6)
