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
    clean = swap_exact_in(V3Pool(SP, L), 5000.0, False).amount_out
    est = estimate_sandwich_v3(V3Swap(5000.0, clean * 0.97, SP, L, zero_for_one=False))
    assert est.feasible and est.attacker_profit > 0


def test_v3_sandwich_with_ticks_is_bounded_by_range():
    ticks = (V3Tick(TICK - 100, L), V3Tick(TICK + 100, -L))
    clean = swap_exact_in(V3Pool(SP, L, 0.003, ticks), 2.0, True).amount_out
    est = estimate_sandwich_v3(V3Swap(2.0, clean * 0.9, SP, L, ticks=ticks))
    assert est.feasible
    assert est.victim_out_attacked >= clean * 0.9 - 1e-9
