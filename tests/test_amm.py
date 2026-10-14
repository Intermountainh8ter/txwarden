import pytest

from txwarden.amm import (
    amount_in_for_out,
    amount_out,
    amount_out_path,
    estimate_sandwich,
    estimate_sandwich_path,
    price_impact_bps,
    price_impact_bps_path,
    spot_out_path,
)
from txwarden.models import Hop, PathSwap, Swap


def test_amount_out_matches_uniswap_v2_formula():
    # 1 ETH into a 100 ETH / 200k USDC pool at 0.3% fee
    out = amount_out(1.0, 100.0, 200_000.0, 0.003)
    assert out == pytest.approx(1.0 * 0.997 * 200_000 / (100 + 0.997))


def test_zero_in_gives_zero_out():
    assert amount_out(0, 100, 100) == 0.0
    assert amount_out(10, 0, 100) == 0.0


def test_amount_in_for_out_inverts_amount_out():
    dy = amount_out(7.0, 1000.0, 3000.0)
    assert amount_in_for_out(dy, 1000.0, 3000.0) == pytest.approx(7.0)
    assert amount_in_for_out(3000.0, 1000.0, 3000.0) == float("inf")


def test_price_impact_grows_with_size():
    small = price_impact_bps(Swap(1, 0, 1000, 1000))
    big = price_impact_bps(Swap(100, 0, 1000, 1000))
    assert 0 < small < big


def test_sandwich_infeasible_when_min_out_unreachable():
    swap = Swap(10, 1e9, 1000, 1000)  # demands more than the pool can pay
    assert not estimate_sandwich(swap).feasible


def test_sandwich_zero_slippage_is_not_profitable():
    clean = amount_out(10, 1000, 1000)
    est = estimate_sandwich(Swap(10, clean, 1000, 1000))
    assert est.attacker_profit == pytest.approx(0.0, abs=1e-9)


def test_sandwich_profit_increases_with_tolerance():
    clean = amount_out(20, 1000, 1000)
    tight = estimate_sandwich(Swap(20, clean * 0.99, 1000, 1000)).attacker_profit
    loose = estimate_sandwich(Swap(20, clean * 0.90, 1000, 1000)).attacker_profit
    assert loose > tight >= 0


def test_sandwich_respects_min_out():
    clean = amount_out(20, 1000, 1000)
    swap = Swap(20, clean * 0.95, 1000, 1000)
    est = estimate_sandwich(swap)
    assert est.victim_out_attacked >= swap.min_out - 1e-6


def test_sandwich_capital_cap_binds_for_absurd_slippage():
    clean = amount_out(20, 1000, 1000)
    est = estimate_sandwich(Swap(20, clean * 0.01, 1000, 1000), attacker_capital_multiple=2.0)
    assert est.attacker_frontrun == pytest.approx(2000.0)


# --------------------------------------------------------------------------- multi-hop

HOPS = (Hop(1000.0, 2_000_000.0), Hop(2_000_000.0, 500.0))


def test_path_amount_out_chains_hops():
    first = amount_out(10, 1000.0, 2_000_000.0)
    expected = amount_out(first, 2_000_000.0, 500.0)
    assert amount_out_path(10, HOPS) == pytest.approx(expected)


def test_path_spot_and_impact():
    assert spot_out_path(10, HOPS) == pytest.approx(10 * 2000 * (500 / 2_000_000))
    imp = price_impact_bps_path(PathSwap(10, 0, HOPS))
    single = price_impact_bps(Swap(10, 0, 1000.0, 2_000_000.0))
    assert imp > single > 0  # two fees and two impacts


def test_path_sandwich_profit_grows_with_tolerance_and_respects_floor():
    clean = amount_out_path(10, HOPS)
    tight = estimate_sandwich_path(PathSwap(10, clean * 0.995, HOPS))
    loose = estimate_sandwich_path(PathSwap(10, clean * 0.9, HOPS))
    assert loose.attacker_profit > tight.attacker_profit >= 0
    assert loose.victim_out_attacked >= clean * 0.9 - 1e-9
    assert not estimate_sandwich_path(PathSwap(10, clean * 2, HOPS)).feasible


def test_path_sandwich_matches_single_hop_when_one_hop():
    hop = (Hop(1000.0, 1000.0),)
    clean = amount_out(20, 1000.0, 1000.0)
    a = estimate_sandwich_path(PathSwap(20, clean * 0.95, hop))
    b = estimate_sandwich(Swap(20, clean * 0.95, 1000.0, 1000.0))
    assert a.attacker_profit == pytest.approx(b.attacker_profit, rel=1e-6)


def test_empty_path_is_infeasible():
    assert not estimate_sandwich_path(PathSwap(1, 0, ())).feasible
