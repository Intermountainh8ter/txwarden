import pytest

from txwarden.amm import amount_out, estimate_sandwich, price_impact_bps
from txwarden.models import Swap


def test_amount_out_matches_uniswap_v2_formula():
    # 1 ETH into a 100 ETH / 200k USDC pool at 0.3% fee
    out = amount_out(1.0, 100.0, 200_000.0, 0.003)
    assert out == pytest.approx(1.0 * 0.997 * 200_000 / (100 + 0.997))


def test_zero_in_gives_zero_out():
    assert amount_out(0, 100, 100) == 0.0


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
