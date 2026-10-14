"""Seeded randomised invariants (stdlib ``random``; no network, no hypothesis dependency).

Each test draws a few hundred cases from a fixed seed, so a failure is reproducible: the assertion
message carries the case index and the parameters.
"""
from __future__ import annotations

import math
import random
from itertools import pairwise

import pytest

from txwarden.abi import (
    SELECTORS,
    AbiError,
    decode,
    decode_call,
    decode_v3_path,
    encode,
    encode_call,
    encode_v3_path,
    parse_type,
)
from txwarden.amm import (
    amount_in_for_out,
    amount_out,
    amount_out_path,
    estimate_sandwich,
    estimate_sandwich_path,
    price_impact_bps,
    price_impact_bps_path,
)
from txwarden.amm_v3 import (
    V3Pool,
    apply,
    estimate_sandwich_v3,
    price_impact_bps_v3,
    sqrt_price_to_tick,
    swap_exact_in,
    tick_to_sqrt_price,
)
from txwarden.config import parse_toml, parse_toml_subset
from txwarden.models import (
    Approval,
    Hop,
    OperatorApproval,
    PathSwap,
    Permit,
    SimResult,
    Swap,
    Transfer,
    Tx,
    V3Swap,
    V3Tick,
    Verdict,
)
from txwarden.risk import RULES, UNLIMITED, PolicyConfig, assess

N = 300


def rng_for(name: str) -> random.Random:
    return random.Random(f"txwarden-properties/{name}")


def log_uniform(rng: random.Random, lo: float, hi: float) -> float:
    return math.exp(rng.uniform(math.log(lo), math.log(hi)))


# --------------------------------------------------------------------------- constant product

def random_pool(rng):
    x = log_uniform(rng, 1e3, 1e12)
    y = x * log_uniform(rng, 1e-4, 1e4)
    return x, y, rng.choice([0.0005, 0.003, 0.01])


def test_constant_product_k_never_decreases_and_output_is_bounded():
    rng = rng_for("k")
    for i in range(N):
        x, y, fee = random_pool(rng)
        dx = x * log_uniform(rng, 1e-6, 50)
        out = amount_out(dx, x, y, fee)
        assert 0 <= out < y, (i, x, y, dx)
        assert (x + dx) * (y - out) >= x * y * (1 - 1e-12), (i, x, y, dx, fee)


def test_amount_in_for_out_inverts_amount_out():
    rng = rng_for("inverse")
    for i in range(N):
        x, y, fee = random_pool(rng)
        dx = x * log_uniform(rng, 1e-5, 5)
        dy = amount_out(dx, x, y, fee)
        assert amount_in_for_out(dy, x, y, fee) == pytest.approx(dx, rel=1e-9), (i, x, y, fee)


def test_output_increases_with_input_and_price_impact_is_monotonic():
    rng = rng_for("impact-v2")
    for i in range(N):
        x, y, fee = random_pool(rng)
        a1 = x * log_uniform(rng, 1e-6, 10)
        a2 = a1 * rng.uniform(1.0001, 20)
        assert amount_out(a2, x, y, fee) >= amount_out(a1, x, y, fee), i
        i1 = price_impact_bps(Swap(a1, 0, x, y, fee))
        i2 = price_impact_bps(Swap(a2, 0, x, y, fee))
        assert 0 <= i1 <= i2 + 1e-9 and i2 < 1e4, (i, x, y, a1, a2)


def test_multihop_price_impact_is_monotonic_and_chaining_loses_value():
    rng = rng_for("impact-path")
    for i in range(100):
        hops = tuple(Hop(*random_pool(rng)[:2]) for _ in range(rng.randint(2, 3)))
        a1 = hops[0].reserve_in * log_uniform(rng, 1e-6, 1)
        a2 = a1 * rng.uniform(1.001, 10)
        assert price_impact_bps_path(PathSwap(a1, 0, hops)) <= price_impact_bps_path(
            PathSwap(a2, 0, hops)) + 1e-9, i
        assert amount_out_path(a1, hops) <= amount_out_path(a2, hops), i


# --------------------------------------------------------------------------- sandwiches

def test_v2_sandwich_profit_is_never_negative_and_respects_the_victims_floor():
    rng = rng_for("sandwich-v2")
    for i in range(N):
        x, y, fee = random_pool(rng)
        dx = x * log_uniform(rng, 1e-4, 0.5)
        tol = rng.choice([0.0, 0.001, 0.005, 0.02, 0.1, 0.5])
        clean = amount_out(dx, x, y, fee)
        swap = Swap(dx, clean * (1 - tol), x, y, fee)
        est = estimate_sandwich(swap)
        assert est.attacker_profit >= 0 and est.attacker_frontrun >= 0, (i, swap)
        assert est.victim_out_attacked >= swap.min_out * (1 - 1e-9), (i, swap)
        assert est.victim_out_attacked <= clean * (1 + 1e-12), (i, swap)
        if not est.feasible:
            assert est.attacker_profit == 0.0


def test_v2_sandwich_profit_is_monotone_in_tolerance():
    rng = rng_for("sandwich-monotone")
    for i in range(150):
        x, y, fee = random_pool(rng)
        dx = x * log_uniform(rng, 1e-3, 0.3)
        clean = amount_out(dx, x, y, fee)
        tols = sorted(rng.uniform(0, 0.3) for _ in range(3))
        profits = [estimate_sandwich(Swap(dx, clean * (1 - t), x, y, fee)).attacker_profit
                   for t in tols]
        assert all(b >= a - 1e-9 * dx for a, b in pairwise(profits)), (i, tols, profits)


def test_v2_sandwich_optimum_beats_random_alternative_front_runs():
    rng = rng_for("sandwich-optimal")
    for i in range(100):
        x, y, fee = random_pool(rng)
        dx = x * log_uniform(rng, 1e-2, 0.3)
        clean = amount_out(dx, x, y, fee)
        swap = Swap(dx, clean * 0.9, x, y, fee)
        est = estimate_sandwich(swap)

        def profit(a, x=x, y=y, fee=fee, dx=dx):
            out_a = amount_out(a, x, y, fee)
            x1, y1 = x + a, y - out_a
            out_v = amount_out(dx, x1, y1, fee)
            return amount_out(out_a, y1 - out_v, x1 + dx, fee) - a, out_v

        for _ in range(10):
            a = est.attacker_frontrun * rng.uniform(0, 3) if est.attacker_frontrun else x * rng.random()
            p, out_v = profit(a)
            if out_v >= swap.min_out:  # alternative is also admissible
                assert p <= est.attacker_profit + 1e-9 * dx, (i, a, p, est)


def test_path_sandwich_profit_is_never_negative():
    rng = rng_for("sandwich-path")
    for i in range(100):
        hops = tuple(Hop(*random_pool(rng)[:2]) for _ in range(rng.randint(2, 3)))
        dx = hops[0].reserve_in * log_uniform(rng, 1e-3, 0.2)
        clean = amount_out_path(dx, hops)
        swap = PathSwap(dx, clean * rng.choice([0.5, 0.9, 0.98, 1.0]), hops)
        est = estimate_sandwich_path(swap)
        assert est.attacker_profit >= 0, i
        assert est.victim_out_attacked >= swap.min_out * (1 - 1e-9), i


# --------------------------------------------------------------------------- V3

def random_v3_pool(rng, with_ticks: bool) -> V3Pool:
    tick = rng.randint(-200_000, 200_000)
    sp = tick_to_sqrt_price(tick)
    liq = log_uniform(rng, 1e10, 1e20)
    ticks: tuple[V3Tick, ...] = ()
    if with_ticks:
        lo, hi = tick - rng.randint(50, 3000), tick + rng.randint(50, 3000)
        mid_lo, mid_hi = tick - rng.randint(5, 40), tick + rng.randint(5, 40)
        extra = liq * rng.uniform(0.1, 2)
        ticks = (V3Tick(lo, extra), V3Tick(mid_lo, liq - extra + extra * 0), V3Tick(mid_hi, -liq),
                 V3Tick(hi, -extra))
    return V3Pool(sp, liq, rng.choice([0.0005, 0.003, 0.01]), ticks)


@pytest.mark.parametrize("with_ticks", [False, True])
def test_v3_swaps_conserve_input_and_move_price_the_right_way(with_ticks):
    rng = rng_for(f"v3-conserve-{with_ticks}")
    for i in range(N):
        pool = random_v3_pool(rng, with_ticks)
        zfo = rng.random() < 0.5
        x_virt = pool.liquidity / pool.sqrt_price
        y_virt = pool.liquidity * pool.sqrt_price
        amount = (x_virt if zfo else y_virt) * log_uniform(rng, 1e-6, 5)
        res = swap_exact_in(pool, amount, zfo)
        assert res.amount_in_consumed + res.remaining == pytest.approx(amount, rel=1e-9), i
        assert res.amount_out >= 0 and res.liquidity_after >= 0, i
        if res.amount_in_consumed > 0:
            moved = res.sqrt_price_after < pool.sqrt_price if zfo else (
                res.sqrt_price_after > pool.sqrt_price)
            assert moved, (i, pool, amount, zfo)


@pytest.mark.parametrize("with_ticks", [False, True])
def test_v3_output_never_exceeds_spot_and_round_trips_never_profit(with_ticks):
    rng = rng_for(f"v3-roundtrip-{with_ticks}")
    for i in range(N):
        pool = random_v3_pool(rng, with_ticks)
        zfo = rng.random() < 0.5
        base = pool.liquidity / pool.sqrt_price if zfo else pool.liquidity * pool.sqrt_price
        amount = base * log_uniform(rng, 1e-6, 0.5)
        fwd = swap_exact_in(pool, amount, zfo)
        price = pool.sqrt_price ** 2
        spot = fwd.amount_in_consumed * (price if zfo else 1 / price)
        assert fwd.amount_out <= spot * (1 + 1e-9), (i, pool, amount, zfo)
        back = swap_exact_in(apply(pool, fwd), fwd.amount_out, not zfo)
        assert back.amount_out <= fwd.amount_in_consumed * (1 + 1e-9), (i, pool, amount, zfo)


@pytest.mark.parametrize("with_ticks", [False, True])
def test_v3_price_impact_is_monotonic_in_size(with_ticks):
    rng = rng_for(f"v3-impact-{with_ticks}")
    for i in range(150):
        pool = random_v3_pool(rng, with_ticks)
        zfo = rng.random() < 0.5
        base = pool.liquidity / pool.sqrt_price if zfo else pool.liquidity * pool.sqrt_price
        a1 = base * log_uniform(rng, 1e-6, 0.05)
        a2 = a1 * rng.uniform(1.001, 5)

        def impact(a, pool=pool, zfo=zfo):
            return price_impact_bps_v3(V3Swap(a, 0, pool.sqrt_price, pool.liquidity, pool.fee, zfo,
                                              pool.ticks))

        assert impact(a1) <= impact(a2) + 1e-6, (i, pool, a1, a2)


def test_v3_sandwich_profit_never_negative_and_floor_respected():
    rng = rng_for("v3-sandwich")
    for i in range(120):
        pool = random_v3_pool(rng, with_ticks=rng.random() < 0.5)
        zfo = rng.random() < 0.5
        base = pool.liquidity / pool.sqrt_price if zfo else pool.liquidity * pool.sqrt_price
        amount = base * log_uniform(rng, 1e-4, 0.1)
        clean = swap_exact_in(pool, amount, zfo).amount_out
        tol = rng.choice([0.0, 0.005, 0.03, 0.2])
        swap = V3Swap(amount, clean * (1 - tol), pool.sqrt_price, pool.liquidity, pool.fee, zfo,
                      pool.ticks)
        est = estimate_sandwich_v3(swap)
        assert est.attacker_profit >= 0, (i, swap)
        if est.feasible:
            assert est.victim_out_attacked >= swap.min_out * (1 - 1e-9), (i, swap)


def test_tick_price_round_trip_over_the_whole_range():
    rng = rng_for("ticks")
    for _ in range(N):
        t = rng.randint(-887_272, 887_272)
        assert sqrt_price_to_tick(tick_to_sqrt_price(t) * (1 + 1e-12)) == t


def test_equivalent_v2_and_v3_single_range_pools_agree_on_swaps():
    rng = rng_for("v2-v3-equivalence")
    for i in range(N):
        x, y, fee = random_pool(rng)
        liq = math.sqrt(x * y)
        pool = V3Pool(math.sqrt(y / x), liq, fee)
        amount = x * log_uniform(rng, 1e-6, 1)
        assert swap_exact_in(pool, amount, True).amount_out == pytest.approx(
            amount_out(amount, x, y, fee), rel=1e-9), i
        amount_b = y * log_uniform(rng, 1e-6, 1)
        assert swap_exact_in(pool, amount_b, False).amount_out == pytest.approx(
            amount_out(amount_b, y, x, fee), rel=1e-9), i


# --------------------------------------------------------------------------- ABI

ALPHABET = "abcXYZ 012_-é漢😀"


def rand_type_and_value(rng: random.Random, depth: int = 0):
    kinds = ["uint", "int", "address", "bool", "bytesN", "bytes", "string"]
    if depth < 3:
        kinds += ["array", "array", "fixed", "tuple"]
    kind = rng.choice(kinds)
    if kind == "uint":
        bits = rng.choice(range(8, 257, 8))
        return f"uint{bits}", rng.choice([0, 1, (1 << bits) - 1, rng.randrange(1 << bits)])
    if kind == "int":
        bits = rng.choice(range(8, 257, 8))
        lim = 1 << (bits - 1)
        return f"int{bits}", rng.choice([0, -1, lim - 1, -lim, rng.randrange(-lim, lim)])
    if kind == "address":
        return "address", "0x" + rng.randbytes(20).hex()
    if kind == "bool":
        return "bool", rng.random() < 0.5
    if kind == "bytesN":
        n = rng.randint(1, 32)
        return f"bytes{n}", "0x" + rng.randbytes(n).hex()
    if kind == "bytes":
        return "bytes", "0x" + rng.randbytes(rng.choice([0, 1, 31, 32, 33, 64, rng.randint(0, 100)])).hex()
    if kind == "string":
        return "string", "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 50)))
    if kind == "array":
        t, _ = rand_type_and_value(rng, depth + 1)
        vals = [rand_value_for(rng, t) for _ in range(rng.randint(0, 3))]
        return f"{t}[]", vals
    if kind == "fixed":
        t, _ = rand_type_and_value(rng, depth + 1)
        n = rng.randint(1, 3)
        return f"{t}[{n}]", [rand_value_for(rng, t) for _ in range(n)]
    comps = [rand_type_and_value(rng, depth + 1) for _ in range(rng.randint(1, 3))]
    return "(" + ",".join(t for t, _ in comps) + ")", [v for _, v in comps]


def rand_value_for(rng: random.Random, type_str: str):
    t = parse_type(type_str)
    if t.base == "uint":
        return rng.randrange(1 << t.size)
    if t.base == "int":
        return rng.randrange(-(1 << (t.size - 1)), 1 << (t.size - 1))
    if t.base == "address":
        return "0x" + rng.randbytes(20).hex()
    if t.base == "bool":
        return rng.random() < 0.5
    if t.base == "bytes":
        n = t.size or rng.randint(0, 70)
        return "0x" + rng.randbytes(n).hex()
    if t.base == "string":
        return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 40)))
    if t.base == "array":
        n = t.length if t.length >= 0 else rng.randint(0, 3)
        return [rand_value_for(rng, str(t.elem)) for _ in range(n)]
    return [rand_value_for(rng, str(c)) for c in t.components]


def test_abi_round_trip_over_random_nested_types():
    rng = rng_for("abi-roundtrip")
    for i in range(N):
        pairs = [rand_type_and_value(rng) for _ in range(rng.randint(1, 4))]
        types, values = [p[0] for p in pairs], [p[1] for p in pairs]
        enc = encode(types, values)
        assert len(enc) % 32 == 0, (i, types)
        assert decode(types, enc) == values, (i, types, values)
        assert [str(parse_type(t)) for t in types] == types


def test_abi_encoding_is_canonical_for_dynamic_offsets():
    rng = rng_for("abi-offsets")
    for i in range(100):
        pairs = [rand_type_and_value(rng) for _ in range(rng.randint(2, 4))]
        types, values = [p[0] for p in pairs], [p[1] for p in pairs]
        head = sum(parse_type(t).static_size for t in types)
        enc = encode(types, values)
        assert len(enc) >= head, i
        # every dynamic offset points inside the encoding and is word aligned
        pos = 0
        for t in types:
            pt = parse_type(t)
            if pt.is_dynamic:
                off = int.from_bytes(enc[pos:pos + 32], "big")
                assert off % 32 == 0 and head <= off <= len(enc), (i, types)
            pos += pt.static_size


def test_decoder_never_raises_anything_but_abierror_on_random_bytes():
    rng = rng_for("abi-fuzz")
    for i in range(N):
        types = [rand_type_and_value(rng)[0] for _ in range(rng.randint(1, 3))]
        blob = rng.randbytes(rng.choice([0, 1, 31, 32, 33, 64, 96, 200, 500]))
        try:
            decode(types, blob)
        except AbiError:
            pass
        except Exception as e:
            pytest.fail(f"case {i}: {types} on {len(blob)} bytes raised {type(e).__name__}: {e}")


def test_decode_call_is_total_over_registered_selectors_and_random_tails():
    rng = rng_for("decode-call-fuzz")
    selectors = list(SELECTORS)
    for i in range(N * 2):
        sel = rng.choice(selectors)
        tail = rng.randbytes(rng.choice([0, 3, 32, 64, 100, 300, 700]))
        d = decode_call(sel + tail.hex())
        assert d.kind  # never raises
        if d.kind == "malformed":
            assert d.error, (i, sel)
    for _ in range(N):
        d = decode_call("0x" + rng.randbytes(rng.randint(0, 80)).hex())
        assert d.kind in ("empty", "malformed", "unknown") or d.selector in SELECTORS


def test_registered_signatures_round_trip_with_random_arguments():
    rng = rng_for("registry-roundtrip")
    skipped = {"universal_router_execute", "multicall", "multicall_deadline",
               "multicall_previous_block", "multicall3_aggregate", "multicall3_aggregate3",
               "multicall3_try_aggregate"}  # post-processing decodes the nested payloads
    for spec in SELECTORS.values():
        if spec.kind in skipped:
            continue
        for _ in range(5):
            values = [rand_value_for(rng, str(t)) for t in spec.types]
            for v, t in zip(values, spec.types):  # V3 paths must be a legal length
                if t.base == "tuple" and any(c.base == "bytes" and c.size == 0 for c in t.components):
                    i = next(j for j, c in enumerate(t.components) if c.base == "bytes")
                    v[i] = encode_v3_path(["0x" + "11" * 20, "0x" + "22" * 20], [3000])
            data = encode_call(spec.signature, values)
            d = decode_call(data)
            assert d.selector == spec.selector, spec.signature
            assert d.kind != "malformed", (spec.signature, d.error)


def test_v3_path_round_trip():
    rng = rng_for("v3-path")
    for i in range(N):
        n = rng.randint(2, 5)
        tokens = ["0x" + rng.randbytes(20).hex() for _ in range(n)]
        fees = [rng.choice([100, 500, 3000, 10000, rng.randrange(1 << 24)]) for _ in range(n - 1)]
        assert decode_v3_path(encode_v3_path(tokens, fees)) == {"tokens": tokens, "fees": fees}, i


# --------------------------------------------------------------------------- engine invariants

ADDRS = ["0x" + f"{n:02x}" * 20 for n in range(0x20, 0x2A)]


def random_scenario(rng: random.Random) -> tuple[Tx, SimResult, PolicyConfig]:
    user = ADDRS[0]
    tx = Tx(user, rng.choice(ADDRS), chain_id=rng.choice([1, 1, 1, 10]))
    sim = SimResult(rng.random() > 0.1, gas_used=rng.choice([0, 50_000, 900_000, 20_000_000]),
                    revert_reason="x", block_timestamp=1_700_000_000, call_kind="erc20_approve")
    for _ in range(rng.randint(0, 3)):
        sim.approvals.append(Approval(tx.to, user, rng.choice(ADDRS), rng.choice(
            [0, 5, UNLIMITED, 2**160 - 1]), rng.choice(["", "permit2"])))
    for _ in range(rng.randint(0, 2)):
        sim.operator_approvals.append(OperatorApproval(tx.to, user, rng.choice(ADDRS),
                                                       rng.random() < 0.8))
    for _ in range(rng.randint(0, 2)):
        sim.permits.append(Permit(tx.to, user, rng.choice(ADDRS), rng.choice([0, 5, UNLIMITED]),
                                  rng.choice([1_700_000_100, 1_800_000_000, 2**41]),
                                  rng.choice(["eip2612", "permit2"])))
    for _ in range(rng.randint(0, 3)):
        sim.transfers.append(Transfer(tx.to, user, rng.choice(ADDRS), rng.randint(1, 100),
                                      rng.choice([None, 100, 1000])))
    if rng.random() < 0.5:
        x = 10 ** rng.randint(3, 9)
        dx = x * rng.choice([0.001, 0.01, 0.1])
        sim.swap = Swap(dx, dx * rng.choice([0.0, 0.9, 1.9, 1.99]), x, x * 2.0)
    pol = PolicyConfig(
        trusted_spenders=set(rng.sample(ADDRS, rng.randint(0, 3))),
        trusted_recipients=set(rng.sample(ADDRS, rng.randint(0, 3))),
        denylist=set(rng.sample(ADDRS, rng.randint(0, 2))),
    )
    return tx, sim, pol


RANK = {Verdict.ALLOW: 0, Verdict.WARN: 1, Verdict.BLOCK: 2}


def test_engine_is_deterministic_and_only_emits_registered_rules():
    rng = rng_for("engine-det")
    for i in range(N):
        tx, sim, pol = random_scenario(rng)
        a, fa = assess(tx, sim, pol)
        b, fb = assess(tx, sim, pol)
        assert a == b and [f.to_dict() for f in fa] == [f.to_dict() for f in fb], i
        for f in fa:
            assert f.rule in RULES and f.severity == RULES[f.rule].severity, (i, f.rule)
        worst = max((RANK[RULES[f.rule].verdict] for f in fa), default=0)
        assert RANK[a] == worst, i


def test_adding_a_denylist_entry_or_removing_trust_never_lowers_the_verdict():
    rng = rng_for("engine-monotone")
    for i in range(N):
        tx, sim, pol = random_scenario(rng)
        base, _ = assess(tx, sim, pol)
        extra = rng.choice(ADDRS)
        stricter = PolicyConfig.from_dict(pol.to_dict() | {"denylist": [*pol.denylist, extra]})
        assert RANK[assess(tx, sim, stricter)[0]] >= RANK[base], (i, extra)
        d = pol.to_dict()
        d["trusted_spenders"] = []
        d["trusted_recipients"] = []
        d["trusted_operators"] = []
        untrusted = PolicyConfig.from_dict(d)
        assert RANK[assess(tx, sim, untrusted)[0]] >= RANK[base], i


def test_disabling_rules_never_raises_the_verdict_and_removes_only_those_rules():
    rng = rng_for("engine-disable")
    for i in range(N):
        tx, sim, pol = random_scenario(rng)
        base, base_f = assess(tx, sim, pol)
        off = set(rng.sample(sorted(RULES), 5))
        looser = PolicyConfig.from_dict(pol.to_dict() | {"disabled_rules": sorted(off)})
        v, f = assess(tx, sim, looser)
        assert RANK[v] <= RANK[base], i
        assert {x.rule for x in f} == {x.rule for x in base_f} - off, i


def test_raising_thresholds_never_raises_the_verdict_on_swaps():
    rng = rng_for("engine-thresholds")
    for i in range(N):
        tx, sim, pol = random_scenario(rng)
        if sim.swap is None:
            continue
        base, _ = assess(tx, sim, pol)
        lax = PolicyConfig.from_dict(pol.to_dict() | {
            "impact_warn_bps": 9e9, "impact_block_bps": 9e9, "slippage_warn": 9.0,
            "slippage_block": 9.0, "sandwich_warn_bps": 9e9, "sandwich_block_bps": 9e9})
        assert RANK[assess(tx, sim, lax)[0]] <= RANK[base], i


# --------------------------------------------------------------------------- config parser

def random_config(rng: random.Random) -> dict:
    words = ["alpha", "beta", "gamma", "d-e", "f_g"]
    cfg: dict = {}
    for k in rng.sample(words, rng.randint(1, 3)):
        cfg[k] = rng.choice([
            rng.randint(-1000, 10**9), round(rng.uniform(-5, 5), 4), rng.random() < 0.5,
            "".join(rng.choice("abc #[]=,.") for _ in range(rng.randint(0, 12))),
            [rng.randint(0, 9) for _ in range(rng.randint(0, 4))],
            ["0x" + rng.randbytes(20).hex() for _ in range(rng.randint(1, 3))],
        ])
    for t in rng.sample(["policy", "simulator", "extra"], rng.randint(0, 3)):
        cfg[t] = {k: rng.choice([rng.randint(0, 99), rng.random() < 0.5, "v" + str(rng.randint(0, 9)),
                                 [rng.randint(0, 9) for _ in range(3)]])
                  for k in rng.sample(words, rng.randint(1, 3))}
    return cfg


def to_toml(cfg: dict) -> str:
    import json

    def val(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, list):
            return "[" + ", ".join(val(x) for x in v) + "]"
        if isinstance(v, str):
            return json.dumps(v)
        return repr(v)

    lines = [f"{k} = {val(v)}" for k, v in cfg.items() if not isinstance(v, dict)]
    for k, v in cfg.items():
        if isinstance(v, dict):
            lines.append(f"[{k}]")
            lines += [f"{kk} = {val(vv)}" for kk, vv in v.items()]
    return "\n".join(lines) + "\n"


def test_fallback_toml_parser_matches_tomllib_on_random_configs():
    rng = rng_for("toml")
    for i in range(N):
        cfg = random_config(rng)
        text = to_toml(cfg)
        assert parse_toml(text) == cfg, (i, text)  # tomllib
        assert parse_toml_subset(text) == cfg, (i, text)  # the 3.10 fallback
