"""Generate the synthetic labelled evaluation set (seeded, reproducible, engine-independent).

    python evals/build_cases.py > evals/cases.jsonl          # regenerate
    python evals/build_cases.py --check                      # fail if cases.jsonl is stale

Every case is a *scenario template* instance: a transaction, a recorded simulation (the JSON a
simulator would hand to the engine) and a policy, together with the verdict a careful human
reviewer would give that class of transaction. The label comes from the template's definition of
the class (see ``CATEGORIES``), never from running the risk engine: this file does not import
``txwarden`` at all, so it cannot depend on the engine's thresholds. Where a template's class
boundary disagrees with the engine's configured thresholds, the evals report it as an error (see
``swap_loose``).

Splits: each category is split 70/30 into ``dev`` and ``heldout`` by *generation*, with disjoint
random draws (``heldout`` cases are generated after ``dev`` from the same category stream). For the
swap categories the held-out draws also come from a different pool-size regime. Thresholds may be
tuned on ``dev`` only; ``heldout`` is for reporting.

The data are synthetic: pools, balances and traces are drawn from distributions chosen by the
author, not sampled from mainnet.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

SEED = 20260614
DEV_FRACTION = 0.7
DEFAULT_PER_CATEGORY = 28

E = 10**18
UNLIM = 2**256 - 1
PERMIT2_MAX = 2**160 - 1
NOW = 1_700_000_000
DAY = 86_400

USER = "0x1111111111111111111111111111111111111111"
ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
FRIEND = "0x2222222222222222222222222222222222222222"
STRANGER = "0x3333333333333333333333333333333333333333"
COLD = "0x4444444444444444444444444444444444444444"
EVIL = "0xdead00000000000000000000000000000000beef"
TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
NFT = "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d"
MARKET = "0x1e0049783f008a0085193e00003d00cd54003c71"
BURN = "0x000000000000000000000000000000000000dead"
CLAIM = "0xc1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1"
HELPER = "0xc1a2c1a2c1a2c1a2c1a2c1a2c1a2c1a2c1a2c1a2"
LIB = "0xc1a3c1a3c1a3c1a3c1a3c1a3c1a3c1a3c1a3c1a3"
IMPL = "0xc1a4c1a4c1a4c1a4c1a4c1a4c1a4c1a4c1a4c1a4"
FACTORY = "0xc1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5c1a5"

POLICY = {
    "trusted_spenders": [ROUTER, PERMIT2],
    "trusted_recipients": [FRIEND],
    "trusted_operators": [MARKET],
    "denylist": [EVIL],
    "address_book": {COLD: "cold wallet", ROUTER: "Uniswap V2 Router02", PERMIT2: "Permit2"},
    "expected_chain_id": 1,
}


# --------------------------------------------------------------------------- helpers

def addr(rng: random.Random) -> str:
    return f"0x{rng.getrandbits(160):040x}"


def lookalike(address: str, rng: random.Random) -> str:
    """Same first 4 and last 4 hex characters, random middle (address poisoning)."""
    body = address[2:]
    return "0x" + body[:4] + f"{rng.getrandbits(128):032x}" + body[-4:]


def v2_out(dx: float, x: float, y: float, fee: float = 0.003) -> float:
    eff = dx * (1 - fee)
    return eff * y / (x + eff)


def tx_dict(to: str = TOKEN, data: str = "0x", value: int = 0, chain_id: int = 1,
            sender: str = USER) -> dict:
    return {"sender": sender, "to": to, "data": data, "value": value, "chain_id": chain_id}


def fresh() -> dict:
    return {"code_size": 0, "nonce": 0, "balance": 0}


def used_eoa(rng: random.Random) -> dict:
    return {"code_size": 0, "nonce": rng.randint(3, 900), "balance": rng.randint(10**15, 10**20)}


def frame(kind: str, frm: str, to: str, inp: str = "0x", calls: list | None = None,
          value: str = "0x0") -> dict:
    d = {"type": kind, "from": frm, "to": to, "value": value, "input": inp}
    if calls:
        d["calls"] = calls
    return d


def transfer_from_input(owner: str, to: str, amount: int) -> str:
    return "0x23b872dd" + owner[2:].rjust(64, "0") + to[2:].rjust(64, "0") + f"{amount:064x}"


def approval(spender: str, amount: int, via: str = "", expiration: int | None = None) -> dict:
    d = {"token": TOKEN, "owner": USER, "spender": spender, "amount": amount, "via": via}
    if expiration is not None:
        d["expiration"] = expiration
    return d


def transfer(to: str, amount: int, balance: int, kind: str = "erc20", token: str = TOKEN,
             sender: str = USER, operator: str | None = None) -> dict:
    return {"token": token, "sender": sender, "recipient": to, "amount": amount,
            "sender_balance_before": balance, "kind": kind, "operator": operator}


def v2_swap_sim(rng: random.Random, pool: float, frac: float, slip: float, **extra) -> dict:
    x = pool * E
    y = x * rng.uniform(0.0005, 0.002)  # token_out is pricier
    amt = x * frac
    clean = v2_out(amt, x, y)
    sim = {"success": True, "gas_used": 150_000, "call_kind": "v2_swap_exact_tokens_for_tokens",
           "swap": {"amount_in": amt, "min_out": clean * (1 - slip), "reserve_in": x,
                    "reserve_out": y}, "output_recipients": [USER]}
    sim.update(extra)
    return sim


def v3_swap_sim(rng: random.Random, frac: float, slip: float, ticks: list | None = None,
                zero_for_one: bool | None = None, fee: float = 0.003) -> dict:
    tick = rng.randint(-120_000, 120_000)
    sqrt_p = 1.0001 ** (tick / 2)
    liq = 10 ** rng.uniform(12, 19)
    zfo = rng.random() < 0.5 if zero_for_one is None else zero_for_one
    x_virt, y_virt = liq / sqrt_p, liq * sqrt_p
    rin, rout = (x_virt, y_virt) if zfo else (y_virt, x_virt)
    amt = rin * frac
    clean = v2_out(amt, rin, rout, fee)
    return {"success": True, "gas_used": 180_000, "call_kind": "v3_exact_input_single",
            "swap_v3": {"amount_in": amt, "min_out": clean * (1 - slip), "sqrt_price": sqrt_p,
                        "liquidity": liq, "fee": fee, "zero_for_one": zfo,
                        "ticks": ticks if ticks is not None else []},
            "output_recipients": [USER], "_tick": tick}


# --------------------------------------------------------------------------- templates

@dataclass(frozen=True)
class Category:
    name: str
    expected: str  # ALLOW | WARN | BLOCK
    group: str
    rationale: str
    gen: Callable[[random.Random, bool], dict]  # (rng, heldout) -> {"tx", "sim", ["policy"], ["expected"]}
    n: int = DEFAULT_PER_CATEGORY


CATEGORIES: list[Category] = []


def cat(name: str, expected: str, group: str, rationale: str, n: int = DEFAULT_PER_CATEGORY):
    def deco(fn: Callable[[random.Random, bool], dict]):
        CATEGORIES.append(Category(name, expected, group, rationale, fn, n))
        return fn

    return deco


def pool_size(rng: random.Random, held: bool, lo: float, hi: float) -> float:
    """Dev draws from [lo, hi]; held-out draws come from shallower or deeper pools."""
    if not held:
        return rng.uniform(lo, hi)
    return rng.choice([rng.uniform(lo / 20, lo), rng.uniform(hi, hi * 20)])


# ---- swaps (constant product)

@cat("swap_tight", "ALLOW", "swap_v2", "tiny trade, deep pool, 0.1% slippage")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4),
                                                      rng.uniform(1e-4, 1e-3), 0.001)}


@cat("swap_default_half_percent", "ALLOW", "swap_v2",
     "the common 0.5% default tolerance on a trade that barely moves the pool")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 5e3, 5e4),
                                                      rng.uniform(5e-5, 3e-4), 0.005)}


@cat("swap_moderate", "WARN", "swap_v2", "1% slippage: worth a second look")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4),
                                                      rng.uniform(1e-4, 1e-3), 0.01)}


@cat("swap_loose", "BLOCK", "swap_v2",
     "3-20% slippage floor: a sandwich can take it all. The 3-5% band disagrees with the "
     "engine's default 5% block threshold, which the evals report")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4),
                                                      rng.uniform(1e-4, 1e-3),
                                                      rng.uniform(0.03, 0.2))}


@cat("swap_zero_floor", "BLOCK", "swap_v2", "min_out of 1 wei: no protection at all")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-2), 0.0)
    sim["swap"]["min_out"] = 1.0
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("swap_high_impact", "WARN", "swap_v2", "5.5-10% of a thin pool in one trade, no slippage slack")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 50, 200),
                                                      rng.uniform(0.055, 0.1), 0.0)}


@cat("swap_extreme_impact", "BLOCK", "swap_v2", "30-100% of a thin pool in one trade")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 50, 200),
                                                      rng.uniform(0.3, 1.0), 0.0)}


@cat("swap_sandwichable", "BLOCK", "swap_v2",
     "1-3% of a mid pool with 2% slack: a textbook sandwich target")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 300, 1500),
                                                      rng.uniform(0.01, 0.03), 0.02)}


@cat("swap_recipient_third_party", "WARN", "swap_v2",
     "a tight, healthy swap whose output goes to an address the user does not know")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["output_recipients"] = [addr(rng)]
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("swap_recipient_trusted_friend", "ALLOW", "swap_v2",
     "the same swap paying a friend the user has listed as a trusted recipient")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["output_recipients"] = [rng.choice([FRIEND, COLD])]
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("swap_recipient_denylisted", "BLOCK", "swap_v2", "swap output routed to a denylisted address")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["output_recipients"] = [EVIL]
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("swap_no_pool_state", "WARN", "swap_v2",
     "a swap that cannot be analysed (no RPC / pool not found) must not be waved through")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": {
        "success": True, "call_kind": "v2_swap_exact_tokens_for_tokens",
        "output_recipients": [USER],
        "incomplete": ["swap_state: no pool state without an RPC"]}}


# ---- swaps (multi-hop)

def path_sim(rng: random.Random, held: bool, frac: float, slip: float) -> dict:
    hops = []
    amt = None
    x0 = pool_size(rng, held, 3e3, 3e4) * E
    cur_in = x0
    for _ in range(2):
        y = cur_in * rng.uniform(0.0005, 0.002) * rng.choice([1, 1000])
        hops.append({"reserve_in": cur_in, "reserve_out": y})
        cur_in = y * rng.uniform(0.8, 1.25)
    amt = x0 * frac
    out = amt
    for h in hops:
        out = v2_out(out, h["reserve_in"], h["reserve_out"])
    return {"success": True, "gas_used": 220_000, "call_kind": "v2_swap_exact_tokens_for_tokens",
            "path_swap": {"amount_in": amt, "min_out": out * (1 - slip), "hops": hops},
            "output_recipients": [USER]}


@cat("path_tight", "ALLOW", "swap_path", "two-hop route, tiny trade, 0.1% slippage")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": path_sim(rng, held, rng.uniform(5e-5, 5e-4), 0.001)}


@cat("path_loose", "BLOCK", "swap_path", "two-hop route with 5-20% slippage")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": path_sim(rng, held, rng.uniform(5e-5, 5e-4),
                                                   rng.uniform(0.05, 0.2))}


# ---- swaps (concentrated liquidity)

@cat("v3_tight", "ALLOW", "swap_v3", "V3 pool, tiny trade, 0.1% slippage")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": strip(v3_swap_sim(rng, rng.uniform(5e-5, 5e-4), 0.001))}


@cat("v3_wide_range_ticks_tight", "ALLOW", "swap_v3",
     "V3 pool with initialised ticks far beyond the trade, 0.1% slippage")
def _(rng, held):
    s = v3_swap_sim(rng, rng.uniform(5e-5, 5e-4), 0.001)
    t = s["_tick"]
    s["swap_v3"]["ticks"] = [{"tick": t - 40_000, "liquidity_net": s["swap_v3"]["liquidity"]},
                             {"tick": t + 40_000, "liquidity_net": -s["swap_v3"]["liquidity"]}]
    return {"tx": tx_dict(ROUTER), "sim": strip(s)}


@cat("v3_moderate", "WARN", "swap_v3", "V3 pool, 1% slippage")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": strip(v3_swap_sim(rng, rng.uniform(5e-5, 5e-4), 0.01))}


@cat("v3_loose", "BLOCK", "swap_v3", "V3 pool, 5-20% slippage")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": strip(v3_swap_sim(rng, rng.uniform(5e-5, 5e-4),
                                                            rng.uniform(0.05, 0.2)))}


@cat("v3_range_exhausted", "BLOCK", "swap_v3",
     "the trade is 1.5-4x what the only active position can absorb: it cannot fill")
def _(rng, held):
    s = v3_swap_sim(rng, 0.01, 0.0, zero_for_one=True)
    t, liq = s["_tick"], s["swap_v3"]["liquidity"]
    sp = s["swap_v3"]["sqrt_price"]
    span = rng.randint(30, 200)
    lower = 1.0001 ** ((t - span) / 2)
    capacity = liq * (sp - lower) / (sp * lower)  # token0 the position can take before the floor
    amount = capacity * rng.uniform(1.5, 4)
    s["swap_v3"]["amount_in"] = amount
    # the user's floor comes from a naive full-range quote (what a UI would show), 1% below it
    x_virt, y_virt = liq / sp, liq * sp
    s["swap_v3"]["min_out"] = v2_out(amount, x_virt, y_virt) * 0.99
    s["swap_v3"]["ticks"] = [{"tick": t - span, "liquidity_net": liq},
                             {"tick": t + span, "liquidity_net": -liq}]
    return {"tx": tx_dict(ROUTER), "sim": strip(s)}


def strip(sim: dict) -> dict:
    sim.pop("_tick", None)
    return sim


# ---- approvals

def approval_sim(*approvals: dict, **extra) -> dict:
    sim = {"success": True, "gas_used": 46_000, "call_kind": "erc20_approve", "chain_id": 1,
           "block_timestamp": NOW, "approvals": list(approvals)}
    sim.update(extra)
    return sim


@cat("approve_unlimited_unknown", "BLOCK", "approval", "max allowance to an address nobody vetted")
def _(rng, held):
    return {"tx": tx_dict(), "sim": approval_sim(approval(addr(rng), rng.choice(
        [UNLIM, UNLIM - 1, 2**255, 2**255 + rng.randint(0, 2**200)])))}


@cat("approve_unlimited_trusted", "ALLOW", "approval", "max allowance to the user's own trusted router")
def _(rng, held):
    return {"tx": tx_dict(), "sim": approval_sim(approval(rng.choice([ROUTER, PERMIT2]), UNLIM))}


@cat("approve_bounded_trusted", "ALLOW", "approval", "exact-amount allowance to a trusted router")
def _(rng, held):
    return {"tx": tx_dict(), "sim": approval_sim(approval(ROUTER, rng.randint(1, 10**9) * 10**6))}


@cat("approve_bounded_unknown", "WARN", "approval", "exact allowance to an unvetted address")
def _(rng, held):
    return {"tx": tx_dict(), "sim": approval_sim(approval(addr(rng), rng.randint(1, 10**9) * 10**6))}


@cat("approve_denylisted", "BLOCK", "approval", "any allowance to a denylisted spender")
def _(rng, held):
    return {"tx": tx_dict(), "sim": approval_sim(approval(EVIL, rng.choice(
        [rng.randint(1, 10**9), UNLIM])))}


@cat("approve_revoke", "ALLOW", "approval", "setting an allowance to zero is always fine")
def _(rng, held):
    return {"tx": tx_dict(), "sim": approval_sim(approval(rng.choice([addr(rng), EVIL, ROUTER]), 0))}


@cat("approve_permit2_unlimited_unknown", "BLOCK", "approval",
     "Permit2 allowance of uint160 max to an unknown spender")
def _(rng, held):
    return {"tx": tx_dict(PERMIT2), "sim": approval_sim(
        approval(addr(rng), PERMIT2_MAX, "permit2", NOW + 30 * DAY))}


@cat("approve_permit2_never_expires_trusted", "WARN", "approval",
     "bounded Permit2 allowance to a trusted router that never expires")
def _(rng, held):
    return {"tx": tx_dict(PERMIT2), "sim": approval_sim(
        approval(ROUTER, rng.randint(1, 10**9) * 10**6, "permit2", 2**48 - 1))}


@cat("approve_permit2_short_trusted", "ALLOW", "approval",
     "bounded Permit2 allowance to a trusted router that expires within the hour")
def _(rng, held):
    return {"tx": tx_dict(PERMIT2), "sim": approval_sim(
        approval(ROUTER, rng.randint(1, 10**9) * 10**6, "permit2", NOW + rng.randint(300, 3600)))}


@cat("approve_lookalike_spender", "BLOCK", "approval",
     "spender shares the first and last 4 hex characters with the trusted router (poisoning)")
def _(rng, held):
    return {"tx": tx_dict(), "sim": approval_sim(approval(lookalike(ROUTER, rng), UNLIM))}


# ---- NFT operators and permits

def operator_sim(operator: str, approved: bool) -> dict:
    return {"success": True, "gas_used": 50_000, "call_kind": "set_approval_for_all",
            "chain_id": 1, "operator_approvals": [{"token": NFT, "owner": USER,
                                                   "operator": operator, "approved": approved,
                                                   "standard": "erc721"}]}


@cat("nft_operator_unknown", "BLOCK", "nft", "setApprovalForAll to an unvetted operator")
def _(rng, held):
    return {"tx": tx_dict(NFT), "sim": operator_sim(addr(rng), True)}


@cat("nft_operator_trusted_marketplace", "ALLOW", "nft", "setApprovalForAll to a trusted marketplace")
def _(rng, held):
    return {"tx": tx_dict(NFT), "sim": operator_sim(MARKET, True)}


@cat("nft_operator_denylisted", "BLOCK", "nft", "setApprovalForAll to a denylisted operator")
def _(rng, held):
    return {"tx": tx_dict(NFT), "sim": operator_sim(EVIL, True)}


@cat("nft_operator_revoke", "ALLOW", "nft", "setApprovalForAll(operator, false)")
def _(rng, held):
    return {"tx": tx_dict(NFT), "sim": operator_sim(rng.choice([addr(rng), EVIL, MARKET]), False)}


def permit_sim(spender: str, amount: int, deadline: int, kind: str = "eip2612") -> dict:
    return {"success": True, "gas_used": 70_000, "call_kind": "erc20_permit", "chain_id": 1,
            "block_timestamp": NOW,
            "permits": [{"token": TOKEN, "owner": USER, "spender": spender, "amount": amount,
                         "deadline": deadline, "kind": kind}]}


@cat("permit_unlimited_unknown", "BLOCK", "permit", "gasless unlimited permit to an unknown spender")
def _(rng, held):
    return {"tx": tx_dict(), "sim": permit_sim(addr(rng), rng.choice([UNLIM, 2**255]),
                                               NOW + rng.randint(600, 7 * DAY))}


@cat("permit_bounded_unknown", "WARN", "permit", "bounded permit to an unknown spender")
def _(rng, held):
    return {"tx": tx_dict(), "sim": permit_sim(addr(rng), rng.randint(1, 10**9) * 10**6,
                                               NOW + rng.randint(600, 7 * DAY))}


@cat("permit_trusted_short", "ALLOW", "permit", "bounded permit to a trusted router, 30 minute deadline")
def _(rng, held):
    return {"tx": tx_dict(), "sim": permit_sim(ROUTER, rng.randint(1, 10**9) * 10**6,
                                               NOW + rng.randint(300, 1800))}


@cat("permit_trusted_far_deadline", "WARN", "permit",
     "bounded permit to a trusted router valid for 90 days or forever")
def _(rng, held):
    return {"tx": tx_dict(), "sim": permit_sim(ROUTER, rng.randint(1, 10**9) * 10**6,
                                               rng.choice([NOW + 90 * DAY, NOW + 365 * DAY, 2**41]))}


@cat("permit_denylisted", "BLOCK", "permit", "permit whose spender is denylisted")
def _(rng, held):
    return {"tx": tx_dict(), "sim": permit_sim(EVIL, rng.randint(1, 10**9), NOW + DAY)}


@cat("permit2_unlimited_unknown", "BLOCK", "permit",
     "Permit2 PermitSingle of uint160 max to an unknown spender")
def _(rng, held):
    return {"tx": tx_dict(PERMIT2), "sim": permit_sim(addr(rng), PERMIT2_MAX, NOW + 30 * DAY,
                                                      "permit2")}


# ---- transfers

def transfer_sim(t: dict, **extra) -> dict:
    sim = {"success": True, "gas_used": 65_000, "call_kind": "erc20_transfer", "chain_id": 1,
           "transfers": [t]}
    sim.update(extra)
    return sim


def rand_balance(rng: random.Random) -> int:
    return 10**6 * rng.randint(10, 10**5)


@cat("transfer_trusted", "ALLOW", "transfer", "any amount to a listed trusted recipient")
def _(rng, held):
    bal = rand_balance(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(rng.choice([FRIEND, COLD]),
                                                          int(bal * rng.uniform(0.1, 1.0)), bal))}


@cat("transfer_unknown_small", "ALLOW", "transfer", "up to half the balance to an established wallet")
def _(rng, held):
    bal, r = rand_balance(rng), addr(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(r, int(bal * rng.uniform(0.01, 0.5)), bal),
                                                 accounts={r: used_eoa(rng)})}


@cat("transfer_unknown_drain", "WARN", "transfer", "92-100% of the balance to an unfamiliar wallet")
def _(rng, held):
    bal, r = rand_balance(rng), addr(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(r, int(bal * rng.uniform(0.92, 1.0)), bal),
                                                 accounts={r: used_eoa(rng)})}


@cat("transfer_denylisted", "BLOCK", "transfer", "any transfer to a denylisted address")
def _(rng, held):
    bal = rand_balance(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(EVIL, int(bal * rng.uniform(0.01, 1)),
                                                          bal))}


@cat("transfer_fresh_address", "WARN", "transfer",
     "funds to an address with no code, no history and no balance")
def _(rng, held):
    bal, r = rand_balance(rng), addr(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(r, int(bal * rng.uniform(0.01, 0.5)), bal),
                                                 accounts={r: fresh()})}


@cat("transfer_to_token_contract", "WARN", "transfer", "tokens sent to the token's own address (lost)")
def _(rng, held):
    bal = rand_balance(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(TOKEN, int(bal * rng.uniform(0.01, 0.5)),
                                                          bal))}


@cat("transfer_to_burn", "WARN", "transfer", "tokens sent to the zero or dead address")
def _(rng, held):
    bal = rand_balance(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(rng.choice([BURN, "0x" + "00" * 20]),
                                                          int(bal * rng.uniform(0.01, 0.5)), bal))}


@cat("transfer_lookalike_recipient", "BLOCK", "transfer",
     "recipient matches the first and last 4 hex characters of the user's cold wallet")
def _(rng, held):
    bal, r = rand_balance(rng), lookalike(COLD, rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(r, int(bal * rng.uniform(0.05, 0.9)), bal),
                                                 accounts={r: fresh()})}


@cat("transfer_to_contract_deposit", "ALLOW", "transfer",
     "tokens to an unlabelled contract, e.g. a deposit address (informational only)")
def _(rng, held):
    bal, r = rand_balance(rng), addr(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(
        transfer(r, int(bal * rng.uniform(0.01, 0.5)), bal),
        accounts={r: {"code_size": rng.randint(100, 20000), "nonce": 1, "balance": 0}})}


# ---- execution health

@cat("revert", "WARN", "execution", "the simulation reverts")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": {"success": False, "revert_reason": rng.choice(
        ["INSUFFICIENT_OUTPUT_AMOUNT", "TRANSFER_FROM_FAILED", "EXPIRED", "STF", "execution reverted"])}}


@cat("chain_id_mismatch", "BLOCK", "execution", "transaction targets another chain than the wallet's")
def _(rng, held):
    return {"tx": tx_dict(chain_id=rng.choice([10, 56, 137, 42161, 8453])),
            "sim": {"success": True, "gas_used": 46_000, "call_kind": "erc20_approve"}}


@cat("rpc_unavailable", "BLOCK", "execution", "the simulator could not reach its node: fail closed")
def _(rng, held):
    return {"tx": tx_dict(), "sim": {"success": False, "error": rng.choice(
        ["cannot reach http://127.0.0.1:8545: [Errno 111] Connection refused", "HTTP 429 from rpc",
         "missing trie node", "request timed out"])}}


@cat("call_to_non_contract", "WARN", "execution", "calldata sent to an address that has no code")
def _(rng, held):
    r = addr(rng)
    return {"tx": tx_dict(r, "0x095ea7b3" + "00" * 64), "sim": {
        "success": True, "gas_used": 21_000, "accounts": {r: fresh()}}}


@cat("gas_normal", "ALLOW", "execution", "gas within 2x of the typical cost of the call")
def _(rng, held):
    kind, typical = rng.choice([("erc20_approve", 46_000), ("erc20_transfer", 65_000),
                                ("v2_swap_exact_tokens_for_tokens", 160_000)])
    return {"tx": tx_dict(), "sim": {"success": True, "call_kind": kind,
                                     "gas_used": int(typical * rng.uniform(0.7, 2.0))}}


@cat("gas_abnormal", "WARN", "execution", "an approval-class call using 8-40x the typical gas")
def _(rng, held):
    return {"tx": tx_dict(), "sim": {"success": True, "call_kind": "erc20_approve",
                                     "gas_used": int(46_000 * rng.uniform(8, 40))}}


@cat("gas_extreme", "BLOCK", "execution", "more than 10M gas")
def _(rng, held):
    return {"tx": tx_dict(), "sim": {"success": True, "call_kind": "erc20_approve",
                                     "gas_used": rng.randint(12_000_000, 30_000_000)}}


# ---- honeypot probe

def probe(buy_ok=True, sell_ok=True, loss=0.01, reason=None, mode="simulate") -> dict:
    return {"mode": mode, "buy_ok": buy_ok, "sell_ok": sell_ok, "amount_in": 1e16,
            "bought": 1e19, "returned": 1e16 * (1 - loss), "loss_fraction": loss,
            "sell_revert_reason": reason, "taxes_observable": mode == "simulate"}


@cat("honeypot_clean", "ALLOW", "honeypot", "round trip loses 0.6-2.5%: fees and a little impact")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["honeypot"] = probe(loss=rng.uniform(0.006, 0.025))
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("honeypot_fee_on_transfer", "WARN", "honeypot", "round trip loses 6-20%: a fee-on-transfer token")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["honeypot"] = probe(loss=rng.uniform(0.06, 0.2))
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("honeypot_severe_tax", "BLOCK", "honeypot", "round trip loses 30-90%")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["honeypot"] = probe(loss=rng.uniform(0.3, 0.9))
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("honeypot_sell_reverts", "BLOCK", "honeypot", "buy works, sell reverts")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["honeypot"] = probe(sell_ok=False, loss=1.0, reason=rng.choice(
        ["TRANSFER_FAILED", "UniswapV2: TRANSFER_FAILED", "Trading not enabled", "blacklisted"]))
    return {"tx": tx_dict(ROUTER), "sim": sim}


# ---- liquidity

def lp_sim(action: str, fraction: float, total: float = 1e21) -> dict:
    return {"success": True, "gas_used": 200_000, "call_kind": "v2_remove_liquidity",
            "lp_events": [{"action": action, "pool": "0x" + "99" * 20,
                           "liquidity": total * fraction, "pool_total": total, "protocol": "v2"}]}


@cat("lp_remove_small", "ALLOW", "liquidity", "withdraws under 10% of a pool")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": lp_sim("remove", rng.uniform(0.0005, 0.1),
                                                 10 ** rng.uniform(18, 24))}


@cat("lp_remove_large", "WARN", "liquidity", "withdraws 25-45% of a pool")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": lp_sim("remove", rng.uniform(0.25, 0.45),
                                                 10 ** rng.uniform(18, 24))}


@cat("lp_remove_majority", "BLOCK", "liquidity", "withdraws 60-100% of a pool")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": lp_sim("remove", rng.uniform(0.6, 1.0),
                                                 10 ** rng.uniform(18, 24))}


@cat("lp_add", "ALLOW", "liquidity", "adding liquidity")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": lp_sim("add", rng.uniform(0.001, 0.5))}


@cat("lp_remove_unknown_total", "WARN", "liquidity",
     "removal whose pool total could not be read: the share cannot be judged")
def _(rng, held):
    sim = lp_sim("remove", 0.5)
    sim["lp_events"][0]["pool_total"] = None
    sim["incomplete"] = ["lp_state: pool total supply unavailable"]
    return {"tx": tx_dict(ROUTER), "sim": sim}


# ---- call trees

def trace_sim(tree: dict, **extra) -> dict:
    sim = {"success": True, "gas_used": 120_000, "call_kind": "unknown", "chain_id": 1,
           "call_tree": tree}
    sim.update(extra)
    return sim


@cat("trace_benign_swap", "ALLOW", "trace", "router -> pair -> token transfers, no delegatecall")
def _(rng, held):
    pair, a, b = addr(rng), addr(rng), addr(rng)
    tree = frame("CALL", USER, ROUTER, "0x38ed1739", [
        frame("CALL", ROUTER, a, "0x23b872dd"),
        frame("STATICCALL", ROUTER, pair, "0x0902f1ac"),
        frame("CALL", ROUTER, pair, "0x022c0d9f", [frame("CALL", pair, b, "0xa9059cbb")])])
    return {"tx": tx_dict(ROUTER), "sim": trace_sim(tree)}


@cat("trace_proxy_delegatecall", "ALLOW", "trace",
     "an upgradeable token proxy delegatecalls its implementation")
def _(rng, held):
    proxy, impl = addr(rng), addr(rng)
    tree = frame("CALL", USER, proxy, "0x095ea7b3", [frame("DELEGATECALL", proxy, impl, "0x095ea7b3")])
    return {"tx": tx_dict(proxy), "sim": trace_sim(tree)}


@cat("trace_nested_delegatecall", "BLOCK", "trace",
     "a contract below the target delegatecalls unknown code that pulls the user's tokens")
def _(rng, held):
    claim, helper, lib, attacker = addr(rng), addr(rng), addr(rng), addr(rng)
    pull = transfer_from_input(USER, attacker, rng.randint(1, 10**9))
    tree = frame("CALL", USER, claim, "0x4e71d92d", [
        frame("CALL", claim, helper, "0x1e83409a", [
            frame("DELEGATECALL", helper, lib, "0x1e83409a", [frame("CALL", helper, TOKEN, pull)])])])
    return {"tx": tx_dict(claim), "sim": trace_sim(tree)}


@cat("trace_selfdestruct", "BLOCK", "trace", "a SELFDESTRUCT somewhere in the tree")
def _(rng, held):
    c, d = addr(rng), addr(rng)
    tree = frame("CALL", USER, c, "0x12345678", [frame("CALL", c, d, "0x", [
        frame("SELFDESTRUCT", d, addr(rng), "0x", value="0x2386f26fc10000")])])
    return {"tx": tx_dict(c), "sim": trace_sim(tree)}


@cat("trace_create2", "WARN", "trace", "a contract is deployed during an approval-like call")
def _(rng, held):
    f = addr(rng)
    tree = frame("CALL", USER, f, "0xabcdef01", [frame("CREATE2", f, addr(rng), "0x6080604052")])
    return {"tx": tx_dict(f), "sim": trace_sim(tree)}


@cat("trace_denylisted_nested", "BLOCK", "trace", "a denylisted address is called several frames down")
def _(rng, held):
    c, d = addr(rng), addr(rng)
    tree = frame("CALL", USER, c, "0x12345678", [frame("CALL", c, d, "0x", [
        frame("CALL", d, EVIL, "0x", value="0x1")])])
    return {"tx": tx_dict(c), "sim": trace_sim(tree)}


@cat("trace_untrusted_pull", "WARN", "trace",
     "an unlabelled contract moves the user's tokens to a third party (no delegatecall)")
def _(rng, held):
    c, attacker = addr(rng), addr(rng)
    amt = rng.randint(10**6, 10**9)
    bal = amt * rng.randint(3, 10)
    sim = trace_sim(frame("CALL", USER, c, "0x4e71d92d", [
        frame("CALL", c, TOKEN, transfer_from_input(USER, attacker, amt))]),
        transfers=[transfer(attacker, amt, bal, operator=c)], accounts={attacker: used_eoa(rng)})
    return {"tx": tx_dict(c), "sim": sim}


# ---- bundles

def bundle(txs: list[dict], sims: list[dict]) -> dict:
    return {"kind": "bundle", "txs": txs, "sims": sims}


@cat("bundle_approve_then_pull", "BLOCK", "bundle",
     "tx0 approves an unknown spender, tx1 is that spender pulling the funds")
def _(rng, held):
    x = addr(rng)
    amt = rng.randint(10**6, 10**9)
    return bundle(
        [tx_dict(), tx_dict(TOKEN, sender=x)],
        [approval_sim(approval(x, rng.choice([amt, UNLIM]))),
         {"success": True, "transfers": [transfer(x, amt, amt * 2, operator=x)]}])


@cat("bundle_approve_then_call_spender", "BLOCK", "bundle",
     "tx0 approves an unknown spender, tx1 calls that spender's contract")
def _(rng, held):
    x = addr(rng)
    return bundle([tx_dict(), tx_dict(x, "0x4e71d92d")],
                  [approval_sim(approval(x, UNLIM)), {"success": True, "gas_used": 90_000}])


@cat("bundle_clean_swap", "ALLOW", "bundle", "approve a trusted router, then swap through it")
def _(rng, held):
    return bundle([tx_dict(), tx_dict(ROUTER)],
                  [approval_sim(approval(ROUTER, rng.randint(1, 10**9) * 10**6)),
                   v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)])


@cat("bundle_cumulative_drain", "WARN", "bundle",
     "three transfers of 31-33% of the balance each to different unknown wallets")
def _(rng, held):
    bal = rand_balance(rng)
    sims, txs = [], []
    for _i in range(3):
        r = addr(rng)
        txs.append(tx_dict())
        sims.append(transfer_sim(transfer(r, int(bal * rng.uniform(0.31, 0.33)), bal),
                                 accounts={r: used_eoa(rng)}))
    return bundle(txs, sims)


@cat("bundle_add_then_remove_liquidity", "BLOCK", "bundle", "liquidity added then removed in one bundle")
def _(rng, held):
    pool = "0x" + "99" * 20
    add = lp_sim("add", 0.3)
    add["lp_events"][0]["pool"] = pool
    rem = lp_sim("remove", rng.uniform(0.05, 0.2))
    rem["lp_events"][0]["pool"] = pool
    return bundle([tx_dict(ROUTER), tx_dict(ROUTER)], [add, rem])


@cat("bundle_mixed_chains", "BLOCK", "bundle", "one bundle spanning two chain ids")
def _(rng, held):
    return bundle([tx_dict(chain_id=1), tx_dict(chain_id=rng.choice([10, 137, 42161]))],
                  [{"success": True}, {"success": True}])


@cat("bundle_two_independent_ok", "ALLOW", "bundle", "two unrelated, individually fine transfers")
def _(rng, held):
    sims, txs = [], []
    for r in (FRIEND, COLD):
        bal = rand_balance(rng)
        txs.append(tx_dict())
        sims.append(transfer_sim(transfer(r, int(bal * 0.2), bal)))
    return bundle(txs, sims)


# ---- composite, "looks complicated but is fine" and "looks fine but is not"

@cat("ur_swap_with_permit2_ok", "ALLOW", "composite",
     "Universal Router flow: short bounded Permit2 permit to the router, then a tight swap to self")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["call_kind"] = "universal_router_execute"
    sim["block_timestamp"] = NOW
    sim["permits"] = [{"token": TOKEN, "owner": USER, "spender": ROUTER,
                       "amount": int(sim["swap"]["amount_in"]) or 1, "deadline": NOW + 1800,
                       "kind": "permit2"}]
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("ur_swap_sweep_to_stranger", "WARN", "composite",
     "Universal Router flow: tight swap, but the swept output goes to an unknown address")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["call_kind"] = "universal_router_execute"
    sim["output_recipients"] = [ROUTER, addr(rng)]
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("multicall_hidden_unlimited_approval", "BLOCK", "composite",
     "a swap multicall that also carries an unlimited approval to an unknown spender")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["call_kind"] = "multicall"
    sim["approvals"] = [approval(addr(rng), UNLIM)]
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("tight_swap_plus_revoke", "ALLOW", "composite", "a tight swap that also revokes an old allowance")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["call_kind"] = "multicall"
    sim["approvals"] = [approval(addr(rng), 0)]
    return {"tx": tx_dict(ROUTER), "sim": sim}


# ---- gray areas and normalisation. Banded categories draw a parameter across a range and label each
# case by a reviewer rule stated in the category text; the rule is the author's judgement and the
# engine's thresholds were not consulted, so disagreement near a boundary is expected and reported.

@cat("swap_impact_band", "BAND", "gray_area",
     "price impact drawn across 1-10%; reviewer rule: warn from 3%, block from 15% (never reached)",
     n=56)
def _(rng, held):
    x_eth = pool_size(rng, held, 50, 400)
    fee = 0.003
    impact = rng.uniform(0.012, 0.10)
    x = x_eth * E
    dx = x * (1 / (1 - impact) - 1 / (1 - fee))
    y = x * rng.uniform(0.0005, 0.002)
    clean = v2_out(dx, x, y)
    sim = {"success": True, "gas_used": 150_000, "call_kind": "v2_swap_exact_tokens_for_tokens",
           "swap": {"amount_in": dx, "min_out": clean, "reserve_in": x, "reserve_out": y},
           "output_recipients": [USER]}
    return {"tx": tx_dict(ROUTER), "sim": sim, "expected": "WARN" if impact >= 0.03 else "ALLOW"}


@cat("swap_slippage_band", "BAND", "gray_area",
     "slippage drawn across 0.1-6% on a trade too small to sandwich; reviewer rule: allow up to "
     "0.5%, warn below 3%, block from 3%", n=56)
def _(rng, held):
    slip = rng.uniform(0.001, 0.06)
    exp = "ALLOW" if slip <= 0.005 else ("WARN" if slip < 0.03 else "BLOCK")
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4),
                                                      rng.uniform(1e-4, 1e-3), slip),
            "expected": exp}


@cat("swap_mid_trade_slippage_band", "BAND", "gray_area",
     "1-2% of a mid pool, slippage drawn across 0.1-1.5%; reviewer rule: the wallet-default 0.5% "
     "is the user's accepted worst case (allow), warn above it", n=56)
def _(rng, held):
    slip = rng.uniform(0.001, 0.015)
    return {"tx": tx_dict(ROUTER), "sim": v2_swap_sim(rng, pool_size(rng, held, 300, 1500),
                                                      rng.uniform(0.01, 0.02), slip),
            "expected": "ALLOW" if slip <= 0.005 else "WARN"}


@cat("approve_near_unlimited_unknown", "BLOCK", "gray_area",
     "an allowance between 2**128 and 2**255: not 'infinite' on paper, but more than any token's "
     "supply, so as dangerous as one")
def _(rng, held):
    return {"tx": tx_dict(), "sim": approval_sim(approval(addr(rng), int(2 ** rng.uniform(128, 255))))}


@cat("approve_unlimited_trusted_mixed_case", "ALLOW", "gray_area",
     "the trusted router written in EIP-55-style mixed case must still be recognised")
def _(rng, held):
    mixed = "0x" + "".join(ch.upper() if rng.random() < 0.5 else ch for ch in ROUTER[2:])
    return {"tx": tx_dict(), "sim": approval_sim(approval(mixed, UNLIM))}


@cat("approve_unlimited_unknown_mixed_case", "BLOCK", "gray_area",
     "an unknown spender in mixed case must not slip past normalisation")
def _(rng, held):
    a = addr(rng)
    mixed = "0x" + "".join(ch.upper() if rng.random() < 0.5 else ch for ch in a[2:])
    return {"tx": tx_dict(), "sim": approval_sim(approval(mixed, UNLIM))}


@cat("permit_unlimited_trusted_short", "ALLOW", "gray_area",
     "an unlimited permit to the user's trusted router that expires within the hour")
def _(rng, held):
    return {"tx": tx_dict(), "sim": permit_sim(ROUTER, UNLIM, NOW + rng.randint(300, 3600))}


@cat("transfer_unknown_70_to_89pct", "ALLOW", "gray_area",
     "moving 70-89% of a balance to an established wallet is not a drain")
def _(rng, held):
    bal, r = rand_balance(rng), addr(rng)
    return {"tx": tx_dict(), "sim": transfer_sim(transfer(r, int(bal * rng.uniform(0.7, 0.89)), bal),
                                                 accounts={r: used_eoa(rng)})}


@cat("honeypot_mild_tax_2_to_4pct", "ALLOW", "gray_area",
     "a token with a 1-2% transfer tax: round trip loses 2-4%, common and not a scam")
def _(rng, held):
    sim = v2_swap_sim(rng, pool_size(rng, held, 2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001)
    sim["honeypot"] = probe(loss=rng.uniform(0.02, 0.04))
    return {"tx": tx_dict(ROUTER), "sim": sim}


@cat("lp_remove_10_to_20pct", "ALLOW", "gray_area", "withdrawing 10-19% of a pool")
def _(rng, held):
    return {"tx": tx_dict(ROUTER), "sim": lp_sim("remove", rng.uniform(0.1, 0.19),
                                                 10 ** rng.uniform(18, 24))}


# The rule ids a reviewer would cite for each non-ALLOW category (any one of them counts). Written
# from the category definitions above, not from engine output. ALLOW categories expect no finding of
# severity HIGH or above.
EXPECT_RULES: dict[str, list[str]] = {
    "swap_moderate": ["SLIPPAGE_TOLERANCE_LOOSE", "SANDWICH_EXPOSURE"],
    "swap_loose": ["SLIPPAGE_TOLERANCE_EXTREME", "SANDWICH_EXPOSURE_SEVERE"],
    "swap_zero_floor": ["SLIPPAGE_TOLERANCE_EXTREME"],
    "swap_high_impact": ["PRICE_IMPACT_HIGH"],
    "swap_extreme_impact": ["PRICE_IMPACT_EXTREME"],
    "swap_sandwichable": ["SANDWICH_EXPOSURE_SEVERE"],
    "swap_recipient_third_party": ["SWAP_RECIPIENT_MISMATCH"],
    "swap_recipient_denylisted": ["TRANSFER_TO_DENYLISTED"],
    "swap_no_pool_state": ["ANALYSIS_INCOMPLETE"],
    "path_loose": ["SLIPPAGE_TOLERANCE_EXTREME", "SANDWICH_EXPOSURE_SEVERE"],
    "v3_moderate": ["SLIPPAGE_TOLERANCE_LOOSE", "SANDWICH_EXPOSURE"],
    "v3_loose": ["SLIPPAGE_TOLERANCE_EXTREME", "SANDWICH_EXPOSURE_SEVERE"],
    "v3_range_exhausted": ["LIQUIDITY_EXHAUSTED"],
    "approve_unlimited_unknown": ["UNLIMITED_APPROVAL_UNKNOWN"],
    "approve_bounded_unknown": ["APPROVAL_UNKNOWN_SPENDER"],
    "approve_denylisted": ["APPROVAL_TO_DENYLISTED"],
    "approve_permit2_unlimited_unknown": ["UNLIMITED_APPROVAL_UNKNOWN"],
    "approve_permit2_never_expires_trusted": ["PERMIT_FAR_DEADLINE"],
    "approve_lookalike_spender": ["ADDRESS_LOOKALIKE"],
    "nft_operator_unknown": ["OPERATOR_APPROVAL_UNKNOWN"],
    "nft_operator_denylisted": ["OPERATOR_APPROVAL_DENYLISTED"],
    "permit_unlimited_unknown": ["PERMIT_UNLIMITED_UNKNOWN"],
    "permit_bounded_unknown": ["PERMIT_UNKNOWN_SPENDER"],
    "permit_trusted_far_deadline": ["PERMIT_FAR_DEADLINE"],
    "permit_denylisted": ["PERMIT_TO_DENYLISTED"],
    "permit2_unlimited_unknown": ["PERMIT_UNLIMITED_UNKNOWN"],
    "transfer_unknown_drain": ["NEAR_FULL_BALANCE_TO_NEW_ADDRESS"],
    "transfer_denylisted": ["TRANSFER_TO_DENYLISTED"],
    "transfer_fresh_address": ["TRANSFER_TO_FRESH_ADDRESS"],
    "transfer_to_token_contract": ["TRANSFER_TO_TOKEN_CONTRACT"],
    "transfer_to_burn": ["TRANSFER_TO_BURN_ADDRESS"],
    "transfer_lookalike_recipient": ["ADDRESS_LOOKALIKE"],
    "revert": ["REVERT"],
    "chain_id_mismatch": ["CHAIN_ID_MISMATCH"],
    "rpc_unavailable": ["SIMULATION_UNAVAILABLE"],
    "call_to_non_contract": ["CALL_TO_NON_CONTRACT"],
    "gas_abnormal": ["GAS_ABNORMAL"],
    "gas_extreme": ["GAS_EXTREME"],
    "honeypot_fee_on_transfer": ["ROUND_TRIP_LOSS"],
    "honeypot_severe_tax": ["ROUND_TRIP_LOSS_SEVERE"],
    "honeypot_sell_reverts": ["HONEYPOT_SELL_REVERTS"],
    "lp_remove_large": ["LP_REMOVAL_LARGE"],
    "lp_remove_majority": ["LP_REMOVAL_MAJORITY"],
    "lp_remove_unknown_total": ["ANALYSIS_INCOMPLETE"],
    "trace_nested_delegatecall": ["DELEGATECALL_TO_UNKNOWN"],
    "trace_selfdestruct": ["SELFDESTRUCT_IN_TRACE"],
    "trace_create2": ["CONTRACT_CREATION_IN_TRACE"],
    "trace_denylisted_nested": ["DENYLISTED_IN_TRACE"],
    "trace_untrusted_pull": ["UNTRUSTED_PULL_IN_TRACE"],
    "bundle_approve_then_pull": ["BUNDLE_APPROVE_THEN_PULL"],
    "bundle_approve_then_call_spender": ["BUNDLE_APPROVE_THEN_PULL"],
    "bundle_cumulative_drain": ["BUNDLE_CUMULATIVE_DRAIN"],
    "bundle_add_then_remove_liquidity": ["BUNDLE_ADD_THEN_REMOVE_LIQUIDITY"],
    "bundle_mixed_chains": ["BUNDLE_MIXED_CHAIN_IDS"],
    "ur_swap_sweep_to_stranger": ["SWAP_RECIPIENT_MISMATCH"],
    "multicall_hidden_unlimited_approval": ["UNLIMITED_APPROVAL_UNKNOWN"],
    "approve_near_unlimited_unknown": ["UNLIMITED_APPROVAL_UNKNOWN"],
    "approve_unlimited_unknown_mixed_case": ["UNLIMITED_APPROVAL_UNKNOWN"],
}


# --------------------------------------------------------------------------- build

def build(seed: int = SEED, per_category: int | None = None) -> list[dict]:
    cases: list[dict] = []
    for c in CATEGORIES:
        n = per_category or c.n
        rng = random.Random(f"{seed}/{c.name}")  # own stream: adding a category moves nothing else
        n_dev = round(n * DEV_FRACTION)
        for i in range(n):
            held = i >= n_dev
            body = c.gen(rng, held)
            case = {"category": c.name, "group": c.group, "split": "heldout" if held else "dev",
                    "expected": body.get("expected", c.expected),
                    "expect_rules": EXPECT_RULES.get(c.name, [])}
            if body.get("kind") == "bundle":
                case |= {"kind": "bundle", "txs": body["txs"], "sims": body["sims"]}
            else:
                case |= {"kind": "single", "tx": body["tx"], "sim": body["sim"]}
            case["policy"] = body.get("policy", POLICY)
            cases.append(case)
    random.Random(f"{seed}/order").shuffle(cases)
    for i, c in enumerate(cases):
        c["id"] = i
    return cases


def dumps(cases: list[dict]) -> str:
    return "".join(json.dumps(c, sort_keys=True) + "\n" for c in cases)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--check", action="store_true", help="exit 1 if evals/cases.jsonl is stale")
    ap.add_argument("--summary", action="store_true", help="print category table instead")
    a = ap.parse_args()
    cases = build(a.seed)
    if a.summary:
        for c in CATEGORIES:
            print(f"{c.name:<40}{c.expected:<6}{c.group:<12}{c.n:>4}  {c.rationale}")
        print(f"{len(CATEGORIES)} categories, {len(cases)} cases")
        return 0
    text = dumps(cases)
    if a.check:
        path = Path(__file__).with_name("cases.jsonl")
        if not path.exists() or path.read_text() != text:
            print("evals/cases.jsonl is stale: run `python evals/build_cases.py > evals/cases.jsonl`",
                  file=sys.stderr)
            return 1
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
