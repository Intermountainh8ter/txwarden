"""Generate the synthetic labelled eval set (seeded, reproducible).

Labels come from the scenario template (what a human reviewer would say about that
class of transaction), NOT from running the risk engine. Thresholds in risk.py are
therefore evaluated against independent intent, and disagreements show up as errors.

    python evals/build_cases.py > evals/cases.jsonl
"""
from __future__ import annotations

import json
import random
import sys

ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
EVIL = "0xdead00000000000000000000000000000000beef"
USER = "0x1111111111111111111111111111111111111111"
FRIEND = "0x2222222222222222222222222222222222222222"
STRANGER = "0x3333333333333333333333333333333333333333"
TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
POLICY = {"trusted_spenders": [ROUTER, PERMIT2], "trusted_recipients": [FRIEND], "denylist": [EVIL]}
UNLIM = 2**256 - 1
E = 10**18


def tx(i: int) -> dict:
    return {"sender": USER, "to": TOKEN, "data": f"0xcase{i:04d}", "value": 0}


def swap_case(rng: random.Random, pool: float, frac: float, slip: float) -> dict:
    x = pool * E
    y = x * rng.uniform(0.0005, 0.002)  # token_out is pricier
    amt = x * frac
    clean = amt * 0.997 * y / (x + amt * 0.997)
    return {"success": True, "swap": {"amount_in": amt, "min_out": clean * (1 - slip),
                                      "reserve_in": x, "reserve_out": y}}


def build() -> list[dict]:
    rng = random.Random(1337)
    cases: list[dict] = []

    def add(category: str, expected: str, sim: dict) -> None:
        i = len(cases)
        cases.append({"id": i, "category": category, "expected": expected,
                      "tx": tx(i), "sim": sim, "policy": POLICY})

    for _ in range(14):  # tight slippage, small trade, deep pool
        add("swap_tight", "ALLOW", swap_case(rng, rng.uniform(2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.001))
    for _ in range(10):  # moderate slippage
        add("swap_moderate", "WARN", swap_case(rng, rng.uniform(2e3, 2e4), rng.uniform(1e-4, 1e-3), 0.01))
    for _ in range(14):  # loose slippage
        add("swap_loose", "BLOCK", swap_case(rng, rng.uniform(2e3, 2e4), rng.uniform(1e-4, 1e-3), rng.uniform(0.03, 0.2)))
    for _ in range(8):  # big trade, thin pool, tight slippage but huge impact
        add("swap_high_impact", "WARN", swap_case(rng, rng.uniform(50, 200), rng.uniform(0.055, 0.1), 0.0))
    for _ in range(8):
        add("swap_extreme_impact", "BLOCK", swap_case(rng, rng.uniform(50, 200), rng.uniform(0.3, 1.0), 0.0))

    for _ in range(8):  # sizeable trade in a mid pool with 2% slippage: textbook sandwich target
        add("swap_sandwichable", "BLOCK", swap_case(rng, rng.uniform(300, 1500), rng.uniform(0.01, 0.03), 0.02))

    def appr(spender: str, amt: int) -> dict:
        return {"success": True, "approvals": [{"token": TOKEN, "owner": USER, "spender": spender, "amount": amt}]}

    for _ in range(8):
        add("approve_unlimited_unknown", "BLOCK", appr(f"0x{rng.getrandbits(160):040x}", UNLIM))
    for _ in range(6):
        add("approve_unlimited_trusted", "ALLOW", appr(rng.choice([ROUTER, PERMIT2]), UNLIM))
    for _ in range(6):
        add("approve_bounded_trusted", "ALLOW", appr(ROUTER, rng.randint(1, 10**9) * 10**6))
    for _ in range(6):
        add("approve_bounded_unknown", "WARN", appr(f"0x{rng.getrandbits(160):040x}", rng.randint(1, 10**9) * 10**6))
    for _ in range(5):
        add("approve_denylisted", "BLOCK", appr(EVIL, rng.randint(1, 10**9)))

    def xfer(to: str, frac: float) -> dict:
        bal = 10**9 * rng.randint(1, 100)
        return {"success": True, "transfers": [{"token": TOKEN, "sender": USER, "recipient": to,
                                                "amount": int(bal * frac), "sender_balance_before": bal}]}

    for _ in range(6):
        add("transfer_trusted", "ALLOW", xfer(FRIEND, rng.uniform(0.1, 1.0)))
    for _ in range(6):
        add("transfer_unknown_small", "ALLOW", xfer(STRANGER, rng.uniform(0.01, 0.5)))
    for _ in range(6):
        add("transfer_unknown_drain", "WARN", xfer(STRANGER, rng.uniform(0.92, 1.0)))
    for _ in range(5):
        add("transfer_denylisted", "BLOCK", xfer(EVIL, rng.uniform(0.01, 1.0)))
    for _ in range(6):
        add("revert", "WARN", {"success": False, "revert_reason": rng.choice(
            ["INSUFFICIENT_OUTPUT_AMOUNT", "TRANSFER_FROM_FAILED", "EXPIRED"])})
    rng.shuffle(cases)
    for i, c in enumerate(cases):
        c["id"] = i
        c["tx"]["data"] = f"0xcase{i:04d}"
    return cases


if __name__ == "__main__":
    for c in build():
        sys.stdout.write(json.dumps(c) + "\n")
