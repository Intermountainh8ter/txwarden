"""Miss rate of per-order and aggregate exposure caps on SIMULATED agent order sequences.

    python3 evals/audit_order_caps.py --seed 7 --out results/144-order-caps-miss-rate.json

Sequences are generated locally from a seed in a neutral generic schema (a list of order
notionals in abstract units). Nothing is taken from a real venue or account. A miss is a sequence
the rule passes although it is malicious (single oversize order, or sub-cap orders that jointly
exceed the exposure cap); a false positive is a benign sequence the rule rejects.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PER_ORDER_CAP = 1000
AGGREGATE_CAP = 5000


def per_order_rule(orders: list[int]) -> bool:
    """True if the sequence is rejected: some single order exceeds the per-order cap."""
    return any(o > PER_ORDER_CAP for o in orders)


def aggregate_rule(orders: list[int]) -> bool:
    """True if rejected: per-order cap breached or the summed exposure exceeds the aggregate cap."""
    return per_order_rule(orders) or sum(orders) > AGGREGATE_CAP


def build(seed: int, n: int = 200) -> list[dict[str, Any]]:
    rng, cases = random.Random(seed), []
    for _ in range(n):
        while True:  # split: every order under the per-order cap, joint total over the aggregate cap
            orders = [rng.randint(int(0.6 * PER_ORDER_CAP), PER_ORDER_CAP)
                      for _ in range(rng.randint(7, 12))]
            if sum(orders) > AGGREGATE_CAP:
                break
        cases.append({"class": "aggregate_exposure_split", "malicious": True, "orders": orders})
        big = rng.randint(PER_ORDER_CAP + 1, 3 * PER_ORDER_CAP)
        orders = [rng.randint(1, PER_ORDER_CAP) for _ in range(rng.randint(0, 3))] + [big]
        rng.shuffle(orders)
        cases.append({"class": "single_oversize", "malicious": True, "orders": orders})
        while True:  # benign: sub-cap orders, total within the aggregate cap
            orders = [rng.randint(1, PER_ORDER_CAP) for _ in range(rng.randint(2, 5))]
            if sum(orders) <= AGGREGATE_CAP:
                break
        cases.append({"class": "benign", "malicious": False, "orders": orders})
    return cases


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 1.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def run(seed: int, n: int = 200) -> dict[str, Any]:
    cases = build(seed, n)
    rules = {"per_order_only": per_order_rule, "with_aggregate": aggregate_rule}
    miss: dict[str, Any] = {}
    fp: dict[str, Any] = {}
    ci: dict[str, Any] = {}
    counts: dict[str, int] = {}
    for cls in ("aggregate_exposure_split", "single_oversize"):
        sel = [c for c in cases if c["class"] == cls]
        counts[cls] = len(sel)
    counts["benign"] = sum(not c["malicious"] for c in cases)
    for name, rule in rules.items():
        for cls in ("aggregate_exposure_split", "single_oversize"):
            sel = [c for c in cases if c["class"] == cls]
            k = sum(not rule(c["orders"]) for c in sel)
            miss.setdefault(cls, {})[name] = k / len(sel)
            ci.setdefault(cls, {})[name] = wilson(k, len(sel))
        ben = [c for c in cases if not c["malicious"]]
        fp[name] = sum(rule(c["orders"]) for c in ben) / len(ben)
    res: dict[str, Any] = {
        "set_label": "SIMULATED seeded order sequences, generic schema; not real orders",
        "caps": {"per_order": PER_ORDER_CAP, "aggregate": AGGREGATE_CAP},
        "counts": counts,
        "miss_rate": {
            "aggregate_exposure_split": miss["aggregate_exposure_split"]["per_order_only"],
            "aggregate_exposure_split_with_aggregate": miss["aggregate_exposure_split"]["with_aggregate"],
            "by_class": miss,
        },
        "wilson_95": ci,
        "false_positive_rate": fp,
    }
    return res


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    t0, started = time.time(), datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = run(a.seed)
    res["provenance"] = {
        "started_at": started, "seeds": [a.seed],
        "command": "python3 evals/audit_order_caps.py " + " ".join(argv or sys.argv[1:]),
        "hardware": "cpu", "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "locally generated seeded synthetic orders (no external data)",
                          "license": "MIT (repository code, no third-party data)"}],
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"miss": res["miss_rate"]["aggregate_exposure_split"],
                      "fp": res["false_positive_rate"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
