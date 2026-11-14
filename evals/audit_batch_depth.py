"""False-negative audit of the rule engine on unlimited approvals nested in multicall payloads.

    python evals/audit_batch_depth.py --seed 7 --out results/175-batch-depth-fn-audit.json

The cases are **constructed and SIMULATED**: generated locally from a seed. An unlimited ERC-20
approval to an unknown spender is wrapped in ``depth`` levels of ``multicall(bytes[])`` among
benign calls. A miss is any outcome other than a BLOCK verdict on a malicious case (an uncaught engine
exception counts as a miss and is tallied separately); a false positive is a
BLOCK on the matched benign nested multicall.
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from txwarden.abi import encode_call
from txwarden.models import Tx
from txwarden.risk import PolicyConfig, assess
from txwarden.simulator import StaticSimulator

ROUTER = "0xe592427a0aece92de3edee1f18e0157c05861564"
TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
SIG_APPROVE = "approve(address,uint256)"
SIG_TRANSFER = "transfer(address,uint256)"
SIG_MULTI = "multicall(bytes[])"
MAX = 2**256 - 1
DEPTHS = (1, 2, 3, 4, 5, 6)


def addr(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))


def _wrap(inners: list[str], depth: int) -> str:
    """Wrap a list of calldata hex strings in ``depth`` nested multicall levels."""
    data = encode_call(SIG_MULTI, [inners])
    for _ in range(depth - 1):
        data = encode_call(SIG_MULTI, [[data]])
    return data


def build(seed: int, n: int = 400) -> list[dict[str, Any]]:
    rng, cases = random.Random(seed), []
    for depth in DEPTHS:
        for _ in range(n):
            user, bad, good = addr(rng), addr(rng), addr(rng)
            benign = encode_call(SIG_TRANSFER, [good, rng.randint(1, 10**6)])
            bounded = encode_call(SIG_APPROVE, [good, rng.randint(1, 10**6)])
            unlimited = encode_call(SIG_APPROVE, [bad, MAX])
            mix = [benign, bounded, benign]
            mal = mix[:]
            mal[rng.randint(0, 2)] = unlimited
            for malicious, inners in ((True, mal), (False, mix)):
                cases.append({"depth": depth, "malicious": malicious,
                              "tx": Tx(user, TOKEN, _wrap(inners, depth))})
    return cases


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 1.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": k / n if n else None, "wilson95": wilson(k, n)}


def run(seed: int, n: int = 400) -> dict[str, Any]:
    sim, pol = StaticSimulator(), PolicyConfig()
    rows = []
    for c in build(seed, n):
        try:
            verdict, _ = assess(c["tx"], sim.simulate(c["tx"]), pol)
            v = verdict.value if hasattr(verdict, "value") else str(verdict)
        except Exception:  # an uncaught engine error yields no verdict at all
            v = "CRASH"
        rows.append({"depth": c["depth"], "malicious": c["malicious"], "verdict": v})
    miss, fpr, crash = {}, {}, {}
    for d in DEPTHS:
        m = [r for r in rows if r["depth"] == d and r["malicious"]]
        b = [r for r in rows if r["depth"] == d and not r["malicious"]]
        crash[d] = sum(r["verdict"] == "CRASH" for r in m)
        miss[d] = rate(sum(r["verdict"] != "BLOCK" for r in m), len(m))
        fpr[d] = rate(sum(r["verdict"] == "BLOCK" for r in b), len(b))
    return {
        "set_label": "constructed, SIMULATED: not real transactions, not a public labelled release",
        "batch": {
            "miss_rate": {f"depth_{d}": miss[d]["rate"] for d in DEPTHS},
            "miss_detail": {f"depth_{d}": miss[d] for d in DEPTHS},
            "benign_block_rate": {f"depth_{d}": fpr[d]["rate"] for d in DEPTHS},
            "benign_block_detail": {f"depth_{d}": fpr[d] for d in DEPTHS},
            "crash_count_malicious": {f"depth_{d}": crash[d] for d in DEPTHS},
            "max_benign_block_rate": max(x["rate"] for x in fpr.values()),
            "decoder_max_depth": __import__("txwarden.abi", fromlist=["MAX_DEPTH"]).MAX_DEPTH,
        },
        "n_cases": len(rows),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    t0, started = time.time(), datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = run(a.seed, a.n)
    res["provenance"] = {
        "started_at": started, "seeds": [a.seed],
        "command": "python3 evals/audit_batch_depth.py " + " ".join(argv or sys.argv[1:]),
        "hardware": "cpu", "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "constructed locally (no external data)",
                          "license": "MIT (component licence)"}],
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    print(json.dumps(res["batch"]["miss_rate"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
