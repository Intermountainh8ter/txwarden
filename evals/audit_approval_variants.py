"""False-negative audit of the rule engine on constructed approval-variant cases.

    python evals/audit_approval_variants.py --seed 7 --out results/73-approval-variants-fn-audit.json

The cases are **constructed and SIMULATED**: generated locally from a seed, not taken from a
public labelled release of real transactions. A false negative is an ALLOW verdict on a malicious
case; a false positive is a WARN or BLOCK on a benign one.
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

PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
NFT = "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d"
UNLIM256, UNLIM160, FAR = 2**256 - 1, 2**160 - 1, 2**48 - 1
SIG = "0x" + "ab" * 65
SIG_INC = "increaseAllowance(address,uint256)"
SIG_SAFA = "setApprovalForAll(address,bool)"
SIG_DAI = "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)"
SIG_P2A = "approve(address,address,uint160,uint48)"
SIG_P2B = "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)"


def addr(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))


def policy() -> PolicyConfig:
    return PolicyConfig(trusted_spenders={ROUTER})


def build(seed: int, n: int = 40) -> list[dict[str, Any]]:
    rng, cases = random.Random(seed), []

    def add(variant: str, malicious: bool, tx: Tx) -> None:
        cases.append({"variant": variant, "malicious": malicious, "tx": tx})

    def dai(user: str, spender: str, allowed: bool) -> Tx:
        return Tx(user, TOKEN, encode_call(SIG_DAI, [user, spender, 0, FAR, allowed, 27,
                                                    "0x" + "11" * 32, "0x" + "22" * 32]))

    def batch(user: str, spender: str, amt: int) -> Tx:
        det = [[TOKEN, amt, FAR, 0], [NFT, amt, FAR, 0]]
        return Tx(user, PERMIT2, encode_call(SIG_P2B, [user, [det, spender, 2**255], SIG]))

    for _ in range(n):
        user, bad = addr(rng), addr(rng)
        amt = rng.randint(1, 10**12)
        # malicious: unlimited or unbounded grant to an unknown spender or operator
        add("increaseAllowance", True, Tx(user, TOKEN, encode_call(SIG_INC, [bad, UNLIM256])))
        add("setApprovalForAll", True, Tx(user, NFT, encode_call(SIG_SAFA, [bad, True])))
        add("dai_permit", True, dai(user, bad, True))
        add("permit2_batch_permit", True, batch(user, bad, UNLIM160))
        add("permit2_approve", True,
            Tx(user, PERMIT2, encode_call(SIG_P2A, [TOKEN, bad, UNLIM160, FAR])))
        # benign matched controls
        add("increaseAllowance", False, Tx(user, TOKEN, encode_call(SIG_INC, [ROUTER, amt])))
        add("setApprovalForAll", False, Tx(user, NFT, encode_call(SIG_SAFA, [bad, False])))
        add("dai_permit", False, dai(user, bad, False))
        add("permit2_batch_permit", False, batch(user, ROUTER, amt))
        add("permit2_approve", False,
            Tx(user, PERMIT2, encode_call(SIG_P2A, [TOKEN, ROUTER, amt, 1_800_000_000])))
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


def run(seed: int, n: int = 40) -> dict[str, Any]:
    sim, pol = StaticSimulator(), policy()
    rows = []
    for c in build(seed, n):
        verdict, findings = assess(c["tx"], sim.simulate(c["tx"]), pol)
        rows.append({**c, "verdict": verdict.value if hasattr(verdict, "value") else str(verdict),
                     "rules": sorted({f.rule for f in findings if f.rule != "CHECKS_SKIPPED"})})
    mal = [r for r in rows if r["malicious"]]
    ben = [r for r in rows if not r["malicious"]]

    def fn(rs):
        return sum(r["verdict"] == "ALLOW" for r in rs)

    def fp(rs):
        return sum(r["verdict"] != "ALLOW" for r in rs)

    variants = sorted({r["variant"] for r in rows})
    fn_by, fp_by = {}, {}
    for v in variants:
        m = [r for r in mal if r["variant"] == v]
        b = [r for r in ben if r["variant"] == v]
        fn_by[v], fp_by[v] = rate(fn(m), len(m)), rate(fp(b), len(b))
    return {
        "set_label": "constructed, SIMULATED: not real transactions, not a public labelled release",
        "false_negative_rate": {"overall": fn(mal) / len(mal),
                                "overall_detail": rate(fn(mal), len(mal)), "by_variant": fn_by,
                                "max_variant": max(x["rate"] for x in fn_by.values())},
        "false_positive_rate": {"overall": fp(ben) / len(ben),
                                "overall_detail": rate(fp(ben), len(ben)), "by_variant": fp_by},
        "verdict_counts": {v: sum(r["verdict"] == v for r in rows)
                           for v in sorted({r["verdict"] for r in rows})},
        "rules_fired_malicious": sorted({x for r in mal for x in r["rules"]}),
        "n_cases": len(rows),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    t0, started = time.time(), datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = run(a.seed)
    res["provenance"] = {
        "started_at": started, "seeds": [a.seed],
        "command": "python3 evals/audit_approval_variants.py " + " ".join(argv or sys.argv[1:]),
        "hardware": "cpu", "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "constructed locally (no external data)",
                          "license": "MIT (component licence)"}],
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"fn": res["false_negative_rate"]["overall"],
                      "fp": res["false_positive_rate"]["overall"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
