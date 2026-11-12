"""False-negative audit of the rule engine on constructed ERC-4337 UserOperation cases.

    python evals/audit_userop_4337.py --seed 7 --out results/116-userop-4337-fn-audit.json

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

ENTRYPOINT = "0x0000000071727de22e5e9d8baf0edac6f37da032"
TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
SIG_OPS = "handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[],address)"
SIG_APPROVE = "approve(address,uint256)"
SIG_TRANSFER = "transfer(address,uint256)"
SIG_EXEC = "execute(address,uint256,bytes)"
SIG_BATCH = "executeBatch(address[],uint256[],bytes[])"
SIG_UPGRADE = "upgradeToAndCall(address,bytes)"
SIG = "0x" + "ab" * 65
MAX = 2**256 - 1


def addr(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))


def policy() -> PolicyConfig:
    return PolicyConfig()


def _hx(a: str) -> bytes:
    return bytes.fromhex(a[2:])


def build(seed: int, n: int = 40) -> list[dict[str, Any]]:
    rng, cases = random.Random(seed), []

    def add(variant: str, malicious: bool, tx: Tx) -> None:
        cases.append({"variant": variant, "malicious": malicious, "tx": tx})

    def ops(user: str, call_data: bytes, paymaster: str | None = None) -> Tx:
        pm = "0x" + paymaster[2:] + "00" * 32 if paymaster else "0x"
        op = [user, 0, "0x", "0x" + call_data.hex(), 200000, 100000, 50000, 10**9, 10**9, pm, SIG]
        return Tx(user, ENTRYPOINT, encode_call(SIG_OPS, [[op], user]))

    def single(user: str, target: str, inner: bytes) -> bytes:
        return _hx(encode_call(SIG_EXEC, [target, 0, "0x" + inner.hex()]))

    def batch(user: str, inners: list[bytes]) -> bytes:
        return _hx(encode_call(SIG_BATCH, [[TOKEN] * len(inners), [0] * len(inners),
                                           ["0x" + i.hex() for i in inners]]))

    for _ in range(n):
        user, bad, good = addr(rng), addr(rng), addr(rng)
        benign_inner = _hx(encode_call(SIG_TRANSFER, [good, rng.randint(1, 10**6)]))
        bounded = _hx(encode_call(SIG_APPROVE, [good, rng.randint(1, 10**6)]))
        unlimited = _hx(encode_call(SIG_APPROVE, [bad, MAX]))
        # unlimited approval to an unknown spender inside execute()
        add("unlimited_approval", True, ops(user, single(user, TOKEN, unlimited)))
        add("unlimited_approval", False, ops(user, single(user, TOKEN, bounded)))
        # one unlimited approval hidden among benign calls in executeBatch()
        pos = rng.randint(0, 2)
        mix = [benign_inner, bounded, benign_inner]
        mal = mix[:]
        mal[pos] = unlimited
        add("batch_hidden_approval", True, ops(user, batch(user, mal)))
        add("batch_hidden_approval", False, ops(user, batch(user, mix)))
        # delegatecall-style target change (upgradeToAndCall to an unknown implementation)
        add("target_change", True, ops(user, _hx(encode_call(SIG_UPGRADE, [bad, "0x"]))))
        add("target_change", False, ops(user, single(user, TOKEN, benign_inner)))
        # unknown paymaster vs no paymaster
        add("unknown_paymaster", True, ops(user, single(user, TOKEN, benign_inner), bad))
        add("unknown_paymaster", False, ops(user, single(user, TOKEN, benign_inner)))
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
        "command": "python3 evals/audit_userop_4337.py " + " ".join(argv or sys.argv[1:]),
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
