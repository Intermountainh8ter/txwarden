"""False-negative audit of the rule engine on constructed EIP-7702 and Permit2 cases.

    python evals/audit_7702_permit2.py --seed 7 --out results/72-7702-permit2-fn-audit.json

The cases are **constructed and SIMULATED**: they are generated locally from a seed, not taken
from a public labelled release of real transactions. ``Tx`` has no authorization-list field, so a
7702 delegation is modelled by what the engine could see of it: a transaction to the sender's own
address (authorization only, empty calldata) or a call into an unknown delegate or the delegated
account with unrecognised calldata. A false negative is an ALLOW verdict on a malicious case.
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
FRIEND = "0x" + "22" * 20
TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
UNLIM160 = 2**160 - 1
FAR = 2**48 - 1
SWEEP_SIGS = ("execute((address,uint256,bytes)[])", "execute(address,uint256,bytes)",
              "sweep(address)")


def addr(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))


def policy() -> PolicyConfig:
    return PolicyConfig(trusted_spenders={ROUTER}, trusted_recipients={FRIEND})


def build(seed: int, n: int = 40) -> list[dict[str, Any]]:
    rng, cases = random.Random(seed), []

    def add(cls: str, malicious: bool, kind: str, tx: Tx) -> None:
        cases.append({"class": cls, "malicious": malicious, "kind": kind, "tx": tx})

    for _ in range(n):
        user, bad, deleg = addr(rng), addr(rng), addr(rng)
        amt = rng.randint(1, 10**12)
        # 7702, malicious: authorization-only tx, or sweeper call into the delegated account
        add("eip7702", True, "authorization_only", Tx(user, user, "0x"))
        sig = rng.choice(SWEEP_SIGS)
        vals = {"sweep(address)": [bad]}.get(sig)
        if vals is None:
            vals = ([[(bad, amt, "0x")]] if sig.startswith("execute((") else [bad, amt, "0x"])
        add("eip7702", True, "sweeper_call", Tx(user, user, encode_call(sig, vals)))
        add("eip7702", True, "delegate_call", Tx(user, deleg, encode_call(sig, vals)))
        # Permit2, malicious
        exp = rng.choice([FAR, 1_900_000_000 + rng.randint(0, 10**6)])
        add("permit2", True, "approve_unlimited_unknown",
            Tx(user, PERMIT2, encode_call("approve(address,address,uint160,uint48)",
                                          [TOKEN, bad, UNLIM160, exp])))
        add("permit2", True, "approve_bounded_unknown",
            Tx(user, PERMIT2, encode_call("approve(address,address,uint160,uint48)",
                                          [TOKEN, bad, amt, exp])))
        add("permit2", True, "permit_unlimited_unknown",
            Tx(user, PERMIT2, encode_call(
                "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
                [user, [[TOKEN, UNLIM160, exp, 0], bad, 2**255], "0x" + "ab" * 65])))
        # benign controls
        add("benign", False, "approve_bounded_trusted",
            Tx(user, PERMIT2, encode_call("approve(address,address,uint160,uint48)",
                                          [TOKEN, ROUTER, amt, 1_800_000_000])))
        add("benign", False, "eth_to_trusted_recipient", Tx(user, FRIEND, "0x", 10**15))
        add("benign", False, "erc20_approve_bounded_trusted",
            Tx(user, TOKEN, encode_call("approve(address,uint256)", [ROUTER, amt])))
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


def run(seed: int) -> dict[str, Any]:
    sim, pol = StaticSimulator(), policy()
    rows = []
    for c in build(seed):
        verdict, findings = assess(c["tx"], sim.simulate(c["tx"]), pol)
        rows.append({**c, "verdict": verdict.value if hasattr(verdict, "value") else str(verdict),
                     "rules": sorted({f.rule for f in findings if f.rule != "CHECKS_SKIPPED"})})
    mal = [r for r in rows if r["malicious"]]
    ben = [r for r in rows if not r["malicious"]]
    fn = lambda rs: sum(r["verdict"] == "ALLOW" for r in rs)  # noqa: E731
    by_kind: dict[str, Any] = {}
    for kind in sorted({r["kind"] for r in mal}):
        rs = [r for r in mal if r["kind"] == kind]
        by_kind[kind] = rate(fn(rs), len(rs))
    return {
        "set_label": "constructed, SIMULATED: not real transactions, not a public labelled release",
        "false_negative_rate": {
            "overall": fn(mal) / len(mal),
            "overall_detail": rate(fn(mal), len(mal)),
            "eip7702": rate(fn([r for r in mal if r["class"] == "eip7702"]),
                            sum(r["class"] == "eip7702" for r in mal)),
            "permit2": rate(fn([r for r in mal if r["class"] == "permit2"]),
                            sum(r["class"] == "permit2" for r in mal)),
            "by_kind": by_kind,
        },
        "false_positive_rate": rate(sum(r["verdict"] != "ALLOW" for r in ben), len(ben)),
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
        "command": "python3 evals/audit_7702_permit2.py " + " ".join(argv or sys.argv[1:]),
        "hardware": "cpu", "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "constructed locally (no external data)",
                          "license": "MIT (component licence)"}],
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    print(json.dumps(res["false_negative_rate"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
