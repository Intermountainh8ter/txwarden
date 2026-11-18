"""False-negative audit of the rule engine on constructed Permit2 transfer entrypoints.

    python3 evals/audit_permit2_transfers.py --seed 7 --out results/440-permit2-transfer-fn-audit.json

Cases are **constructed and SIMULATED** from a seed (no public labelled release exists): token
moves to an unknown recipient through permitTransferFrom (single, batch), permitWitnessTransferFrom
and AllowanceTransfer transferFrom, each with a matched benign control to a trusted recipient.
A false negative is an ALLOW verdict on a malicious case.
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

    def add(malicious: bool, kind: str, tx: Tx) -> None:
        cases.append({"class": "permit2_transfer" if malicious else "benign",
                      "malicious": malicious, "kind": kind, "tx": tx})

    sig_single = "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)"
    sig_batch = ("permitTransferFrom(((address,uint256)[],uint256,uint256),"
                 "(address,uint256)[],address,bytes)")
    sig_wit = ("permitWitnessTransferFrom(((address,uint256),uint256,uint256),(address,uint256),"
               "address,bytes32,string,bytes)")
    sig_allow = "transferFrom(address,address,uint160,address)"
    sigb = "0x" + "ab" * 65

    def single(user, to, amt, rng):
        return encode_call(sig_single, [[[TOKEN, amt], rng.randint(0, 2**64), FAR],
                                        [to, amt], user, sigb])

    def batch(user, to, amt, rng):
        return encode_call(sig_batch, [[[[TOKEN, amt], [TOKEN, amt + 1]], rng.randint(0, 2**64), FAR],
                                       [[to, amt], [to, amt + 1]], user, sigb])

    def wit(user, to, amt, rng):
        return encode_call(sig_wit, [[[TOKEN, amt], rng.randint(0, 2**64), FAR], [to, amt], user,
                                     "0x" + "cd" * 32, "Witness witness)", sigb])

    def allow(user, to, amt, rng):
        return encode_call(sig_allow, [user, to, min(amt, UNLIM160), TOKEN])

    builders = {"permit_transfer_single": single, "permit_transfer_batch": batch,
                "permit_witness_transfer": wit, "allowance_transfer_from": allow}
    for _ in range(n):
        user, bad = addr(rng), addr(rng)
        amt = rng.randint(1, 10**12)
        for kind, fn_ in builders.items():
            add(True, kind + "_unknown_recipient", Tx(user, PERMIT2, fn_(user, bad, amt, rng)))
            add(False, kind + "_trusted_recipient", Tx(user, PERMIT2, fn_(user, FRIEND, amt, rng)))
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
        "command": "python3 evals/audit_permit2_transfers.py " + " ".join(argv or sys.argv[1:]),
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
