"""False-negative audit of the rule engine on constructed EIP-712 typed-data cases.

    python evals/audit_eip712_typed_data.py --seed 7 --out results/85-eip712-typed-data-fn-audit.json

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

from txwarden.models import Tx
from txwarden.risk import PolicyConfig, assess
from txwarden.simulator import StaticSimulator

SEAPORT = "0x0000000000000068f116a894984e2db1123eb395"
PERMIT_TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
UNBOUNDED = 2**256 - 1
FAIR = 10**18  # fair listing consideration in wei, fixed for the whole set


def addr(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))


def policy() -> PolicyConfig:
    return PolicyConfig()


def _word(x: int | str) -> bytes:
    if isinstance(x, str):
        return bytes.fromhex(x[2:]).rjust(32, b"\x00")
    return x.to_bytes(32, "big")


def typed_tx(user: str, verifying: str, fields: list[int | str]) -> Tx:
    """Closest Tx representation of an eth_signTypedData request.

    Tx has no typed-data field, so the signed payload (EIP-191 0x1901 prefix, a domain word for
    the verifying contract, then the struct words) is placed in `data` of a zero-value Tx to the
    verifying contract. This is a constructed encoding, not a real wire format.
    """
    body = b"\x19\x01" + _word(verifying) + b"".join(_word(f) for f in fields)
    return Tx(user, verifying, "0x" + body.hex())


def build(seed: int, n: int = 40) -> list[dict[str, Any]]:
    rng, cases = random.Random(seed), []

    def add(variant: str, malicious: bool, tx: Tx) -> None:
        cases.append({"variant": variant, "malicious": malicious, "tx": tx})

    for _ in range(n):
        user, bad, other = addr(rng), addr(rng), addr(rng)
        # free Seaport listing: consideration zero or far below fair, vs fair listing
        price = rng.randint(0, FAIR // 100)
        add("seaport_free_listing", True,
            typed_tx(user, SEAPORT, [user, PERMIT_TOKEN, price, rng.getrandbits(64)]))
        add("seaport_free_listing", False,
            typed_tx(user, SEAPORT, [user, PERMIT_TOKEN, rng.randint(FAIR * 99 // 100, FAIR),
                                     rng.getrandbits(64)]))
        # unbounded permit to an unknown spender, vs bounded permit to the signer's own router
        add("unbounded_permit", True,
            typed_tx(user, PERMIT_TOKEN, [user, bad, UNBOUNDED, rng.getrandbits(64)]))
        add("unbounded_permit", False,
            typed_tx(user, PERMIT_TOKEN, [user, user, rng.randint(1, 10**6), rng.getrandbits(64)]))
        # domain mismatch: verifying contract differs from the contract the dapp names
        add("domain_mismatch", True,
            typed_tx(user, other, [user, PERMIT_TOKEN, 10**6, rng.getrandbits(64)]))
        add("domain_mismatch", False,
            typed_tx(user, PERMIT_TOKEN, [user, PERMIT_TOKEN, 10**6, rng.getrandbits(64)]))
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
        "typed_data_input_path": "none: Tx has no typed-data field; cases use a constructed "
                                 "0x1901 payload in Tx.data",
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
        "command": "python3 evals/audit_eip712_typed_data.py " + " ".join(argv or sys.argv[1:]),
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
