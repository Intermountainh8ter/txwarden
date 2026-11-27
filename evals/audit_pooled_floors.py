"""Pooled false-negative audit of the rule engine against allow-all and deny-all floors.

    python evals/audit_pooled_floors.py --seed 7 --out results/645-pooled-floors-fn-audit.json

Pools the seeded **constructed and SIMULATED** sets of the shipped per-class audits into one labelled
set and scores the engine with Youden's J (TPR + TNR - 1; WARN or BLOCK counts as flagged). The
constant floors (flag nothing, flag everything) score exactly 0.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from txwarden.risk import assess  # noqa: E402
from txwarden.simulator import StaticSimulator  # noqa: E402

SOURCES = ["audit_7702_permit2", "audit_approval_variants", "audit_intent_swaps",
           "audit_userop_4337", "audit_permit2_transfers"]


def _load(name: str):
    spec = importlib.util.spec_from_file_location("pooled_" + name, HERE / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


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


def youden(flagged_mal: int, n_mal: int, flagged_ben: int, n_ben: int) -> float:
    return flagged_mal / n_mal + (n_ben - flagged_ben) / n_ben - 1


def run(seed: int, n: int = 40) -> dict[str, Any]:
    sim = StaticSimulator()
    rows = []
    for name in SOURCES:
        mod = _load(name)
        pol = mod.policy()
        for c in mod.build(seed, n):
            verdict, _ = assess(c["tx"], sim.simulate(c["tx"]), pol)
            v = verdict.value if hasattr(verdict, "value") else str(verdict)
            rows.append({"source": name, "malicious": c["malicious"], "flagged": v != "ALLOW"})
    mal = [r for r in rows if r["malicious"]]
    ben = [r for r in rows if not r["malicious"]]
    tp, fp = sum(r["flagged"] for r in mal), sum(r["flagged"] for r in ben)
    by_source = {}
    for name in SOURCES:
        m = [r for r in mal if r["source"] == name]
        b = [r for r in ben if r["source"] == name]
        by_source[name] = {"n_malicious": len(m), "n_benign": len(b),
                           "youden_j": youden(sum(r["flagged"] for r in m), len(m),
                                              sum(r["flagged"] for r in b), len(b))}
    return {
        "set_label": "constructed, SIMULATED: not real transactions, not a public labelled release",
        "engine": {"youden_j": youden(tp, len(mal), fp, len(ben)),
                   "false_negative_rate": rate(len(mal) - tp, len(mal)),
                   "false_positive_rate": rate(fp, len(ben)),
                   "by_source": by_source},
        "floors": {"allow_all": {"youden_j": youden(0, len(mal), 0, len(ben))},
                   "deny_all": {"youden_j": youden(len(mal), len(mal), len(ben), len(ben))}},
        "n_cases": len(rows), "n_malicious": len(mal), "n_benign": len(ben),
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
        "command": "python3 evals/audit_pooled_floors.py " + " ".join(argv or sys.argv[1:]),
        "hardware": "cpu", "wall_s": round(time.time() - t0, 3),
        "data_sources": [{"url": "constructed locally (no external data)",
                          "license": "MIT (component licence)"}],
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"youden_j": res["engine"]["youden_j"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
