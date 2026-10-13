"""Score the deterministic risk engine against the labelled set.

    python evals/run_evals.py [--min-accuracy 0.9] [--show-errors]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from txwarden.models import SimResult, Tx
from txwarden.risk import PolicyConfig, assess

LABELS = ["ALLOW", "WARN", "BLOCK"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(Path(__file__).with_name("cases.jsonl")))
    ap.add_argument("--min-accuracy", type=float, default=0.0)
    ap.add_argument("--show-errors", action="store_true")
    a = ap.parse_args()

    cases = [json.loads(line) for line in Path(a.cases).read_text().splitlines() if line.strip()]
    conf: Counter[tuple[str, str]] = Counter()
    per_cat: dict[str, list[bool]] = defaultdict(list)
    errors = []
    for c in cases:
        verdict, findings = assess(Tx.from_dict(c["tx"]), SimResult.from_dict(c["sim"]),
                                   PolicyConfig(**{k: set(v) for k, v in c["policy"].items()}))
        got = verdict.value
        conf[(c["expected"], got)] += 1
        per_cat[c["category"]].append(got == c["expected"])
        if got != c["expected"]:
            errors.append((c["id"], c["category"], c["expected"], got, [f.rule for f in findings]))

    n = len(cases)
    correct = sum(conf[(l, l)] for l in LABELS)
    print(f"cases: {n}   accuracy: {correct / n:.3f}")
    tp = conf[("BLOCK", "BLOCK")]
    fp = sum(conf[(e, "BLOCK")] for e in LABELS if e != "BLOCK")
    fn = sum(conf[("BLOCK", g)] for g in LABELS if g != "BLOCK")
    print(f"BLOCK precision: {tp / (tp + fp) if tp + fp else 1.0:.3f}   "
          f"BLOCK recall: {tp / (tp + fn) if tp + fn else 1.0:.3f}")
    unsafe_allow = sum(conf[(e, "ALLOW")] for e in ("WARN", "BLOCK"))
    print(f"unsafe ALLOW (should have warned/blocked): {unsafe_allow}")
    print("\nconfusion (rows=expected, cols=got)")
    print("          " + "".join(f"{l:>7}" for l in LABELS))
    for e in LABELS:
        print(f"{e:<10}" + "".join(f"{conf[(e, g)]:>7}" for g in LABELS))
    print("\nper category")
    for cat, oks in sorted(per_cat.items()):
        print(f"  {cat:<28}{sum(oks)}/{len(oks)}")
    if a.show_errors:
        print("\nerrors")
        for e in errors:
            print("  ", e)
    return 0 if correct / n >= a.min_accuracy else 1


if __name__ == "__main__":
    sys.exit(main())
