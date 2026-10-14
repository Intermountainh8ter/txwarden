"""Score the deterministic risk engine against the labelled synthetic set.

    python evals/run_evals.py                          # all splits, headline numbers
    python evals/run_evals.py --split heldout --show-errors
    python evals/run_evals.py --sweep                  # threshold frontier: unsafe ALLOW vs over-BLOCK
    python evals/run_evals.py --min-accuracy 0.9 --max-unsafe-allow 0    # CI gate (exit 1 on miss)
    python evals/run_evals.py --markdown               # the tables pasted into README.md
    python evals/run_evals.py --cases evals/cases_v1.jsonl   # the original 122-case set

Definitions (expected = the template's label, got = the engine's verdict):

- accuracy: got == expected.
- unsafe ALLOW: expected WARN or BLOCK, got ALLOW. The error that lets a bad transaction through.
- over-BLOCK: expected ALLOW or WARN, got BLOCK. Friction: a user is told "do not sign" for a
  transaction a reviewer would accept or merely flag.
- under-BLOCK: expected BLOCK, got WARN.
- right reason: among cases with the correct non-ALLOW verdict, the share where at least one of the
  template's expected rule ids fired.

Thresholds are tuned on ``dev`` only (``--sweep`` shows both splits side by side); ``heldout`` is
the number to quote.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from txwarden.batch import assess_bundle
from txwarden.models import SimResult, Tx, Verdict
from txwarden.risk import PolicyConfig, apply_rules, compute_facts, verdict_from

LABELS = ["ALLOW", "WARN", "BLOCK"]
DEFAULT_CASES = Path(__file__).with_name("cases.jsonl")


# --------------------------------------------------------------------------- loading

@dataclass
class Prepared:
    case: dict[str, Any]
    tx: Tx | None = None
    sim: SimResult | None = None
    facts: Any = None
    txs: list[Tx] = field(default_factory=list)
    sims: list[SimResult] = field(default_factory=list)


def load_cases(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def prepare(cases: list[dict[str, Any]]) -> list[Prepared]:
    out = []
    for c in cases:
        if c.get("kind") == "bundle":
            out.append(Prepared(c, txs=[Tx.from_dict(t) for t in c["txs"]],
                                sims=[SimResult.from_dict(s) for s in c["sims"]]))
        else:
            tx, sim = Tx.from_dict(c["tx"]), SimResult.from_dict(c["sim"])
            out.append(Prepared(c, tx, sim, compute_facts(tx, sim)))
    return out


def make_policy(raw: dict[str, Any], overrides: dict[str, Any] | None) -> PolicyConfig:
    return PolicyConfig.from_dict({**raw, **(overrides or {})})


def run_case(p: Prepared, overrides: dict[str, Any] | None = None) -> tuple[Verdict, set[str]]:
    policy = make_policy(p.case["policy"], overrides)
    if p.case.get("kind") == "bundle":
        review = assess_bundle(p.txs, p.sims, policy)
        rules = {f.rule for t in review.per_tx for f in t.findings}
        rules |= {f.rule for f in review.bundle_findings}
        return review.verdict, rules
    findings = apply_rules(p.tx, p.sim, p.facts, policy)
    return verdict_from(findings), {f.rule for f in findings}


# --------------------------------------------------------------------------- metrics

@dataclass
class Result:
    n: int = 0
    correct: int = 0
    unsafe_allow: int = 0
    over_block: int = 0
    under_block: int = 0
    conf: Counter = field(default_factory=Counter)
    reason_ok: int = 0
    reason_n: int = 0
    per_cat: dict[str, list[bool]] = field(default_factory=lambda: defaultdict(list))
    per_group: dict[str, list[bool]] = field(default_factory=lambda: defaultdict(list))
    errors: list[tuple] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        return self.correct / self.n if self.n else 1.0

    def block_pr(self) -> tuple[float, float]:
        tp = self.conf[("BLOCK", "BLOCK")]
        fp = sum(self.conf[(e, "BLOCK")] for e in LABELS if e != "BLOCK")
        fn = sum(self.conf[("BLOCK", g)] for g in LABELS if g != "BLOCK")
        return (tp / (tp + fp) if tp + fp else 1.0, tp / (tp + fn) if tp + fn else 1.0)


def evaluate(prepared: list[Prepared], overrides: dict[str, Any] | None = None) -> Result:
    r = Result()
    for p in prepared:
        c = p.case
        verdict, rules = run_case(p, overrides)
        got, exp = verdict.value, c["expected"]
        r.n += 1
        r.conf[(exp, got)] += 1
        ok = got == exp
        r.correct += ok
        r.per_cat[c["category"]].append(ok)
        r.per_group[c.get("group", "all")].append(ok)
        if exp != "ALLOW" and got == "ALLOW":
            r.unsafe_allow += 1
        if exp != "BLOCK" and got == "BLOCK":
            r.over_block += 1
        if exp == "BLOCK" and got == "WARN":
            r.under_block += 1
        if ok and exp != "ALLOW" and c.get("expect_rules"):
            r.reason_n += 1
            r.reason_ok += bool(rules & set(c["expect_rules"]))
        if not ok:
            r.errors.append((c["id"], c["category"], exp, got, sorted(rules)))
    return r


def split_cases(cases: list[dict[str, Any]], split: str) -> list[dict[str, Any]]:
    if split == "all":
        return cases
    return [c for c in cases if c.get("split", "dev") == split]


# --------------------------------------------------------------------------- sweeps

SWAP_KNOBS = {"sandwich_warn_bps": 30.0, "sandwich_block_bps": 100.0, "impact_warn_bps": 500.0,
              "impact_block_bps": 2000.0, "slippage_warn": 0.0075, "slippage_block": 0.05}


def scaled(k: float) -> dict[str, Any]:
    return {name: v * k for name, v in SWAP_KNOBS.items()}


SWEEPS: dict[str, tuple[str, list[tuple[str, dict[str, Any]]]]] = {
    # title: (label of the shipped default, [(label, PolicyConfig overrides)])
    "swap thresholds x k (all six scaled together; k>1 is looser)": (
        "k=1", [(f"k={k:g}", scaled(k)) for k in (0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0)]),
    "slippage_block (default 0.05)": (
        "0.05", [(f"{v:g}", {"slippage_block": v}) for v in (0.01, 0.02, 0.03, 0.04, 0.05, 0.08, 0.15)]),
    "impact_warn_bps (default 500)": (
        "500", [(f"{v:g}", {"impact_warn_bps": v}) for v in (100, 200, 300, 400, 500, 800, 1500)]),
    "sandwich_warn_bps (default 30)": (
        "30", [(f"{v:g}", {"sandwich_warn_bps": v}) for v in (5, 15, 30, 45, 60, 100, 200)]),
    "drain_fraction (default 0.9)": (
        "0.9", [(f"{v:g}", {"drain_fraction": v}) for v in (0.3, 0.5, 0.7, 0.9, 0.95, 0.99)]),
    "honeypot_loss_warn (default 0.05)": (
        "0.05", [(f"{v:g}", {"honeypot_loss_warn": v}) for v in (0.01, 0.03, 0.05, 0.1, 0.2)]),
    "lp_removal_block_fraction (default 0.5)": (
        "0.5", [(f"{v:g}", {"lp_removal_block_fraction": v}) for v in (0.25, 0.4, 0.5, 0.7, 0.9)]),
    "gas_abnormal_multiple (default 5)": (
        "5", [(f"{v:g}", {"gas_abnormal_multiple": v}) for v in (2.0, 3.0, 5.0, 8.0, 20.0, 50.0)]),
}


def pareto(points: list[tuple[int, int]]) -> list[bool]:
    """True for points not dominated on (unsafe_allow, over_block), both to be minimised."""
    flags = []
    for i, (a, b) in enumerate(points):
        dominated = any(a2 <= a and b2 <= b and (a2 < a or b2 < b)
                        for j, (a2, b2) in enumerate(points) if j != i)
        flags.append(not dominated)
    return flags


def run_sweeps(dev: list[Prepared], held: list[Prepared], only: str | None, out: Any) -> None:
    for title, (default_label, variants) in SWEEPS.items():
        if only and only not in title:
            continue
        rows = []
        for label, ov in variants:
            d, h = evaluate(dev, ov), evaluate(held, ov)
            rows.append((label, d, h))
        flags = pareto([(d.unsafe_allow, d.over_block) for _, d, _ in rows])
        print(f"\n{title}", file=out)
        print(f"  {'setting':<10}{'dev acc':>9}{'unsafe':>8}{'over-B':>8}{'|':>3}"
              f"{'held acc':>9}{'unsafe':>8}{'over-B':>8}   frontier(dev)", file=out)
        for (label, d, h), on in zip(rows, flags):
            print(f"  {label:<10}{d.accuracy:>9.3f}{d.unsafe_allow:>8}{d.over_block:>8}{'|':>3}"
                  f"{h.accuracy:>9.3f}{h.unsafe_allow:>8}{h.over_block:>8}   {'*' if on else ''}",
                  file=out)
        best = max(rows, key=lambda r: (r[1].accuracy, -r[1].unsafe_allow))
        base = next(r for r in rows if r[0] == default_label)
        print(f"  best on dev: {best[0]} (dev {best[1].accuracy:.3f} -> held-out {best[2].accuracy:.3f});"
              f" default: {base[0]} (held-out {base[2].accuracy:.3f})", file=out)


# --------------------------------------------------------------------------- reporting

def pct(ok: list[bool]) -> str:
    return f"{sum(ok)}/{len(ok)}"


def print_report(r: Result, title: str, out: Any, show_errors: bool, by_category: bool = True) -> None:
    prec, rec = r.block_pr()
    print(f"[{title}] cases: {r.n}   accuracy: {r.accuracy:.3f}", file=out)
    print(f"  BLOCK precision: {prec:.3f}   BLOCK recall: {rec:.3f}", file=out)
    print(f"  unsafe ALLOW (should have warned/blocked): {r.unsafe_allow}", file=out)
    print(f"  over-BLOCK (blocked, reviewer would allow/warn): {r.over_block}   "
          f"under-BLOCK (warned, reviewer would block): {r.under_block}", file=out)
    if r.reason_n:
        print(f"  right reason (expected rule fired when verdict matched): "
              f"{r.reason_ok}/{r.reason_n} = {r.reason_ok / r.reason_n:.3f}", file=out)
    print("  confusion (rows=expected, cols=got)", file=out)
    print("            " + "".join(f"{x:>7}" for x in LABELS), file=out)
    for e in LABELS:
        print(f"  {e:<10}" + "".join(f"{r.conf[(e, g)]:>7}" for g in LABELS), file=out)
    print("  per group", file=out)
    for g, oks in sorted(r.per_group.items()):
        print(f"    {g:<14}{pct(oks):>9}  {sum(oks) / len(oks):.3f}", file=out)
    if by_category:
        print("  per category (only those below 100% are marked)", file=out)
        for cat, oks in sorted(r.per_cat.items()):
            mark = "" if all(oks) else "   <--"
            print(f"    {cat:<40}{pct(oks):>8}{mark}", file=out)
    if show_errors:
        print("  errors (id, category, expected, got, rules)", file=out)
        for e in r.errors:
            print("   ", e, file=out)


def markdown(all_r: Result, dev: Result, held: Result, n_cat: int) -> str:
    def row(name: str, r: Result) -> str:
        p, rc = r.block_pr()
        rs = f"{r.reason_ok / r.reason_n:.3f}" if r.reason_n else "n/a"
        return (f"| {name} | {r.n} | {r.accuracy:.3f} | {r.unsafe_allow} | {r.over_block} | "
                f"{p:.3f} | {rc:.3f} | {rs} |")

    lines = ["| Split | Cases | Accuracy | Unsafe ALLOW | Over-BLOCK | BLOCK precision | BLOCK recall "
             "| Right reason |", "|---|---:|---:|---:|---:|---:|---:|---:|",
             row("dev", dev), row("held-out", held), row("all", all_r), "",
             f"{n_cat} categories.", "", "| Group | Correct / total (all splits) | Accuracy |",
             "|---|---:|---:|"]
    lines += [f"| {g} | {pct(oks)} | {sum(oks) / len(oks):.3f} |"
              for g, oks in sorted(all_r.per_group.items())]
    below = sorted((c, oks) for c, oks in all_r.per_cat.items() if not all(oks))
    lines += ["", "Categories below 100% (all splits):", "", "| Category | Correct / total |", "|---|---:|"]
    lines += [f"| `{c}` | {pct(oks)} |" for c, oks in below] or ["| (none) | |"]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--cases", default=str(DEFAULT_CASES))
    ap.add_argument("--split", choices=["dev", "heldout", "all"], default="all")
    ap.add_argument("--min-accuracy", type=float, default=0.0)
    ap.add_argument("--max-unsafe-allow", type=int, default=None)
    ap.add_argument("--max-over-block", type=int, default=None)
    ap.add_argument("--show-errors", action="store_true")
    ap.add_argument("--no-categories", action="store_true")
    ap.add_argument("--sweep", nargs="?", const="", default=None, metavar="NAME",
                    help="threshold frontier; optionally only sweeps whose title contains NAME")
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    ap.add_argument("--markdown", action="store_true", help="README tables")
    a = ap.parse_args()

    cases = load_cases(a.cases)
    t0 = time.perf_counter()
    prepared = prepare(split_cases(cases, a.split))
    full = prepare(cases) if a.split != "all" else prepared
    dev = [p for p in full if p.case.get("split", "dev") == "dev"]
    held = [p for p in full if p.case.get("split") == "heldout"]
    result = evaluate(prepared)
    elapsed = time.perf_counter() - t0
    n_cat = len({c["category"] for c in cases})

    if a.json:
        prec, rec = result.block_pr()
        print(json.dumps({
            "split": a.split, "cases": result.n, "categories": n_cat, "accuracy": result.accuracy,
            "unsafe_allow": result.unsafe_allow, "over_block": result.over_block,
            "under_block": result.under_block, "block_precision": prec, "block_recall": rec,
            "right_reason": result.reason_ok / result.reason_n if result.reason_n else None,
            "per_category": {c: sum(v) / len(v) for c, v in sorted(result.per_cat.items())},
            "seconds": elapsed}, indent=2))
    elif a.markdown:
        print(markdown(evaluate(full), evaluate(dev), evaluate(held), n_cat))
    elif a.sweep is not None:
        if not dev or not held:
            print("sweeps need a cases file with dev and heldout splits", file=sys.stderr)
            return 3
        run_sweeps(dev, held, a.sweep or None, sys.stdout)
    else:
        print(f"cases file: {a.cases}   categories: {n_cat}   split: {a.split}   "
              f"({elapsed:.1f}s)")
        print_report(result, a.split, sys.stdout, a.show_errors, not a.no_categories)
        if a.split == "all" and dev and held:
            for name, subset in (("dev", dev), ("heldout", held)):
                print_report(evaluate(subset), name, sys.stdout, False, by_category=False)

    failed = False
    if result.accuracy < a.min_accuracy:
        print(f"FAIL: accuracy {result.accuracy:.3f} < {a.min_accuracy}", file=sys.stderr)
        failed = True
    if a.max_unsafe_allow is not None and result.unsafe_allow > a.max_unsafe_allow:
        print(f"FAIL: unsafe ALLOW {result.unsafe_allow} > {a.max_unsafe_allow}", file=sys.stderr)
        failed = True
    if a.max_over_block is not None and result.over_block > a.max_over_block:
        print(f"FAIL: over-BLOCK {result.over_block} > {a.max_over_block}", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
