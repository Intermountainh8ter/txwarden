#!/usr/bin/env python3
"""Fill the generated blocks of README.md with numbers from real runs.

    python scripts/update_readme.py            # rewrite README.md in place
    python scripts/update_readme.py --check    # exit 1 if any generated block is stale (CI)

Blocks look like ``<!-- BEGIN name -->`` ... ``<!-- END name -->``. Everything between the markers
is replaced; nothing outside them is touched, so prose can never silently carry a stale number
that these blocks would have corrected, and the numbers cannot be typed by hand.

    rules-table      the rule table, from the registry
    rule-counts      one sentence with the rule counts
    eval-table       tables from ``evals/run_evals.py --markdown`` on evals/cases.jsonl
    legacy-eval      the original 122-case set
    sweeps           threshold sweeps (dev vs held-out)
    injection-table  ``evals/injection_eval.py --markdown``
    cli-example      real output of `txwarden review examples/approve_unlimited.json --no-llm`
    cli-bundle       real output of `txwarden batch examples/bundle_approve_then_pull.json`
    test-count       number of collected tests (pytest --collect-only)
    coverage         from coverage.json if present (pytest --cov --cov-report=json)
"""
from __future__ import annotations

import importlib.util
import io
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
sys.path.insert(0, str(ROOT / "src"))

from txwarden.ruledocs import markdown_summary_table  # noqa: E402
from txwarden.rules import RULES  # noqa: E402


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"_{name}", ROOT / "evals" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def eval_table() -> str:
    run = load("run_evals")
    cases = run.load_cases(ROOT / "evals" / "cases.jsonl")
    full = run.prepare(cases)
    dev = [p for p in full if p.case["split"] == "dev"]
    held = [p for p in full if p.case["split"] == "heldout"]
    return run.markdown(run.evaluate(full), run.evaluate(dev), run.evaluate(held),
                        len({c["category"] for c in cases}))


def legacy_eval() -> str:
    run = load("run_evals")
    cases = run.load_cases(ROOT / "evals" / "cases_v1.jsonl")
    r = run.evaluate(run.prepare(cases))
    p, rc = r.block_pr()
    return (f"`evals/cases_v1.jsonl` ({r.n} cases, 16 categories): accuracy **{r.accuracy:.3f}**, "
            f"BLOCK precision {p:.3f}, BLOCK recall {rc:.3f}, unsafe ALLOW {r.unsafe_allow}.")


def sweeps() -> str:
    run = load("run_evals")
    cases = run.load_cases(ROOT / "evals" / "cases.jsonl")
    full = run.prepare(cases)
    dev = [p for p in full if p.case["split"] == "dev"]
    held = [p for p in full if p.case["split"] == "heldout"]
    out = io.StringIO()
    for name in ("swap thresholds", "slippage_block", "impact_warn_bps", "sandwich_warn_bps"):
        run.run_sweeps(dev, held, name, out)
    return "```text\n" + out.getvalue().strip("\n") + "\n```"


def injection_table() -> str:
    inj = load("injection_eval")
    total, by_vector, by_attack, violations = inj.run_all()
    if violations:
        raise SystemExit(f"injection invariant broken in {len(violations)} runs; not updating README")
    return inj.markdown(total, by_vector, by_attack)


def cli_output(*argv: str) -> str:
    import contextlib

    from txwarden.cli import main as cli_main

    buf, cwd = io.StringIO(), Path.cwd()
    err = io.StringIO()
    try:
        import os

        os.chdir(ROOT)
        with contextlib.redirect_stderr(err):
            code = cli_main(list(argv), buf)
    finally:
        os.chdir(cwd)
    shown = " ".join(argv)
    return f"```text\n$ txwarden {shown}\n{buf.getvalue().rstrip()}\n(exit code {code})\n```"


def cli_example() -> str:
    return cli_output("review", "examples/approve_unlimited.json", "--no-llm")


def cli_bundle() -> str:
    return cli_output("batch", "examples/bundle_approve_then_pull.json")


def rule_counts() -> str:
    c = {v: sum(1 for r in RULES.values() if r.verdict.value == v) for v in ("BLOCK", "WARN", "ALLOW")}
    return (f"**{len(RULES)} rules**: {c['BLOCK']} CRITICAL (BLOCK), {c['WARN']} HIGH (WARN), "
            f"{c['ALLOW']} MEDIUM/INFO (reported, never stopping).")


def test_count() -> str:
    r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p",
                        "no:cacheprovider", "--no-cov"], cwd=ROOT, capture_output=True, text=True)
    m = re.search(r"(\d+) tests? collected", r.stdout) or re.search(r"(\d+) tests?", r.stdout)
    if not m:
        raise SystemExit("could not count tests:\n" + r.stdout[-500:] + r.stderr[-500:])
    total = int(m.group(1))
    live = len(re.findall(r"tests/test_live\.py::", r.stdout))
    return (f"**{total - live} tests** run by default, plus {live} opt-in live-RPC tests that are "
            "skipped unless `TXWARDEN_LIVE_RPC` is set.")


def coverage() -> str | None:
    path = ROOT / "coverage.json"
    if not path.exists():
        return None
    d = json.loads(path.read_text())
    files = d["files"]
    lines = sum(f["summary"]["num_statements"] for f in files.values())
    hit = sum(f["summary"]["covered_lines"] for f in files.values())
    per = {Path(k).name: 100 * f["summary"]["covered_lines"] / f["summary"]["num_statements"]
           for k, f in files.items() if f["summary"]["num_statements"]}
    worst = min(per, key=per.get)
    return (f"Line coverage of `src/txwarden`: **{100 * hit / lines:.1f}%** ({hit}/{lines} "
            f"statements); with branches **{d['totals']['percent_covered']:.1f}%**. Lowest module: "
            f"`{worst}` at {per[worst]:.1f}%. CI fails below 90%.")


BLOCKS = {"rules-table": markdown_summary_table, "rule-counts": rule_counts,
          "cli-example": cli_example, "cli-bundle": cli_bundle,
          "eval-table": eval_table, "legacy-eval": legacy_eval, "sweeps": sweeps,
          "injection-table": injection_table, "test-count": test_count, "coverage": coverage}
# the coverage block needs a prior `pytest --cov --cov-report=json`; it is not checked in --check
CHECK_SKIP = {"coverage"}


def render(text: str, only_check: bool) -> tuple[str, list[str]]:
    changed: list[str] = []
    for name, fn in BLOCKS.items():
        if only_check and name in CHECK_SKIP:
            continue
        pat = re.compile(rf"(<!-- BEGIN {name} -->\n)(.*?)(\n<!-- END {name} -->)", re.S)
        if not pat.search(text):
            raise SystemExit(f"README.md has no '{name}' block")
        body = fn()
        if body is None:  # nothing to say yet: keep what is there
            continue
        new = pat.sub(lambda m, body=body: m.group(1) + body + m.group(3), text)
        if new != text:
            changed.append(name)
        text = new
    return text, changed


def main() -> int:
    check = "--check" in sys.argv[1:]
    text = README.read_text()
    new, changed = render(text, only_check=check)
    if check:
        if changed:
            print("README.md generated blocks are stale: " + ", ".join(changed)
                  + "\nrun `python scripts/update_readme.py`", file=sys.stderr)
            return 1
        return 0
    README.write_text(new)
    print("updated blocks:", ", ".join(changed) or "(none, already current)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
