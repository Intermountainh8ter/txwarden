#!/usr/bin/env python3
"""Fill the generated blocks of README.md and docs/FLOWCHARTS.md from real runs and sources.

    python scripts/update_readme.py            # rewrite README.md in place
    python scripts/update_readme.py --check    # exit 1 if any generated block is stale (CI)

Blocks look like ``<!-- BEGIN name -->`` ... ``<!-- END name -->``. Everything between the markers
is replaced; nothing outside them is touched, so prose can never silently carry a stale number
that these blocks would have corrected, and the numbers cannot be typed by hand.

    rules-table      the rule table, from the registry
    rule-counts      one sentence with the rule counts
    eval-table       tables from ``evals/run_evals.py --markdown`` on evals/cases.jsonl
    legacy-eval      the original 122-case set
    strict-eval      scores outside the deliberately ambiguous gray_area group
    sweeps           threshold sweeps (dev vs held-out)
    injection-table  ``evals/injection_eval.py --markdown``
    cli-example      real output of `txwarden review examples/approve_unlimited.json --no-llm`
    cli-bundle       real output of `txwarden batch examples/bundle_approve_then_pull.json`
    facts            (docs/launch/*.md) the numbers that copy may quote
    test-count       number of collected tests (pytest --collect-only)
    coverage         from coverage.json if present (pytest --cov --cov-report=json)
    replay-status    "Real-chain results: NOT YET RUN" until a non-MOCK file is under results/,
                     then the numbers `txwarden replay-report` computes from it (README and
                     docs/LIVE_REPLAY.md)
    replay-reasons   (docs/LIVE_REPLAY.md) the reason codes of `txwarden replay`, from the runner
    replay-options   (docs/LIVE_REPLAY.md) every `txwarden replay` option, from the parser
    replay-report-options  the same for `txwarden replay-report`
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

from txwarden.cli import build_parser  # noqa: E402
from txwarden.replay import REASON_CODES  # noqa: E402
from txwarden.replay_report import status_markdown  # noqa: E402
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


def strict_eval() -> str:
    run = load("run_evals")
    cases = run.load_cases(ROOT / "evals" / "cases.jsonl")
    r_all = run.evaluate(run.prepare(cases))
    strict = run.evaluate(run.prepare([c for c in cases if c["group"] != "gray_area"]))
    return (f"All {r_all.unsafe_allow} unsafe ALLOWs and {r_all.over_block} over-BLOCKs fall in the "
            f"`gray_area` group; outside it ({strict.n} cases) there are {strict.unsafe_allow} "
            f"unsafe ALLOWs and {strict.over_block} over-BLOCKs, accuracy {strict.accuracy:.3f}.")


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


def facts() -> str:
    run, inj = load("run_evals"), load("injection_eval")
    cases = run.load_cases(ROOT / "evals" / "cases.jsonl")
    full = run.prepare(cases)
    dev = [p for p in full if p.case["split"] == "dev"]
    held = [p for p in full if p.case["split"] == "heldout"]
    r_all, r_dev, r_held = run.evaluate(full), run.evaluate(dev), run.evaluate(held)
    strict = run.evaluate(run.prepare([c for c in cases if c["group"] != "gray_area"]))
    legacy = run.evaluate(run.prepare(run.load_cases(ROOT / "evals" / "cases_v1.jsonl")))
    total, _, _, violations = inj.run_all()
    c = {v: sum(1 for r in RULES.values() if r.verdict.value == v) for v in ("BLOCK", "WARN", "ALLOW")}
    p_, rc = r_all.block_pr()
    missed = ", ".join(f"`{k}`" for k, oks in sorted(r_all.per_cat.items()) if not all(oks)) or "none"
    return "\n".join([
        "**Numbers you can quote** (generated by `scripts/update_readme.py` from real runs):",
        "",
        f"- Rules: {len(RULES)} ({c['BLOCK']} CRITICAL/BLOCK, {c['WARN']} HIGH/WARN, "
        f"{c['ALLOW']} report-only).",
        f"- {test_count().replace('**', '')}",
        f"- Synthetic labelled evals: {r_all.n} cases in {len({x['category'] for x in cases})} "
        f"categories; accuracy {r_all.accuracy:.3f} (dev {r_dev.accuracy:.3f}, held-out "
        f"{r_held.accuracy:.3f}); BLOCK precision {p_:.3f}, recall {rc:.3f}.",
        f"- Disagreements with the labels: {r_all.unsafe_allow} unsafe ALLOW and {r_all.over_block} "
        f"over-BLOCK, of which {strict.unsafe_allow} and {strict.over_block} outside the "
        f"deliberately ambiguous `gray_area` group. Categories with any miss: {missed}.",
        f"- The original 122-case set still scores {legacy.accuracy:.3f}.",
        f"- Prompt-injection eval (a scripted model that obeys every injected instruction): "
        f"{total.runs} runs, verdict weaker than the engine's in {total.weaker}, changed after "
        f"`assess_risk` in {total.unequal_after_assess}; {total.stricter_failclosed} runs ended in "
        "a fail-closed BLOCK. No real language model was run.",
        "- Not verified: any run against a real Ethereum node, real-world detection rates.",
    ]) + ("" if not violations else "\nWARNING: injection invariant broken")


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


def replay_status() -> str:
    return status_markdown(ROOT / "results")


def options_table(command: str) -> str:
    """Every option of a sub-command, read from the argparse definition (so it cannot drift)."""
    parser = next(a for a in build_parser()._actions if a.dest == "cmd").choices[command]
    rows = ["| Option | Argument | Default | Meaning |", "|---|---|---|---|"]
    for a in parser._actions:
        if a.option_strings == ["-h", "--help"]:
            continue
        name = ", ".join(f"`{o}`" for o in a.option_strings) if a.option_strings \
            else f"`{a.dest}` (positional)"
        if a.choices:
            arg = "{" + "\\|".join(a.choices) + "}"
        elif a.option_strings and a.nargs != 0:
            arg = a.metavar or a.dest.upper()
        else:
            arg = ""
        shown = "" if a.default is None or a.default is False or not a.option_strings \
            else f"`{a.default}`"
        text = re.sub(r"\s*\(default: %\(default\)s\)", "", a.help or "")  # it has its own column
        text = text.replace("%(default)s", str(a.default)).replace("|", "\\|")
        rows.append(f"| {name} | {f'`{arg}`' if arg else ''} | {shown} | {text} |")
    return "\n".join(rows)


def replay_reasons() -> str:
    rows = ["| Code | Status | Meaning |", "|---|---|---|"]
    rows.extend(f"| `{code}` | {status} | {text} |" for code, (status, text) in REASON_CODES.items())
    return "\n".join(rows)


def mermaid(name: str):
    def fn() -> str:
        return "```mermaid\n" + (ROOT / "docs" / "diagrams" / f"{name}.mmd").read_text().rstrip() + "\n```"
    return fn


FLOWCHART_BLOCKS = {"usage-mmd": mermaid("usage"), "troubleshooting-mmd": mermaid("troubleshooting")}
LIVE_REPLAY_BLOCKS = {"replay-status": replay_status, "replay-reasons": replay_reasons,
                      "replay-options": lambda: options_table("replay"),
                      "replay-report-options": lambda: options_table("replay-report")}
BLOCKS = {"rules-table": markdown_summary_table, "rule-counts": rule_counts,
          "cli-example": cli_example, "cli-bundle": cli_bundle,
          "eval-table": eval_table, "legacy-eval": legacy_eval, "strict-eval": strict_eval,
          "sweeps": sweeps,
          "injection-table": injection_table, "test-count": test_count, "coverage": coverage,
          "replay-status": replay_status}
# the coverage block needs a prior `pytest --cov --cov-report=json`; it is not checked in --check
CHECK_SKIP = {"coverage"}


def render(text: str, blocks: dict, only_check: bool) -> tuple[str, list[str]]:
    changed: list[str] = []
    for name, fn in blocks.items():
        if only_check and name in CHECK_SKIP:
            continue
        pat = re.compile(rf"(<!-- BEGIN {name} -->\n)(.*?)(<!-- END {name} -->)", re.S)
        if not pat.search(text):
            raise SystemExit(f"missing '{name}' block")
        body = fn()
        if body is None:  # nothing to say yet: keep what is there
            continue
        new = pat.sub(lambda m, body=body: m.group(1) + body + "\n" + m.group(3), text)
        if new != text:
            changed.append(name)
        text = new
    return text, changed


LAUNCH = sorted((ROOT / "docs" / "launch").glob("*.md"))
TARGETS = ((README, BLOCKS), (ROOT / "docs" / "FLOWCHARTS.md", FLOWCHART_BLOCKS),
           (ROOT / "docs" / "LIVE_REPLAY.md", LIVE_REPLAY_BLOCKS),
           *((p, {"facts": facts}) for p in LAUNCH))


def main() -> int:
    check = "--check" in sys.argv[1:]
    stale: list[str] = []
    for path, blocks in TARGETS:
        text = path.read_text()
        new, changed = render(text, blocks, only_check=check)
        if check:
            stale += [f"{path.name}:{c}" for c in changed]
        else:
            path.write_text(new)
            print(f"{path.name}: updated blocks:", ", ".join(changed) or "(none, already current)")
    if check and stale:
        print("generated blocks are stale: " + ", ".join(stale)
              + "\nrun `python scripts/update_readme.py`", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
