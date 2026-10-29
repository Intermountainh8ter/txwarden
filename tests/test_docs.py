"""Documentation is code here: generated blocks, links, diagrams, examples and claims are checked."""
from __future__ import annotations

import importlib.util
import io
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from txwarden import __version__
from txwarden.abi import SELECTORS
from txwarden.cli import main
from txwarden.risk import RULES

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted([ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "CHANGELOG.md",
               *(ROOT / "docs").rglob("*.md")])


def run_script(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True,
                          timeout=300)


def cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return main(list(argv), out), out.getvalue()


# --------------------------------------------------------------------------- generated content

def test_rules_reference_is_current():
    r = run_script("scripts/gen_rules_doc.py", "--check")
    assert r.returncode == 0, r.stderr


def test_generated_readme_flowchart_and_launch_blocks_are_current():
    """README tables, CLI output, flowchart sources and launch facts come from real runs."""
    r = run_script("scripts/update_readme.py", "--check")
    assert r.returncode == 0, r.stderr + "\n(run `make docs` and commit)"


def test_every_markdown_file_with_markers_has_matched_begin_and_end():
    for p in DOCS:
        text = p.read_text()
        begins = re.findall(r"<!-- BEGIN ([\w-]+) -->", text)
        ends = re.findall(r"<!-- END ([\w-]+) -->", text)
        assert begins == ends, p


# --------------------------------------------------------------------------- links and claims

@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(path):
    text = re.sub(r"```.*?```", "", path.read_text(), flags=re.S)
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if re.match(r"[a-z]+:", target) or target.startswith("#"):
            continue
        file = target.split("#")[0]
        assert (path.parent / file).resolve().exists(), f"{path.name}: broken link {target}"


def test_rule_count_claims_match_the_registry():
    for p in DOCS:
        for n in re.findall(r"(?<!\()\b(\d+) rules\b", p.read_text()):  # "(26 rules)" is a per-severity count
            assert int(n) == len(RULES), f"{p.name} says {n} rules, registry has {len(RULES)}"


def test_selector_count_claims_are_close_to_the_registry():
    for p in DOCS:
        for n in re.findall(r"\babout (\d+) selectors\b", p.read_text()):
            assert abs(int(n) - len(SELECTORS)) <= 5, p.name
    assert f"{len(SELECTORS)} selectors" in (ROOT / "CHANGELOG.md").read_text()


def test_changelog_numbers_and_versions_agree_with_the_code():
    log = (ROOT / "CHANGELOG.md").read_text()
    cases = [line for line in (ROOT / "evals" / "cases.jsonl").read_text().splitlines() if line]
    categories = len({__import__("json").loads(line)["category"] for line in cases})
    assert f"{len(cases)} synthetic labelled cases in {categories} categories" in log
    assert f"**{len(RULES)} rules**" in log
    top = re.search(r"^## \[(\d+\.\d+\.\d+)\]", log, re.M).group(1)
    pyproject = (ROOT / "pyproject.toml").read_text()  # regex, not tomllib: this runs on 3.10 too
    assert top == __version__ == re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    assert re.search(r'authors = \[\{ name = "Ammon Jackson" \}\]', pyproject)
    assert re.search(r'license = \{ text = "MIT" \}', pyproject)
    assert "Ammon Jackson" in (ROOT / "LICENSE").read_text()


def test_threshold_prose_in_the_readme_matches_the_sweeps():
    """README says the best single-knob changes on dev are slippage_block 0.03 and impact_warn_bps
    300 and that both also improve held-out accuracy. Recompute, so the prose cannot rot."""
    spec = importlib.util.spec_from_file_location("_re", ROOT / "evals" / "run_evals.py")
    run = importlib.util.module_from_spec(spec)
    sys.modules["_re"] = run
    spec.loader.exec_module(run)
    full = run.prepare(run.load_cases(ROOT / "evals" / "cases.jsonl"))
    dev = [p for p in full if p.case["split"] == "dev"]
    held = [p for p in full if p.case["split"] == "heldout"]
    for title, best_label in (("slippage_block (default 0.05)", "0.03"),
                              ("impact_warn_bps (default 500)", "300")):
        default_label, variants = run.SWEEPS[title]
        scored = [(label, run.evaluate(dev, ov), run.evaluate(held, ov)) for label, ov in variants]
        best = max(scored, key=lambda r: (r[1].accuracy, -r[1].unsafe_allow))
        default = next(r for r in scored if r[0] == default_label)
        assert best[0] == best_label, (title, best[0])
        assert best[2].accuracy > default[2].accuracy, title
    text = (ROOT / "README.md").read_text()
    assert "`slippage_block` 0.05 to 0.03" in text and "`impact_warn_bps` 500 to 300" in text
    # "scaling all six swap thresholds by 0.75 ... gains little on heldout and doubles its over-BLOCKs"
    default_label, variants = run.SWEEPS["swap thresholds x k (all six scaled together; k>1 is looser)"]
    by_label = {label: (run.evaluate(dev, ov), run.evaluate(held, ov)) for label, ov in variants}
    (_, base_held), (k_dev, k_held) = by_label["k=1"], by_label["k=0.75"]
    assert k_dev.accuracy > by_label["k=1"][0].accuracy
    assert k_held.accuracy - base_held.accuracy < 0.005
    assert k_held.over_block == 2 * base_held.over_block


def test_no_model_identifiers_in_the_tree_except_the_configurable_default():
    allowed = ROOT / "src" / "txwarden" / "llm.py"
    pattern = re.compile(r"claude|sonnet|opus|haiku|gpt-?\d|gemini|llama|openai", re.I)
    skip = {".git", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache"}
    for p in ROOT.rglob("*"):
        if (set(p.relative_to(ROOT).parts) & skip or not p.is_file() or p.suffix in
                {".svg", ".png", ".pyc"} or p.name.endswith(".egg-info") or p == Path(__file__)
                or "egg-info" in str(p) or p.name == "coverage.json" or p.name == ".coverage"):
            continue
        try:
            text = p.read_text()
        except UnicodeDecodeError:
            continue
        if p == allowed:
            hits = [line for line in text.splitlines() if pattern.search(line)]
            assert len(hits) == 1 and "TXWARDEN_MODEL" in hits[0], "one configurable default only"
        else:
            assert not pattern.search(text), f"model identifier in {p.relative_to(ROOT)}"


# --------------------------------------------------------------------------- real-chain status

def test_readme_real_chain_status_follows_what_is_committed_under_results():
    from txwarden.replay_report import committed_real_results

    text = (ROOT / "README.md").read_text()
    assert "## Real-chain replay" in text
    committed = committed_real_results(ROOT / "results")
    assert ("Real-chain results: NOT YET RUN" in text) == (not committed)


LIVE = ROOT / "docs" / "LIVE_REPLAY.md"


def test_live_replay_status_block_matches_the_results_directory():
    from txwarden.replay_report import committed_real_results

    text = LIVE.read_text()
    assert ("Real-chain results: NOT YET RUN" in text) == (not committed_real_results(ROOT / "results"))


def test_live_replay_walkthrough_covers_what_the_author_needs():
    text = " ".join(LIVE.read_text().split())
    for needle in (
            "TXWARDEN_LIVE_RPC", "read -rs", "--rpc-env", "archive state", "128 blocks",
            "debug_traceCall", "allow-listed", "--estimate", "--budget-calls", "--budget-units",
            "--validate-only", "ZeroMEV", "EigenPhi", "mev-inspect", "None of these was checked",
            "no hashes are supplied", "intra-block ordering effects are not reproduced",
            "Label noise", "Selection bias", "Few cases", "must be verified in the provider "
            "console", "2 for `debug_*`/`trace_*`", "N-1", "--allow-mock", "--allow-small",
            "SMALL SAMPLE", "MOCK", "make docs", "results/"):
        assert needle in text, needle
    assert "never in a file" in text.lower() or "Do not write it into a file" in text


def test_live_replay_documents_every_option_and_reason_code():
    from txwarden.cli import build_parser
    from txwarden.replay import REASON_CODES

    text = LIVE.read_text()
    subs = next(a for a in build_parser()._actions if a.dest == "cmd").choices
    for name in ("replay", "replay-report"):
        for action in subs[name]._actions:
            for opt in action.option_strings:
                assert opt in ("-h", "--help") or f"`{opt}`" in text, f"{name} {opt} undocumented"
    for code in REASON_CODES:
        assert f"`{code}`" in text


def test_the_documented_example_cases_load_and_are_obviously_fake():
    from txwarden.replay import parse_cases

    block = re.search(r"```csv\n(.*?)```", LIVE.read_text(), re.S).group(1)
    cases = parse_cases(block, "example.csv")
    assert cases.counts == {"sandwiched": 1, "ordinary": 1}
    assert {c.source for c in cases.cases} == {"EXAMPLE"}
    assert all(set(c.tx_hash[2:-1]) == {"0"} for c in cases.cases)


def test_replay_commands_in_the_docs_parse_with_the_real_parser():
    import shlex

    from txwarden.cli import build_parser

    parser = build_parser()
    seen = 0
    for path in (ROOT / "README.md", LIVE):
        for block in re.findall(r"```(?:bash|sh)\n(.*?)```", path.read_text(), re.S):
            for line in block.splitlines():
                if not re.match(r"txwarden replay(-report)?\b", line):
                    continue
                argv = shlex.split(line, comments=True)[1:]
                parser.parse_args(argv)  # raises SystemExit on a flag that does not exist
                assert not any("://" in a for a in argv)
                seen += 1
    assert seen >= 6


def test_docs_never_show_a_url_with_a_key_or_an_rpc_flag_for_replay():
    for path in DOCS:
        text = path.read_text()
        assert not re.search(r"txwarden replay[^\n]*--rpc(?!-env)", text), path.name
        assert not re.search(r"https?://[^\s)`\"']*(?:/v\d/|apikey=|api_key=)[A-Za-z0-9_-]{16,}", text), \
            path.name


def test_no_mock_results_are_committed():
    results = ROOT / "results"
    if results.exists():
        assert not [p for p in results.rglob("*") if "MOCK" in p.name], "MOCK output must not ship"


# --------------------------------------------------------------------------- README snippets

def test_readme_python_example_runs_and_blocks():
    text = (ROOT / "README.md").read_text()
    block = re.search(r"```python\n(.*?)```", text, re.S).group(1)
    ns: dict = {}
    exec(compile(block, "README.md", "exec"), ns)
    assert ns["verdict"].value == "BLOCK"
    assert "UNLIMITED_APPROVAL_UNKNOWN" in [f.rule for f in ns["findings"]]


def test_readme_toml_example_loads():
    text = (ROOT / "README.md").read_text()
    block = re.search(r"```toml\n(.*?)```", text, re.S).group(1)
    from txwarden.config import config_from_dict, parse_toml, parse_toml_subset

    assert parse_toml(block) == parse_toml_subset(block)
    cfg = config_from_dict(parse_toml(block))
    assert cfg.policy.slippage_block == 0.05 and cfg.policy.expected_chain_id == 1


def test_readme_commands_exist_and_have_help():
    from txwarden.cli import SUBCOMMANDS, build_parser

    text = (ROOT / "README.md").read_text()
    mentioned = set(re.findall(r"^txwarden (\w+)", text, re.M))
    assert {"review", "decode", "rules", "explain", "label", "mcp"} <= mentioned
    assert mentioned <= set(SUBCOMMANDS)
    parser = build_parser()
    for sub in SUBCOMMANDS:
        with pytest.raises(SystemExit) as e:
            parser.parse_args([sub, "--help"])
        assert e.value.code == 0


# --------------------------------------------------------------------------- examples

@pytest.mark.parametrize("args,code,needle", [
    (["review", "examples/approve_unlimited.json", "--no-llm"], 2, "UNLIMITED_APPROVAL_UNKNOWN"),
    (["review", "examples/approve_router.json", "--no-llm"], 2, "labelled 'Uniswap V2 Router02'"),
    (["review", "examples/approve_router.json", "--no-llm", "--trust-well-known"], 0, "ALLOW"),
    (["review", "examples/approve_router.json", "--no-llm", "--config", "examples/txwarden.toml"],
     0, "ALLOW"),
    (["review", "examples/swap_usdc_to_weth.json", "--no-llm"], 2, "ANALYSIS_INCOMPLETE"),
    (["review", "examples/set_approval_for_all.json", "--no-llm"], 2, "OPERATOR_APPROVAL_UNKNOWN"),
    (["batch", "examples/bundle_approve_then_pull.json"], 2, "BUNDLE_APPROVE_THEN_PULL"),
])
def test_shipped_examples_behave_as_documented(args, code, needle, monkeypatch):
    monkeypatch.chdir(ROOT)
    got, out = cli(*args)
    assert got == code and needle in out, out


def test_example_config_is_valid_and_trusts_what_it_says():
    from txwarden.config import load_config

    cfg = load_config(ROOT / "examples" / "txwarden.toml")
    assert cfg.policy.expected_chain_id == 1 and len(cfg.policy.trusted_spenders) == 1


# --------------------------------------------------------------------------- diagrams

@pytest.mark.parametrize("name", ["usage", "troubleshooting"])
def test_svgs_are_portable_and_match_their_mermaid_sources(name):
    mmd = (ROOT / "docs" / "diagrams" / f"{name}.mmd").read_text()
    svg_text = (ROOT / "docs" / "diagrams" / f"{name}.svg").read_text()
    ET.fromstring(svg_text)  # well-formed XML
    assert "foreignObject" not in svg_text, "labels must be SVG text so every viewer shows them"
    root = ET.fromstring(svg_text)
    shown = "".join("".join(el.itertext()) for el in root.iter() if el.tag.endswith(("text", "tspan")))
    # <style> content is not label text; labels may wrap across tspans, so compare compact strings
    compact = re.sub(r"[^A-Za-z0-9]", "", shown)
    labels = re.findall(r'\["(.*?)"\]|\{"(.*?)"\}|\{\{"(.*?)"\}\}|-- "(.*?)" -->', mmd)
    parts = [re.sub(r"[^A-Za-z0-9]", "", seg) for group in labels for part in group if part
             for seg in [part.replace("<br/>", "")]]
    assert parts
    missing = [p for p in parts if p and p not in compact]
    assert not missing, missing[:5]


def test_both_diagrams_are_embedded_in_the_readme_and_flowcharts_doc():
    readme = (ROOT / "README.md").read_text()
    flow = (ROOT / "docs" / "FLOWCHARTS.md").read_text()
    for name in ("usage", "troubleshooting"):
        assert f"docs/diagrams/{name}.svg" in readme
        assert f"diagrams/{name}.svg" in flow
        assert (ROOT / "docs" / "diagrams" / f"{name}.mmd").read_text().strip() in flow
    assert flow.count("```mermaid") == 2


def test_troubleshooting_symptoms_are_real_messages():
    """Every quoted symptom in the troubleshooting chart is something the code can print."""
    src = "".join(p.read_text() for p in (ROOT / "src" / "txwarden").glob("*.py"))
    chart = (ROOT / "docs" / "diagrams" / "troubleshooting.mmd").read_text()
    for fragment in ("no fixture for calldata", "SIMULATION_UNAVAILABLE", "cannot reach",
                     "did not return JSON", "no recorded response", "ANALYSIS_INCOMPLETE",
                     "language model unavailable", "ANTHROPIC_API_KEY is not set",
                     "is not installed", "unknown policy keys", "names unknown rules",
                     "cannot be disabled", "cannot load config", "unknown keys",
                     "missing trie node", "header not found"):
        assert fragment in src, f"{fragment!r} is not a message in the code"
    for fragment in ("no fixture for calldata", "SIMULATION_UNAVAILABLE", "ANTHROPIC_API_KEY",
                     "unknown policy keys", "cannot load config"):
        assert fragment in chart


# --------------------------------------------------------------------------- build files

def test_ci_matrix_and_gates_match_the_makefile_and_claims():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    for v in ("3.10", "3.11", "3.12", "3.13"):
        assert f'"{v}"' in ci
    for cmd in ("ruff check .", "pytest -q --cov", "evals/build_cases.py --check",
                "evals/injection_eval.py", "scripts/gen_rules_doc.py --check",
                "scripts/update_readme.py --check", "--min-accuracy", "--max-unsafe-allow",
                "docker build"):
        assert cmd in ci, cmd
    makefile = (ROOT / "Makefile").read_text()
    contributing = (ROOT / "CONTRIBUTING.md").read_text()
    for target in re.findall(r"`make ([\w-]+)`", contributing):
        assert re.search(rf"^{target}:", makefile, re.M), f"make {target} is documented but missing"
    gates = re.findall(r"--min-accuracy ([\d.]+)", ci)
    assert gates and all(float(g) < 0.977 for g in gates), "gates must sit below the measured value"


def test_pyproject_pins_lint_rules_and_coverage_floor():
    text = (ROOT / "pyproject.toml").read_text()
    assert re.search(r"^\[tool\.ruff\.lint\]\n(?:#.*\n)?select = \[", text, re.M)
    assert int(re.search(r"^fail_under = (\d+)", text, re.M).group(1)) >= 90
    assert 'dev = ["pytest' in text and "pytest-cov" in text
    assert re.search(r"^dependencies = \[\]$", text, re.M)  # zero runtime dependencies by rule
