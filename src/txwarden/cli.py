"""Command-line interface.

    txwarden review tx.json [--intent ...] [--rpc URL | --fixture sim.json] [--no-llm] [--json]
    txwarden batch bundle.json [--rpc URL] [--json]
    txwarden decode 0x095ea7b3...
    txwarden explain UNLIMITED_APPROVAL_UNKNOWN
    txwarden rules
    txwarden label 0x7a25...
    txwarden mcp [--rpc URL]
    txwarden replay CASES.csv [--out RESULTS.jsonl] [--rpc-env NAME] [--budget-calls N] ...
    txwarden replay-report RESULTS.jsonl

``txwarden tx.json ...`` (no sub-command) is accepted as ``review`` for backward compatibility.
Exit codes: 0 ALLOW, 2 WARN/BLOCK, 3 usage or input error. ``replay`` exits 0 when it finished
(or hit ``--limit``), 4 when it stopped early (budget, repeated RPC failures, interrupt).
``replay`` never takes an RPC URL on the command line: the endpoint comes from an environment
variable because it carries an API key.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .abi import decode_call, describe
from .agent import TxWardenAgent
from .batch import assess_bundle
from .config import AppConfig, ConfigError, load_config
from .models import Finding, SimResult, Tx, Verdict
from .redact import Redactor, redact_url
from .replay import (
    ReplayConfig,
    Replayer,
    ReplayError,
    endpoint_from_env,
    format_estimate,
    load_cases,
    valid_env_name,
)
from .replay_report import ReportRefused, render_json, render_text, report_from_file
from .replay_rpc import CostModel
from .risk import RULES, PolicyConfig, assess
from .ruledocs import explain_dict, explain_text, rules_markdown, rules_table
from .simulator import (
    AnvilSimulator,
    FixtureSimulator,
    RecordingTransport,
    StaticSimulator,
    http_transport,
    replay_transport,
)

SUBCOMMANDS = ("review", "batch", "decode", "explain", "rules", "label", "mcp", "replay",
               "replay-report")


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", default=None, help="TOML config file")
    p.add_argument("--rpc", default=None, help="fork RPC URL (default: config or none)")
    p.add_argument("--trust-spender", action="append", default=[])
    p.add_argument("--trust-recipient", action="append", default=[])
    p.add_argument("--trust-operator", action="append", default=[])
    p.add_argument("--deny", action="append", default=[])
    p.add_argument("--trust-well-known", action="store_true",
                   help="trust routers/Permit2/marketplaces from the built-in address book")
    p.add_argument("--address-book", default=None, help="extra address book JSON")
    p.add_argument("--json", action="store_true", help="machine-readable output")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="txwarden",
                                description="Pre-signature transaction reviewer for Ethereum.")
    p.add_argument("--version", action="version", version=f"txwarden {__version__}")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("review", help="review one transaction")
    r.add_argument("tx_json", help="JSON file: {sender,to,data,value,chain_id}")
    r.add_argument("--intent", default="", help="what the user says they want to do")
    r.add_argument("--no-llm", action="store_true", help="deterministic findings only")
    r.add_argument("--fixture", default=None,
                   help="recorded SimResult JSON (offline review, no RPC)")
    r.add_argument("--record", default=None, metavar="PATH",
                   help="save the RPC session to PATH (with --rpc) so it can be replayed offline")
    r.add_argument("--replay", default=None, metavar="PATH",
                   help="review from an RPC session saved with --record (no network)")
    _common(r)

    b = sub.add_parser("batch", help="review a bundle of transactions together")
    b.add_argument("bundle_json", help='JSON: [tx, ...] or {"txs": [...], "sims": [...]}')
    _common(b)

    d = sub.add_parser("decode", help="decode calldata")
    d.add_argument("data")
    d.add_argument("--json", action="store_true")

    e = sub.add_parser("explain", help="explain a rule id")
    e.add_argument("rule")
    e.add_argument("--json", action="store_true")

    ru = sub.add_parser("rules", help="list all rules")
    ru.add_argument("--json", action="store_true")
    ru.add_argument("--markdown", action="store_true", help="the full rule reference (docs/RULES.md)")
    ru.add_argument("--category", default=None, help="only this category (e.g. approval, swap)")
    ru.add_argument("--verdict", default=None, choices=["ALLOW", "WARN", "BLOCK", "allow", "warn",
                                                        "block"], help="only rules with this verdict")

    la = sub.add_parser("label", help="look up an address label")
    la.add_argument("address")
    la.add_argument("--config", default=None)
    la.add_argument("--address-book", default=None)
    la.add_argument("--json", action="store_true")

    m = sub.add_parser("mcp", help="serve the MCP stdio server")
    m.add_argument("--config", default=None)
    m.add_argument("--rpc", default=None)

    _replay_parser(sub)

    rr = sub.add_parser(
        "replay-report", allow_abbrev=False,
        help="headline detection / false-positive numbers from a replay results file",
        description="Compute detection rate (sandwiched cases) and false-positive rate (ordinary "
                    "cases) with Wilson 95% intervals from a results file written by `txwarden "
                    "replay`, and nothing else. Refuses MOCK results and fewer than 30 analysable "
                    "cases per label unless told otherwise; those outputs are stamped.")
    rr.add_argument("results", help="results JSONL written by `txwarden replay`")
    rr.add_argument("--allow-mock", action="store_true",
                    help="render results produced against the in-repo fake node (stamped MOCK)")
    rr.add_argument("--allow-small", action="store_true",
                    help="render with fewer than 30 analysable cases per label (stamped "
                         "SMALL SAMPLE)")
    rr.add_argument("--json", action="store_true", help="machine-readable output")
    rr.add_argument("--out", default=None, metavar="PATH",
                    help="write the report here instead of stdout (MOCK / SMALL SAMPLE are "
                         "added to the file name)")
    return p


def _env_name(value: str) -> str:
    if not valid_env_name(value):  # never echo the value: a mistyped --rpc URL ends up here
        raise argparse.ArgumentTypeError("must be an environment variable name")
    return value


def _replay_parser(sub: Any) -> None:
    r = sub.add_parser(
        "replay", allow_abbrev=False,
        help="replay labelled historical swaps against a node (endpoint from an env var)",
        description="Replay labelled historical swaps (sandwiched / ordinary) through the normal "
                    "simulate-and-assess pipeline, each pinned to the block before the one that "
                    "mined it. The RPC URL is read from an environment variable and is never "
                    "accepted as an argument or printed.")
    r.add_argument("cases", help="CSV or JSONL file with columns tx_hash, label "
                                 "(sandwiched|ordinary), optional source, notes")
    r.add_argument("--format", choices=["csv", "jsonl"], default=None,
                   help="case file format (default: from the file suffix or content)")
    r.add_argument("--out", default="replay_results.jsonl", metavar="PATH",
                   help="results JSONL; appended to and resumed (default: %(default)s)")
    r.add_argument("--rpc-env", default="TXWARDEN_LIVE_RPC", type=_env_name, metavar="NAME",
                   help="environment variable holding the endpoint URL (default: %(default)s)")
    r.add_argument("--config", default=None,
                   help="TOML policy/simulator settings (its rpc_url is ignored)")
    r.add_argument("--cache-dir", default=".txwarden-replay-cache", metavar="DIR",
                   help="on-disk response cache (default: %(default)s)")
    r.add_argument("--no-cache", action="store_true", help="do not read or write the cache")
    r.add_argument("--limit", type=int, default=None, metavar="N",
                   help="analyse at most N not-yet-done cases in this run")
    r.add_argument("--rps", type=float, default=10.0, metavar="R",
                   help="requests per second ceiling (default: %(default)s)")
    r.add_argument("--budget-calls", type=int, default=None, metavar="N",
                   help="stop cleanly before sending more than N RPC requests in this run")
    r.add_argument("--budget-units", type=float, default=None, metavar="U",
                   help="stop cleanly before spending more than U billing units in this run")
    r.add_argument("--cost-per-call", type=float, default=1.0, metavar="U",
                   help="units per request (default: %(default)s)")
    r.add_argument("--cost-debug-trace", type=float, default=2.0, metavar="U",
                   help="units per debug_*/trace_* request (default: %(default)s)")
    r.add_argument("--cost-archive", type=float, default=2.0, metavar="U",
                   help="units per state read older than the archive window "
                        "(default: %(default)s)")
    r.add_argument("--cost-combine", choices=["sum", "max"], default="sum",
                   help="how a request that is both debug/trace and archive is priced "
                        "(default: %(default)s, the conservative choice)")
    r.add_argument("--archive-window", type=int, default=128, metavar="BLOCKS",
                   help="state older than head minus this needs archive access "
                        "(default: %(default)s)")
    r.add_argument("--max-retries", type=int, default=5, metavar="N",
                   help="retries per request on HTTP 429/5xx, with exponential backoff "
                        "(default: %(default)s)")
    r.add_argument("--max-consecutive-errors", type=int, default=10, metavar="N",
                   help="stop after N cases in a row fail on the RPC; 0 never stops "
                        "(default: %(default)s)")
    r.add_argument("--retry-errors", action="store_true",
                   help="redo cases the results file records as error")
    r.add_argument("--estimate", action="store_true",
                   help="run the first 3 cases, print measured requests and the projected total, "
                        "write no results")
    r.add_argument("--validate-only", action="store_true",
                   help="check the case file and print counts per label; no endpoint needed")
    r.add_argument("--mock", action="store_true",
                   help="stamp the results MOCK (done automatically for the in-repo fake node)")
    r.add_argument("--endpoint-label", default="rpc endpoint", metavar="TEXT",
                   help="how the results header names the endpoint (never the URL)")


def _normalise_argv(argv: list[str]) -> list[str]:
    """Insert ``review`` when the first argument is a file rather than a sub-command."""
    if argv and not argv[0].startswith("-") and argv[0] not in SUBCOMMANDS:
        return ["review", *argv]
    return argv


def _config(a: argparse.Namespace) -> AppConfig:
    cfg = load_config(a.config) if getattr(a, "config", None) else AppConfig()
    if getattr(a, "rpc", None):
        cfg.rpc_url = a.rpc
    if getattr(a, "trust_well_known", False):
        cfg.trust_well_known = True
    if getattr(a, "address_book", None):
        from .addressbook import AddressBook

        cfg.address_book = cfg.address_book.merge(AddressBook.load(a.address_book))
    pol = cfg.policy
    pol.trusted_spenders |= {s.lower() for s in getattr(a, "trust_spender", [])}
    pol.trusted_recipients |= {s.lower() for s in getattr(a, "trust_recipient", [])}
    pol.trusted_operators |= {s.lower() for s in getattr(a, "trust_operator", [])}
    pol.denylist |= {s.lower() for s in getattr(a, "deny", [])}
    return cfg


def _print_findings(verdict: Verdict, findings: list[Finding], out: Any) -> None:
    print(f"Verdict: {verdict.value}", file=out)
    for f in findings:
        print(f"  [{f.severity.name}] {f.rule}: {f.message}", file=out)
    if not findings:
        print("  (no findings)", file=out)


HINTS = {
    "SIMULATION_UNAVAILABLE": "the RPC could not be used: check --rpc / rpc_url is reachable "
                              "(`curl -s -X POST -H 'content-type: application/json' --data "
                              "'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\","
                              "\"params\":[]}' $RPC`) and not rate limited, then re-run",
    "ANALYSIS_INCOMPLETE": "pool state is missing: pass --rpc <fork url> (or set rpc_url in the "
                           "config) so price impact and sandwich exposure can be computed",
    "CHAIN_ID_MISMATCH": "the transaction's chain id differs from the expected/simulated chain: "
                         "point --rpc at the right network or fix chain_id in the tx JSON",
}


UNTRUSTED_RULES = {"APPROVAL_UNKNOWN_SPENDER", "UNLIMITED_APPROVAL_UNKNOWN",
                   "OPERATOR_APPROVAL_UNKNOWN", "PERMIT_UNKNOWN_SPENDER",
                   "PERMIT_UNLIMITED_UNKNOWN"}


def _print_hints(findings: list[Finding], out: Any, book: Any = None) -> None:
    for rule in dict.fromkeys(f.rule for f in findings):
        if rule in HINTS:
            print(f"Hint ({rule}): {HINTS[rule]}", file=out)
    if book is None:
        return
    for f in findings:  # a well-known address that is merely not trusted yet
        who = f.data.get("spender") or f.data.get("operator")
        label = book.get(who) if f.rule in UNTRUSTED_RULES and who else None
        if label:
            print(f"Hint ({f.rule}): {who} is '{label.name}' in the built-in address book but "
                  f"is not trusted; add it with --trust-spender {who} (or --trust-operator), or "
                  "pass --trust-well-known to trust routers, Permit2 and marketplaces", file=out)


def _exit_code(verdict: Verdict) -> int:
    return 0 if verdict == Verdict.ALLOW else 2


def cmd_review(a: argparse.Namespace, out: Any) -> int:
    cfg = _config(a)
    policy = cfg.effective_policy()
    tx = Tx.from_dict(json.loads(Path(a.tx_json).read_text()))
    warning = None
    recorder: RecordingTransport | None = None
    if a.fixture:
        raw = json.loads(Path(a.fixture).read_text())
        if not isinstance(raw, dict):
            raise ValueError(f"{a.fixture}: expected a SimResult object or {{calldata: SimResult}}")
        if "success" in raw:
            sim_data = raw  # a single recorded SimResult
        elif tx.data in raw:
            sim_data = raw[tx.data]  # a table keyed by calldata
        else:
            raise ValueError(f"no fixture for calldata {tx.data[:18]}... in {a.fixture} "
                             f"(keys: {', '.join(k[:18] for k in list(raw)[:5]) or 'none'}); "
                             "a fixture is a SimResult JSON with a `success` field, or a "
                             "{calldata: SimResult} table")
        sim = SimResult.from_dict(sim_data)
        simulator: Any = FixtureSimulator({tx.data: sim})
    elif a.replay:
        simulator = AnvilSimulator(transport=replay_transport(a.replay), options=cfg.simulator)
    elif cfg.rpc_url:
        transport = http_transport(cfg.rpc_url)
        if a.record:
            transport = recorder = RecordingTransport(transport)
        simulator = AnvilSimulator(transport=transport, options=cfg.simulator)
    else:
        simulator = StaticSimulator(cfg.address_book)
        warning = ("no RPC configured (--rpc/config): static decode only; swap, honeypot, trace "
                   "and account rules could not run")
    try:
        return _review(a, out, cfg, policy, tx, simulator, warning)
    finally:
        if recorder is not None:
            recorder.save(a.record, f"txwarden {__version__} session for {tx.to}")


def _review(a: argparse.Namespace, out: Any, cfg: AppConfig, policy: PolicyConfig, tx: Tx,
            simulator: Any, warning: str | None) -> int:
    has_backend = bool(cfg.rpc_url or a.fixture or a.replay)
    if a.no_llm or not has_backend:
        sim = simulator.simulate(tx)
        verdict, findings = assess(tx, sim, policy)
        if a.json:
            payload = {"verdict": verdict.value, "findings": [f.to_dict() for f in findings],
                       "call_kind": sim.call_kind, "decoded": sim.decoded}
            if warning:
                payload["warning"] = warning
            print(json.dumps(payload, indent=2, default=str), file=out)
        else:
            if sim.decoded:
                print(f"Call: {describe(decode_call(tx.data))}", file=out)
            _print_findings(verdict, findings, out)
            _print_hints(findings, out, cfg.address_book)
            if warning:
                print(f"Warning: {warning}", file=out)
        return _exit_code(verdict)

    from .llm import AnthropicLLM, LLMError

    try:
        llm = AnthropicLLM(model=cfg.model)
        review = TxWardenAgent(llm, simulator, policy, address_book=cfg.address_book).review(
            tx, a.intent)
    except LLMError as e:
        # the verdict never depended on the model: report it, and say why there is no explanation
        sim = simulator.simulate(tx)
        verdict, findings = assess(tx, sim, policy)
        note = f"language model unavailable ({e}); deterministic verdict only"
        if a.json:
            print(json.dumps({"verdict": verdict.value, "findings": [f.to_dict() for f in findings],
                              "call_kind": sim.call_kind, "decoded": sim.decoded, "warning": note},
                             indent=2, default=str), file=out)
        else:
            _print_findings(verdict, findings, out)
            _print_hints(findings, out, cfg.address_book)
            print(f"Warning: {note}", file=out)
        return _exit_code(verdict)
    if a.json:
        print(json.dumps(review.to_dict(), indent=2, default=str), file=out)
    else:
        _print_findings(review.verdict, review.findings, out)
        _print_hints(review.findings, out, cfg.address_book)
        if review.explanation:
            print("\n" + review.explanation, file=out)
        if review.model_contradicts_verdict:
            print("\n(note: the model's explanation contradicted the verdict and was ignored "
                  "for the decision)", file=out)
    return _exit_code(review.verdict)


def cmd_batch(a: argparse.Namespace, out: Any) -> int:
    cfg = _config(a)
    policy = cfg.effective_policy()
    raw = json.loads(Path(a.bundle_json).read_text())
    if isinstance(raw, list):
        txs_raw, sims_raw = raw, None
    else:
        txs_raw, sims_raw = raw["txs"], raw.get("sims")
    txs = [Tx.from_dict(t) for t in txs_raw]
    if sims_raw is not None:
        sims = [SimResult.from_dict(s) for s in sims_raw]
    else:
        simulator: Any = (AnvilSimulator(cfg.rpc_url, options=cfg.simulator) if cfg.rpc_url
                          else StaticSimulator(cfg.address_book))
        sims = [simulator.simulate(tx) for tx in txs]
    review = assess_bundle(txs, sims, policy)
    if a.json:
        print(json.dumps(review.to_dict(), indent=2, default=str), file=out)
    else:
        print(f"Bundle verdict: {review.verdict.value}", file=out)
        for t in review.per_tx:
            print(f"  tx #{t.index}: {t.verdict.value}"
                  + (" — " + ", ".join(f.rule for f in t.findings) if t.findings else ""), file=out)
        for f in review.bundle_findings:
            print(f"  [{f.severity.name}] {f.rule}: {f.message}", file=out)
    return _exit_code(review.verdict)


def cmd_decode(a: argparse.Namespace, out: Any) -> int:
    call = decode_call(a.data)
    if a.json:
        print(json.dumps(call.to_dict(), indent=2, default=str), file=out)
    else:
        print(describe(call), file=out)
        for c in call.walk():
            indent = "  "
            print(f"{indent}{c.kind} {c.signature or ''}", file=out)
            for k, v in c.args.items():
                print(f"{indent}  {k} = {json.dumps(v, default=str)}", file=out)
    return 0


def cmd_explain(a: argparse.Namespace, out: Any) -> int:
    spec = RULES.get(a.rule.upper())
    if spec is None:
        print(f"unknown rule {a.rule}. Known: {', '.join(sorted(RULES))}", file=sys.stderr)
        return 3
    if a.json:
        print(json.dumps(explain_dict(spec), indent=2), file=out)
    else:
        print(explain_text(spec), file=out)
    return 0


def cmd_rules(a: argparse.Namespace, out: Any) -> int:
    specs = [r for r in RULES.values()
             if (not a.category or r.category == a.category)
             and (not a.verdict or r.verdict.value == a.verdict.upper())]
    if a.markdown:
        print(rules_markdown(), file=out, end="")
        return 0
    if a.json:
        print(json.dumps([{"rule": r.id, "severity": r.severity.name, "verdict": r.verdict.value,
                           "category": r.category, "title": r.title} for r in specs], indent=2),
              file=out)
        return 0
    print(rules_table(specs), file=out)
    print(f"\n{len(specs)} rules. `txwarden explain <RULE>` for details.", file=out)
    return 0


def cmd_label(a: argparse.Namespace, out: Any) -> int:
    cfg = _config(a)
    lbl = cfg.address_book.get(a.address)
    if a.json:
        print(json.dumps({"address": a.address.lower(),
                          "label": lbl.name if lbl else None,
                          "kind": lbl.kind if lbl else None}), file=out)
    else:
        print(f"{a.address.lower()}: {lbl.name + ' (' + lbl.kind + ')' if lbl else 'unknown'}",
              file=out)
    return 0


def cmd_mcp(a: argparse.Namespace, out: Any) -> int:
    from .mcp_server import MCPServer

    cfg = _config(a)
    return MCPServer(cfg).serve(stdout=out if out is not sys.stdout else None)


def _replay_policy_hash(cfg: AppConfig) -> str:
    import hashlib
    from dataclasses import asdict

    sim = {k: (sorted(v) if isinstance(v, set) else v) for k, v in asdict(cfg.simulator).items()}
    blob = json.dumps({"policy": cfg.effective_policy().to_dict(), "simulator": sim},
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def cmd_replay(a: argparse.Namespace, out: Any) -> int:
    cases = load_cases(a.cases, a.format)
    print(cases.summary(), file=out)
    if a.validate_only:
        return 0
    redactor = Redactor()
    try:
        url = endpoint_from_env(a.rpc_env)
        redactor = Redactor(url)  # from here on every message is scrubbed of the URL's parts
        costs = CostModel(a.cost_per_call, a.cost_debug_trace, a.cost_archive, a.cost_combine,
                          a.archive_window)
        cfg = ReplayConfig(
            out_path=Path(a.out), cache_dir=None if a.no_cache else Path(a.cache_dir),
            limit=a.limit, rps=a.rps, budget_calls=a.budget_calls, budget_units=a.budget_units,
            costs=costs, max_retries=a.max_retries, retry_errors=a.retry_errors,
            max_consecutive_errors=a.max_consecutive_errors, mock=a.mock,
            endpoint_label=a.endpoint_label, estimate=a.estimate)
        for name in ("limit", "budget_calls", "budget_units", "max_retries",
                     "max_consecutive_errors"):
            value = getattr(cfg, name)
            if value is not None and value < 0:
                raise ReplayError(f"--{name.replace('_', '-')} must not be negative")
        if not cfg.rps > 0:
            raise ReplayError("--rps must be positive")
        app = _config(a)
        print(f"endpoint: {redact_url(url)} (from ${a.rpc_env})", file=out)
        replayer = Replayer(
            cases, http_transport(url), cfg, app.effective_policy(), app.simulator, redactor,
            log=lambda m: print(redactor.scrub(m), file=out), config_sha256=_replay_policy_hash(app))
        outcome = replayer.run()
    except (ReplayError, ConfigError) as e:
        print(f"error: {redactor.scrub(e)}", file=sys.stderr)
        return 3
    except Exception as e:  # never let a traceback (which may quote the URL) reach the terminal
        print(f"error: {redactor.exception(e)}", file=sys.stderr)
        return 1
    if outcome.mock:
        print("MOCK: the endpoint is the in-repo fake node; these results say nothing about "
              "real transactions", file=out)
    if cfg.estimate:
        print(format_estimate(outcome, costs), file=out)
        return outcome.exit_code
    c = outcome.counts
    print(f"{outcome.stopped}: {outcome.analysed} analysed this run ({c['analysed']} with a "
          f"verdict, {c['unsupported']} unsupported, {c['error']} error); {outcome.skipped} "
          f"already done; {outcome.calls} RPC requests, {outcome.units:g} units, "
          f"{outcome.cache_hits} cache hits", file=out)
    if outcome.out_path is not None:
        print(f"results: {outcome.out_path}", file=out)
    if outcome.message:
        print(redactor.scrub(outcome.message), file=out)
    return outcome.exit_code


def cmd_replay_report(a: argparse.Namespace, out: Any) -> int:
    try:
        rep = report_from_file(a.results, allow_mock=a.allow_mock, allow_small=a.allow_small)
    except ReportRefused as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    text = render_json(rep) if a.json else render_text(rep)
    if a.out:
        path = rep.output_path(a.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}", file=out)
    else:
        out.write(text)
    return 0


def _refuses_url_argument(argv: list[str]) -> bool:
    """True for ``replay`` invoked with something that looks like an RPC URL or an --rpc flag."""
    return bool(argv) and argv[0] == "replay" and any(
        "://" in t or t == "--rpc" or t.startswith("--rpc=") for t in argv[1:])


def main(argv: list[str] | None = None, out: Any = None) -> int:
    out = out or sys.stdout
    argv = _normalise_argv(list(sys.argv[1:] if argv is None else argv))
    if _refuses_url_argument(argv):
        print("error: replay does not take an RPC URL on the command line (it would land in shell "
              "history and process listings). Put the URL in an environment variable "
              "(default TXWARDEN_LIVE_RPC, or choose one with --rpc-env NAME).", file=sys.stderr)
        return 3
    parser = build_parser()
    a, extra = parser.parse_known_args(argv)
    if extra:
        if a.cmd == "replay":  # a mistyped flag may sit next to a pasted key: say nothing about it
            print("error: replay: unrecognized arguments (not shown). See `txwarden replay "
                  "--help`; the endpoint is read from an environment variable.", file=sys.stderr)
            raise SystemExit(2)
        parser.error("unrecognized arguments: " + " ".join(extra))
    if a.cmd is None:
        parser.print_help(file=out)
        return 3
    handler = {
        "review": cmd_review, "batch": cmd_batch, "decode": cmd_decode, "explain": cmd_explain,
        "rules": cmd_rules, "label": cmd_label, "mcp": cmd_mcp, "replay": cmd_replay,
        "replay-report": cmd_replay_report,
    }[a.cmd]
    try:
        return handler(a, out)
    except (ConfigError, FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
