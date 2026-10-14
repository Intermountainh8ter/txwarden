"""Command-line interface.

    txwarden review tx.json [--intent ...] [--rpc URL | --fixture sim.json] [--no-llm] [--json]
    txwarden batch bundle.json [--rpc URL] [--json]
    txwarden decode 0x095ea7b3...
    txwarden explain UNLIMITED_APPROVAL_UNKNOWN
    txwarden rules
    txwarden label 0x7a25...
    txwarden mcp [--rpc URL]

``txwarden tx.json ...`` (no sub-command) is accepted as ``review`` for backward compatibility.
Exit codes: 0 ALLOW, 2 WARN/BLOCK, 3 usage or input error.
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

SUBCOMMANDS = ("review", "batch", "decode", "explain", "rules", "label", "mcp")


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
    return p


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


def _print_hints(findings: list[Finding], out: Any) -> None:
    for rule in dict.fromkeys(f.rule for f in findings):
        if rule in HINTS:
            print(f"Hint ({rule}): {HINTS[rule]}", file=out)


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
        sim_data = raw.get(tx.data, raw) if isinstance(raw, dict) and "success" not in raw else raw
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
            _print_hints(findings, out)
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
            _print_hints(findings, out)
            print(f"Warning: {note}", file=out)
        return _exit_code(verdict)
    if a.json:
        print(json.dumps(review.to_dict(), indent=2, default=str), file=out)
    else:
        _print_findings(review.verdict, review.findings, out)
        _print_hints(review.findings, out)
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


def main(argv: list[str] | None = None, out: Any = None) -> int:
    out = out or sys.stdout
    argv = _normalise_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    a = parser.parse_args(argv)
    if a.cmd is None:
        parser.print_help(file=out)
        return 3
    handler = {
        "review": cmd_review, "batch": cmd_batch, "decode": cmd_decode, "explain": cmd_explain,
        "rules": cmd_rules, "label": cmd_label, "mcp": cmd_mcp,
    }[a.cmd]
    try:
        return handler(a, out)
    except (ConfigError, FileNotFoundError, json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
