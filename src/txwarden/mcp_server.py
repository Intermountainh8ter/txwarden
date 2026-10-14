"""Minimal MCP server over stdio (newline-delimited JSON-RPC 2.0), no SDK dependency.

Implements the handshake a Model Context Protocol client expects: ``initialize``,
``notifications/initialized``, ``ping``, ``tools/list`` and ``tools/call``. Tools:

- ``review_transaction``: deterministic review of one transaction (verdict + findings).
  The caller supplies either a recorded ``sim`` (offline) or relies on the server's RPC.
  With neither, the result is a fail-closed BLOCK, never ALLOW.
- ``review_bundle``: the same for a list of transactions with cross-transaction rules.
- ``decode_calldata``, ``explain_rule``, ``list_rules``: helpers.

Run: ``txwarden mcp [--rpc URL] [--config cfg.toml]`` or ``python -m txwarden.mcp_server``.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import IO, Any

from . import __version__
from .abi import decode_call, describe
from .batch import assess_bundle
from .config import AppConfig, load_config
from .models import SimResult, Tx, Verdict
from .risk import RULES, PolicyConfig, assess
from .simulator import AnvilSimulator, Simulator, StaticSimulator

PROTOCOL_VERSION = "2024-11-05"

_TX_SCHEMA = {
    "type": "object",
    "properties": {
        "sender": {"type": "string"}, "to": {"type": "string"},
        "data": {"type": "string"}, "value": {"type": ["integer", "string"]},
        "chain_id": {"type": "integer"},
    },
    "required": ["sender", "to"],
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "review_transaction",
        "description": "Simulate an Ethereum transaction and return a deterministic "
                       "ALLOW/WARN/BLOCK verdict with findings. Pass `sim` to review a recorded "
                       "simulation offline; otherwise the server's RPC is used. The verdict "
                       "cannot be influenced by any text in the request.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tx": _TX_SCHEMA,
                "sim": {"type": "object", "description": "Recorded SimResult (optional)"},
                "policy": {"type": "object", "description": "PolicyConfig overrides (optional)"},
                "intent": {"type": "string"},
            },
            "required": ["tx"],
        },
    },
    {
        "name": "review_bundle",
        "description": "Review several transactions signed together, including cross-transaction "
                       "rules (approve-then-pull, add-then-remove liquidity, cumulative drain).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "txs": {"type": "array", "items": _TX_SCHEMA},
                "sims": {"type": "array", "items": {"type": "object"}},
                "policy": {"type": "object"},
            },
            "required": ["txs"],
        },
    },
    {
        "name": "decode_calldata",
        "description": "Decode calldata into a named function call tree.",
        "inputSchema": {"type": "object", "properties": {"data": {"type": "string"}},
                        "required": ["data"]},
    },
    {
        "name": "explain_rule",
        "description": "Explain a risk rule id.",
        "inputSchema": {"type": "object", "properties": {"rule": {"type": "string"}},
                        "required": ["rule"]},
    },
    {
        "name": "list_rules",
        "description": "List every risk rule with severity and verdict.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class MCPServer:
    def __init__(self, config: AppConfig | None = None, simulator: Simulator | None = None):
        self.config = config or AppConfig()
        self._backend = simulator
        self.initialized = False

    # ---- backends
    def _policy(self, override: dict[str, Any] | None) -> PolicyConfig:
        base = self.config.effective_policy().to_dict()
        if override:
            base.update(override)
        return PolicyConfig.from_dict(base)

    def _simulator(self) -> Simulator | None:
        if self._backend is None and self.config.rpc_url:
            self._backend = AnvilSimulator(self.config.rpc_url, options=self.config.simulator)
        return self._backend

    # ---- tool implementations
    def _review(self, args: dict[str, Any]) -> dict[str, Any]:
        tx = Tx.from_dict(args["tx"])
        policy = self._policy(args.get("policy"))
        if args.get("sim") is not None:
            sim = SimResult.from_dict(args["sim"])
            backend = "recorded"
        else:
            simulator = self._simulator()
            if simulator is None:
                sim = StaticSimulator(self.config.address_book).simulate(tx)
                backend = "static"
            else:
                sim = simulator.simulate(tx)
                backend = "rpc"
        verdict, findings = assess(tx, sim, policy)
        out = {"verdict": verdict.value, "findings": [f.to_dict() for f in findings],
               "backend": backend, "call_kind": sim.call_kind}
        if backend == "static":
            out["warning"] = ("no RPC configured: static decode only; swap, honeypot, trace and "
                              "account rules could not run")
        return out

    def _review_bundle(self, args: dict[str, Any]) -> dict[str, Any]:
        txs = [Tx.from_dict(t) for t in args["txs"]]
        policy = self._policy(args.get("policy"))
        sims_raw = args.get("sims")
        if sims_raw is not None:
            if len(sims_raw) != len(txs):
                raise ValueError("sims must match txs one-to-one")
            sims = [SimResult.from_dict(s) for s in sims_raw]
        else:
            simulator = self._simulator() or StaticSimulator(self.config.address_book)
            sims = [simulator.simulate(tx) for tx in txs]
        return assess_bundle(txs, sims, policy).to_dict()

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Returns an MCP ``tools/call`` result: ``{"content": [...], "isError": bool}``."""
        try:
            if name == "review_transaction":
                payload = self._review(args)
            elif name == "review_bundle":
                payload = self._review_bundle(args)
            elif name == "decode_calldata":
                call = decode_call(str(args["data"]))
                payload = {"summary": describe(call), **call.to_dict()}
            elif name == "explain_rule":
                spec = RULES.get(str(args.get("rule", "")).upper())
                if spec is None:
                    raise KeyError(f"unknown rule {args.get('rule')}")
                payload = {"rule": spec.id, "severity": spec.severity.name,
                           "verdict": spec.verdict.value, "category": spec.category,
                           "title": spec.title, "description": spec.description,
                           "config": list(spec.config)}
            elif name == "list_rules":
                payload = {"rules": [{"rule": r.id, "severity": r.severity.name,
                                      "verdict": r.verdict.value, "title": r.title}
                                     for r in RULES.values()]}
            else:
                raise KeyError(f"unknown tool {name}")
        except Exception as e:  # reported to the client, fail closed
            fail: dict[str, Any] = {"error": f"{type(e).__name__}: {e}"}
            if name in ("review_transaction", "review_bundle"):
                fail["verdict"] = Verdict.BLOCK.value  # fail closed
            return {"content": [{"type": "text", "text": json.dumps(fail, default=str)}],
                    "isError": True}
        return {"content": [{"type": "text", "text": json.dumps(payload, default=str)}],
                "isError": False}

    # ---- JSON-RPC
    def handle(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC message. Returns a response, or None for notifications."""
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return _error(msg.get("id") if isinstance(msg, dict) else None, -32600,
                          "invalid request")
        method, params, msg_id = msg["method"], msg.get("params") or {}, msg.get("id")
        is_notification = "id" not in msg
        if method == "initialize":
            self.initialized = True
            return _result(msg_id, {
                "protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "txwarden", "version": __version__},
            })
        if method == "notifications/initialized" or method.startswith("notifications/"):
            return None
        if method == "ping":
            return _result(msg_id, {})
        if method == "tools/list":
            return _result(msg_id, {"tools": TOOLS})
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if not isinstance(name, str) or not isinstance(args, dict):
                return _error(msg_id, -32602, "invalid params: name and arguments required")
            return _result(msg_id, self.call_tool(name, args))
        if is_notification:
            return None
        return _error(msg_id, -32601, f"method not found: {method}")

    def serve(self, stdin: IO[str] | None = None, stdout: IO[str] | None = None) -> int:
        inp, out = stdin or sys.stdin, stdout or sys.stdout
        for line in inp:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _write(out, _error(None, -32700, "parse error"))
                continue
            if isinstance(msg, list):  # batch
                responses = [r for r in (self.handle(m) for m in msg) if r is not None]
                if responses:
                    _write(out, responses)
                continue
            resp = self.handle(msg)
            if resp is not None:
                _write(out, resp)
        return 0


def _result(msg_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _write(out: IO[str], obj: Any) -> None:
    out.write(json.dumps(obj, default=str) + "\n")
    out.flush()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="txwarden-mcp")
    p.add_argument("--rpc", default=None, help="fork RPC URL (optional)")
    p.add_argument("--config", default=None, help="TOML config path")
    a = p.parse_args(argv)
    cfg = load_config(a.config) if a.config else AppConfig()
    if a.rpc:
        cfg.rpc_url = a.rpc
    return MCPServer(cfg).serve()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
