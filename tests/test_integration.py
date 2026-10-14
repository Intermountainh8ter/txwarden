"""End-to-end through real sockets and real processes.

- ``AnvilSimulator`` -> ``http_transport`` -> an HTTP server running in a thread that replays
  recorded sessions (``tests/fixtures/rpc_*.json``) or misbehaves on purpose.
- the CLI and the MCP server run as subprocesses with pipes, the way a user or an MCP client
  starts them.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from txwarden.cli import main
from txwarden.models import SimResult, Tx, Verdict
from txwarden.risk import PolicyConfig, assess
from txwarden.simulator import (
    AnvilSimulator,
    RpcError,
    SimulatorOptions,
    http_transport,
    replay_transport,
)

from . import make_fixtures
from .fake_rpc import FakeRpcServer, replay_handler
from .helpers import ROUTER, STRANGER, TOKEN, U, approve_calldata

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]


def fixture(name: str) -> tuple[Path, Tx]:
    path = FIXTURES / f"{name}.json"
    return path, Tx.from_dict(json.loads(path.read_text())["tx"])


def serve(name: str, **kw) -> tuple[FakeRpcServer, Tx]:
    path, tx = fixture(name)
    return FakeRpcServer(replay_handler(path), **kw), tx


# --------------------------------------------------------------------------- fixtures

def test_committed_recordings_are_current():
    """The recordings are derived data: regenerate with ``python -m tests.make_fixtures``."""
    for name, data in make_fixtures.build_all().items():
        assert json.loads((FIXTURES / f"{name}.json").read_text()) == data, name
    for f in FIXTURES.glob("rpc_*.json"):
        assert "not a real node" in json.loads(f.read_text())["description"]


# --------------------------------------------------------------------------- HTTP path

def test_http_path_gives_the_same_result_as_replaying_the_recording_in_process():
    server, tx = serve("rpc_swap_tight")
    path, _ = fixture("rpc_swap_tight")
    with server:
        over_http = AnvilSimulator(rpc_url=server.url).simulate(tx)
        methods = server.methods
    in_process = AnvilSimulator(transport=replay_transport(path)).simulate(tx)
    assert over_http.to_dict() == in_process.to_dict()
    assert {"eth_chainId", "eth_call", "eth_estimateGas", "eth_getCode", "eth_simulateV1",
            "debug_traceCall"} <= set(methods)
    assert over_http.success and over_http.swap is not None and over_http.honeypot.sell_ok
    verdict, findings = assess(tx, over_http, PolicyConfig(trusted_spenders={ROUTER}))
    assert verdict == Verdict.ALLOW, [f.rule for f in findings]


def test_http_path_blocks_an_unlimited_approval_and_blocks_a_honeypot():
    server, tx = serve("rpc_unlimited_approve")
    with server:
        sim = AnvilSimulator(rpc_url=server.url).simulate(tx)
    verdict, findings = assess(tx, sim, PolicyConfig())
    assert verdict == Verdict.BLOCK and findings[0].rule == "UNLIMITED_APPROVAL_UNKNOWN"
    assert sim.accounts[STRANGER].is_fresh
    server, tx = serve("rpc_honeypot")
    with server:
        sim = AnvilSimulator(rpc_url=server.url).simulate(tx)
    verdict, findings = assess(tx, sim, PolicyConfig(trusted_spenders={ROUTER}))
    assert verdict == Verdict.BLOCK and "HONEYPOT_SELL_REVERTS" in {f.rule for f in findings}


def test_json_rpc_revert_over_http_is_a_revert_with_the_decoded_reason():
    server, tx = serve("rpc_revert")
    with server:
        sim = AnvilSimulator(rpc_url=server.url).simulate(tx)
    assert not sim.success and sim.error is None
    assert sim.revert_reason == "UniswapV2Router: EXPIRED"
    assert assess(tx, sim, PolicyConfig())[0] == Verdict.WARN


@pytest.mark.parametrize("kwargs,fragment", [
    ({"status": 500}, "HTTP 500"),
    ({"status": 429}, "HTTP 429"),
    ({"status": 503, "body": b"<html>bad gateway</html>", "content_type": "text/html"}, "HTTP 503"),
    ({"body": b"<html>captive portal</html>", "content_type": "text/html"}, "did not return JSON"),
    ({"body": b"[1, 2, 3]"}, "malformed JSON-RPC response"),
])
def test_server_misbehaviour_is_unavailable_and_blocks(kwargs, fragment):
    with FakeRpcServer(lambda m, p: "0x", **kwargs) as server:
        sim = AnvilSimulator(rpc_url=server.url).simulate(Tx(U, TOKEN, approve_calldata(STRANGER, 1)))
    assert not sim.success and fragment in sim.error and sim.revert_reason is None
    verdict, findings = assess(Tx(U, TOKEN), sim, PolicyConfig())
    assert verdict == Verdict.BLOCK and [f.rule for f in findings] == ["SIMULATION_UNAVAILABLE"]


def test_slow_server_times_out_into_unavailable():
    with FakeRpcServer(lambda m, p: "0x", delay=1.5) as server:
        call = http_transport(server.url, timeout=0.2)
        with pytest.raises(RpcError) as e:
            call("eth_chainId", [])
    assert e.value.transport and "cannot reach" in e.value.message


def test_nothing_listening_is_unavailable():
    sim = AnvilSimulator(transport=http_transport("http://127.0.0.1:9", timeout=1)).simulate(
        Tx(U, TOKEN, "0x"))
    assert sim.error and "cannot reach" in sim.error


def test_unknown_optional_methods_degrade_over_http():
    path, tx = fixture("rpc_unlimited_approve")
    handle = replay_handler(path)

    def only_core(method, params):
        if method in ("debug_traceCall", "eth_getCode", "eth_simulateV1"):
            raise RpcError("the method does not exist/is not available", -32601)
        return handle(method, params)

    with FakeRpcServer(only_core) as server:
        sim = AnvilSimulator(rpc_url=server.url).simulate(tx)
    assert sim.success and sim.call_tree is None and sim.accounts == {}
    assert set(sim.incomplete) == {"account_probe", "call_trace"}


def test_http_transport_ids_increment_and_errors_carry_codes():
    seen = []

    def handler(method, params):
        seen.append(method)
        if method == "boom":
            raise RpcError("execution reverted", 3, "0x08c379a0")
        return {"ok": method}

    with FakeRpcServer(handler) as server:
        call = http_transport(server.url)
        assert call("a", []) == {"ok": "a"} and call("b", [1]) == {"ok": "b"}
        with pytest.raises(RpcError) as e:
            call("boom", [])
    assert [r["id"] for r in server.requests] == [1, 2, 3]
    assert e.value.code == 3 and e.value.data == "0x08c379a0" and not e.value.transport


# --------------------------------------------------------------------------- CLI over HTTP

def run(*argv: str) -> tuple[int, str]:
    import io

    out = io.StringIO()
    return main(list(argv), out), out.getvalue()


def test_cli_review_over_http_with_json_output_and_config_file(tmp_path):
    server, tx = serve("rpc_unlimited_approve")
    tx_file = tmp_path / "tx.json"
    tx_file.write_text(json.dumps(tx.to_dict()))
    cfg = tmp_path / "txwarden.toml"
    with server:
        cfg.write_text(f'rpc_url = "{server.url}"\n[simulator]\nhoneypot = false\n')
        code, out = run("review", str(tx_file), "--config", str(cfg), "--no-llm", "--json")
    payload = json.loads(out)
    assert code == 2 and payload["verdict"] == "BLOCK"
    assert payload["findings"][0]["rule"] == "UNLIMITED_APPROVAL_UNKNOWN"
    assert "warning" not in payload  # a real RPC was used
    assert "eth_call" in server.methods


def test_cli_record_then_replay_reproduces_the_review_offline(tmp_path):
    path, tx = fixture("rpc_swap_tight")
    tx_file = tmp_path / "tx.json"
    tx_file.write_text(json.dumps(tx.to_dict()))
    session = tmp_path / "session.json"
    with FakeRpcServer(replay_handler(path)) as server:
        code, live = run("review", str(tx_file), "--rpc", server.url, "--no-llm", "--json",
                         "--record", str(session), "--trust-spender", ROUTER)
    assert code == 0 and json.loads(session.read_text())["records"]
    assert "txwarden" in json.loads(session.read_text())["description"]
    code2, replayed = run("review", str(tx_file), "--replay", str(session), "--no-llm", "--json",
                          "--trust-spender", ROUTER)  # no network involved
    assert code2 == 0 and json.loads(replayed) == json.loads(live)
    other = tmp_path / "other.json"
    other.write_text(json.dumps(tx.to_dict() | {"value": 123}))  # not in the recording
    code3, out3 = run("review", str(other), "--replay", str(session), "--no-llm")
    assert code3 == 2 and "SIMULATION_UNAVAILABLE" in out3 and "no recorded response" in out3


def test_cli_batch_over_http(tmp_path):
    path, tx = fixture("rpc_unlimited_approve")
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps([tx.to_dict(), tx.to_dict() | {"to": STRANGER, "data": "0x"}]))
    with FakeRpcServer(replay_handler(path)) as server:
        code, out = run("batch", str(bundle), "--rpc", server.url, "--json")
    data = json.loads(out)
    assert code == 2 and data["verdict"] == "BLOCK"
    assert data["per_tx"][0]["verdict"] == "BLOCK"
    # the second transaction was not recorded: its own review is unavailable, not silently clean
    assert data["per_tx"][1]["findings"][0]["rule"] == "SIMULATION_UNAVAILABLE"
    assert data["per_tx"][1]["verdict"] == "BLOCK"


def test_tomllib_and_fallback_parser_read_the_same_config(tmp_path, monkeypatch):
    from txwarden import config as cfgmod

    f = tmp_path / "c.toml"
    f.write_text(f'rpc_url = "http://x"\n[policy]\ntrusted_spenders = ["{ROUTER}"]\n'
                 "slippage_block = 0.03\n")
    via_default = cfgmod.load_config(f)
    monkeypatch.setattr(cfgmod, "_tomllib", None)
    via_fallback = cfgmod.load_config(f)
    assert via_default.policy.to_dict() == via_fallback.policy.to_dict()
    assert via_default.rpc_url == via_fallback.rpc_url == "http://x"
    assert sys.version_info < (3, 11) or via_default is not via_fallback


# --------------------------------------------------------------------------- real processes

def pyrun(*args: str, stdin: str | None = None, timeout: float = 60) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONUNBUFFERED": "1"}
    return subprocess.run([sys.executable, *args], input=stdin, capture_output=True, text=True,
                          timeout=timeout, env=env, cwd=ROOT)


def test_cli_process_exit_codes_and_module_entry_point(tmp_path):
    f = tmp_path / "tx.json"
    f.write_text(json.dumps({"sender": U, "to": TOKEN, "data": approve_calldata(STRANGER, 2**256 - 1)}))
    r = pyrun("-m", "txwarden", "review", str(f), "--no-llm")
    assert r.returncode == 2 and "Verdict: BLOCK" in r.stdout
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"sender": U, "to": TOKEN, "data": approve_calldata(STRANGER, 0)}))
    assert pyrun("-m", "txwarden", "review", str(ok), "--no-llm").returncode == 0
    r = pyrun("-m", "txwarden", "review", str(tmp_path / "missing.json"))
    assert r.returncode == 3 and "error:" in r.stderr
    assert pyrun("-m", "txwarden", "--version").stdout.startswith("txwarden ")
    assert pyrun("-m", "txwarden", "explain", "REVERT").returncode == 0


class McpProcess:
    """An MCP client's view of ``txwarden-mcp``: newline-delimited JSON-RPC over pipes."""

    def __init__(self, *args: str):
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONUNBUFFERED": "1"}
        self.p = subprocess.Popen([sys.executable, "-m", "txwarden.mcp_server", *args],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, env=env, cwd=ROOT)
        self.next_id = 0

    def send(self, obj) -> None:
        self.p.stdin.write((obj if isinstance(obj, str) else json.dumps(obj)) + "\n")
        self.p.stdin.flush()

    def read(self, timeout: float = 30) -> dict:
        deadline = time.time() + timeout
        line = ""
        while not line and time.time() < deadline:
            line = self.p.stdout.readline()
        assert line, "no response from the MCP server: " + self.p.stderr.read()
        return json.loads(line)

    def request(self, method: str, params: dict | None = None) -> dict:
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}})
        resp = self.read()
        assert resp["id"] == self.next_id
        return resp

    def call(self, name: str, args: dict) -> dict:
        return self.request("tools/call", {"name": name, "arguments": args})["result"]

    def close(self) -> int:
        self.p.stdin.close()
        return self.p.wait(timeout=30)


def test_mcp_server_handshake_listing_and_calls_over_pipes():
    mcp = McpProcess()
    try:
        init = mcp.request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                          "clientInfo": {"name": "pytest", "version": "0"}})
        assert init["result"]["serverInfo"]["name"] == "txwarden"
        assert init["result"]["capabilities"]["tools"] == {"listChanged": False}
        mcp.send({"jsonrpc": "2.0", "method": "notifications/initialized"})  # no response expected
        tools = mcp.request("tools/list")["result"]["tools"]
        assert {t["name"] for t in tools} >= {"review_transaction", "review_bundle", "list_rules"}
        res = mcp.call("review_transaction", {"tx": {
            "sender": U, "to": TOKEN, "data": approve_calldata(STRANGER, 2**256 - 1)}})
        body = json.loads(res["content"][0]["text"])
        assert res["isError"] is False and body["verdict"] == "BLOCK" and body["backend"] == "static"
        bad = mcp.call("review_transaction", {"tx": {"sender": U}})
        assert bad["isError"] is True and json.loads(bad["content"][0]["text"])["verdict"] == "BLOCK"
        mcp.send("this is not json")
        assert mcp.read()["error"]["code"] == -32700
        assert mcp.request("ping")["result"] == {}  # still alive after garbage
        assert mcp.request("no/such/method")["error"]["code"] == -32601
    finally:
        assert mcp.close() == 0


def test_mcp_server_uses_the_rpc_backend_over_http():
    server, tx = serve("rpc_unlimited_approve")
    with server:
        mcp = McpProcess("--rpc", server.url)
        try:
            mcp.request("initialize", {"protocolVersion": "2024-11-05"})
            res = mcp.call("review_transaction", {"tx": tx.to_dict()})
            body = json.loads(res["content"][0]["text"])
            assert body["backend"] == "rpc" and body["verdict"] == "BLOCK" and "warning" not in body
        finally:
            mcp.close()


def test_mcp_server_with_unreachable_rpc_fails_closed():
    mcp = McpProcess("--rpc", "http://127.0.0.1:9")
    try:
        mcp.request("initialize")
        res = mcp.call("review_transaction", {"tx": {"sender": U, "to": TOKEN,
                                                     "data": approve_calldata(STRANGER, 1)}})
        body = json.loads(res["content"][0]["text"])
        assert body["verdict"] == "BLOCK"
        assert body["findings"][0]["rule"] == "SIMULATION_UNAVAILABLE"
    finally:
        mcp.close()


def test_mcp_via_the_cli_subcommand_and_closed_stdin_exits_cleanly():
    r = pyrun("-m", "txwarden", "mcp", stdin=json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n")
    assert r.returncode == 0
    assert any(t["name"] == "review_transaction" for t in json.loads(r.stdout)["result"]["tools"])


def test_unused_imports_keep_the_module_honest():
    assert SimResult and SimulatorOptions  # referenced so the public names stay importable
