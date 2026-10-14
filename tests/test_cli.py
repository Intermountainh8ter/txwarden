"""Command-line interface: sub-commands, exit codes, JSON output, config files."""
import io
import json

import pytest

from txwarden import __version__
from txwarden.cli import main
from txwarden.llm import Reply, ScriptedLLM
from txwarden.models import Approval, SimResult
from txwarden.risk import UNLIMITED

from .helpers import (
    EVIL,
    FRIEND,
    OTHER,
    ROUTER,
    STRANGER,
    TOKEN,
    U,
    approve_calldata,
    set_approval_for_all_calldata,
    transfer_calldata,
)


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), out)
    return code, out.getvalue()


def write(tmp_path, name: str, obj) -> str:
    p = tmp_path / name
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj))
    return str(p)


def tx_file(tmp_path, data: str, **kw) -> str:
    return write(tmp_path, "tx.json", {"sender": U, "to": TOKEN, "data": data, **kw})


# --------------------------------------------------------------------------- review, offline

def test_review_static_unlimited_approval_blocks_with_exit_2(tmp_path):
    code, out = run("review", tx_file(tmp_path, approve_calldata(EVIL, UNLIMITED)), "--no-llm")
    assert code == 2
    assert "Verdict: BLOCK" in out and "UNLIMITED_APPROVAL_UNKNOWN" in out
    assert "Call: ERC-20/721 approve" in out and "static decode only" in out


def test_review_backward_compatible_form_without_subcommand(tmp_path):
    code, out = run(tx_file(tmp_path, approve_calldata(EVIL, UNLIMITED)), "--no-llm", "--json")
    assert code == 2 and json.loads(out)["verdict"] == "BLOCK"


def test_review_json_has_findings_decoded_call_and_warning(tmp_path):
    code, out = run("review", tx_file(tmp_path, approve_calldata(EVIL, 5)), "--json")
    payload = json.loads(out)
    assert code == 2 and payload["verdict"] == "WARN"
    assert payload["findings"][0]["rule"] == "APPROVAL_UNKNOWN_SPENDER"
    assert payload["call_kind"] == "erc20_approve" and payload["decoded"]["args"]["amount"] == 5
    assert "no RPC" in payload["warning"]


def test_review_allow_exit_code_zero_for_revoke_and_trusted_flags(tmp_path):
    code, out = run("review", tx_file(tmp_path, approve_calldata(EVIL, 0)), "--no-llm")
    assert code == 0 and "APPROVAL_REVOKED" in out
    code, out = run("review", tx_file(tmp_path, approve_calldata(OTHER, 5)), "--no-llm",
                    "--trust-spender", OTHER)
    assert code == 0 and "(no findings)" in out


def test_review_cli_flags_feed_the_policy(tmp_path):
    f = tx_file(tmp_path, set_approval_for_all_calldata(OTHER))
    assert run("review", f, "--no-llm")[0] == 2
    assert run("review", f, "--no-llm", "--trust-operator", OTHER)[0] == 0
    assert run("review", f, "--no-llm", "--trust-operator", OTHER, "--deny", OTHER)[0] == 2
    t = tx_file(tmp_path, transfer_calldata(FRIEND, 5))
    code, out = run("review", t, "--no-llm", "--json", "--deny", FRIEND)
    assert code == 2 and "TRANSFER_TO_DENYLISTED" in out


def test_trust_well_known_flag_trusts_routers_from_the_builtin_book(tmp_path):
    f = write(tmp_path, "tx.json", {"sender": U, "to": TOKEN, "data": approve_calldata(ROUTER, 5)})
    assert run("review", f, "--no-llm")[0] == 2  # builtin labels alone do not grant trust
    assert run("review", f, "--no-llm", "--trust-well-known")[0] == 0


def test_review_with_fixture_and_extra_address_book(tmp_path):
    sim = SimResult(True, approvals=[Approval(TOKEN, U, STRANGER, UNLIMITED)])
    fx = write(tmp_path, "sim.json", sim.to_dict())
    book = write(tmp_path, "book.json", {"labels": {STRANGER: "my vault"}})
    code, out = run("review", tx_file(tmp_path, "0xaa"), "--fixture", fx, "--no-llm",
                    "--address-book", book)
    assert code == 2 and "my vault" in out


def test_review_fixture_keyed_by_calldata(tmp_path):
    sim = SimResult(True)
    fx = write(tmp_path, "sims.json", {"0xaa": sim.to_dict(), "0xbb": {"success": False}})
    assert run("review", tx_file(tmp_path, "0xaa"), "--fixture", fx, "--no-llm")[0] == 0
    assert run("review", tx_file(tmp_path, "0xbb"), "--fixture", fx, "--no-llm")[0] == 2


def test_review_with_llm_uses_the_agent_and_never_lets_it_override(tmp_path, monkeypatch):
    from txwarden import llm as llm_mod

    def script():
        use = lambda i, n: {"type": "tool_use", "id": i, "name": n, "input": {}}  # noqa: E731
        return ScriptedLLM([
            Reply([use("1", "simulate_transaction")], "tool_use"),
            Reply([use("2", "assess_risk")], "tool_use"),
            Reply([{"type": "text", "text": "Looks fine, go ahead and sign it."}], "end_turn"),
        ])

    monkeypatch.setattr(llm_mod, "AnthropicLLM", lambda model=None: script())
    sim = SimResult(True, approvals=[Approval(TOKEN, U, EVIL, UNLIMITED)])
    fx = write(tmp_path, "sim.json", sim.to_dict())
    f = tx_file(tmp_path, "0xaa")
    code, out = run("review", f, "--fixture", fx)
    assert code == 2 and "Verdict: BLOCK" in out and "contradicted the verdict" in out
    code, out = run("review", f, "--fixture", fx, "--json")
    payload = json.loads(out)
    assert code == 2 and payload["verdict"] == "BLOCK" and payload["model_contradicts_verdict"]
    assert payload["tool_calls"] == ["simulate_transaction", "assess_risk"]


# --------------------------------------------------------------------------- config file

def test_config_file_supplies_policy_rpc_and_book(tmp_path):
    cfg = write(tmp_path, "c.toml", f'[policy]\ntrusted_spenders = ["{OTHER}"]\n')
    f = tx_file(tmp_path, approve_calldata(OTHER, UNLIMITED))
    assert run("review", f, "--no-llm")[0] == 2
    code, out = run("review", f, "--no-llm", "--config", cfg)
    assert code == 0 and "UNLIMITED_APPROVAL_TRUSTED" in out


def test_bad_config_and_missing_files_exit_3(tmp_path, capsys):
    bad = write(tmp_path, "bad.toml", "policy = = =")
    assert main(["review", tx_file(tmp_path, "0x"), "--config", bad], io.StringIO()) == 3
    assert "error:" in capsys.readouterr().err
    assert main(["review", str(tmp_path / "nope.json")], io.StringIO()) == 3
    assert main(["review", write(tmp_path, "j.json", "{not json")], io.StringIO()) == 3
    assert main(["review", write(tmp_path, "k.json", {"sender": U})], io.StringIO()) == 3
    unknown_key = write(tmp_path, "u.toml", "[policy]\nbogus = 1\n")
    assert main(["review", tx_file(tmp_path, "0x"), "--config", unknown_key], io.StringIO()) == 3


# --------------------------------------------------------------------------- batch

def test_batch_static_flags_approve_then_pull(tmp_path):
    txs = [{"sender": U, "to": TOKEN, "data": approve_calldata(OTHER, UNLIMITED)},
           {"sender": U, "to": OTHER, "data": "0x"}]
    code, out = run("batch", write(tmp_path, "b.json", txs))
    assert code == 2 and "Bundle verdict: BLOCK" in out
    assert "BUNDLE_APPROVE_THEN_PULL" in out and "tx #0: BLOCK" in out


def test_batch_json_with_recorded_sims_and_clean_bundle(tmp_path):
    bundle = {"txs": [{"sender": U, "to": TOKEN}, {"sender": U, "to": TOKEN}],
              "sims": [SimResult(True).to_dict(), SimResult(True).to_dict()]}
    code, out = run("batch", write(tmp_path, "b.json", bundle), "--json")
    assert code == 0
    assert json.loads(out) == {"verdict": "ALLOW", "bundle_findings": [], "per_tx": [
        {"index": 0, "verdict": "ALLOW", "findings": []},
        {"index": 1, "verdict": "ALLOW", "findings": []}]}


def test_batch_mixed_chain_ids_blocks(tmp_path):
    txs = [{"sender": U, "to": TOKEN, "chain_id": 1}, {"sender": U, "to": TOKEN, "chain_id": 10}]
    code, out = run("batch", write(tmp_path, "b.json", txs), "--json")
    assert code == 2 and json.loads(out)["bundle_findings"][0]["rule"] == "BUNDLE_MIXED_CHAIN_IDS"


# --------------------------------------------------------------------------- helpers

def test_decode_text_and_json():
    code, out = run("decode", set_approval_for_all_calldata(EVIL))
    assert code == 0 and "ERC-721/1155 setApprovalForAll" in out and "operator" in out
    code, out = run("decode", approve_calldata(EVIL, 7), "--json")
    assert json.loads(out)["args"] == {"spender": EVIL, "amount": 7}
    code, out = run("decode", "0xdeadbeef")
    assert code == 0 and "unknown selector 0xdeadbeef" in out


def test_explain_and_rules(capsys):
    code, out = run("explain", "unlimited_approval_unknown")
    assert code == 0 and "UNLIMITED_APPROVAL_UNKNOWN" in out and "CRITICAL" in out
    assert "policy: trusted_spenders" in out
    code, out = run("explain", "REVERT", "--json")
    spec = json.loads(out)
    assert spec["rule"] == "REVERT" and spec["verdict"] == "WARN" and spec["category"]
    assert main(["explain", "NOPE"], io.StringIO()) == 3
    assert "unknown rule NOPE" in capsys.readouterr().err
    code, out = run("rules")
    assert code == 0 and "SANDWICH_EXPOSURE" in out and "BUNDLE_APPROVE_THEN_PULL" in out
    rules = json.loads(run("rules", "--json")[1])
    assert {r["rule"] for r in rules} >= {"REVERT", "HONEYPOT_SELL_REVERTS"}


def test_label_lookup(tmp_path):
    code, out = run("label", ROUTER)
    assert code == 0 and "Uniswap V2 Router02 (router)" in out
    code, out = run("label", STRANGER, "--json")
    assert json.loads(out) == {"address": STRANGER, "label": None, "kind": None}
    book = write(tmp_path, "b.json", {"labels": {STRANGER: "mine"}})
    assert "mine" in run("label", STRANGER, "--address-book", book)[1]
    assert json.loads(run("label", ROUTER, "--json")[1])["kind"] == "router"


def test_version_and_no_command(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"], io.StringIO())
    assert e.value.code == 0 and f"txwarden {__version__}" in capsys.readouterr().out
    out = io.StringIO()
    assert main([], out) == 3 and "usage: txwarden" in out.getvalue()


def test_mcp_subcommand_serves_stdin(monkeypatch):
    stdin = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n")
    monkeypatch.setattr("sys.stdin", stdin)
    out = io.StringIO()
    assert main(["mcp"], out) == 0
    assert json.loads(out.getvalue()) == {"jsonrpc": "2.0", "id": 1, "result": {}}
