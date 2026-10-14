import json

import pytest

from txwarden.models import (
    AccountInfo,
    CallFrame,
    Finding,
    LPEvent,
    PathSwap,
    Severity,
    SimResult,
    Transfer,
    Tx,
    V3Swap,
    Verdict,
    worst_verdict,
)

from .helpers import EVIL, ROUTER, TOKEN, U


def test_worst_verdict_ordering_and_empty_default():
    assert worst_verdict() == Verdict.ALLOW
    assert worst_verdict(Verdict.ALLOW, Verdict.WARN) == Verdict.WARN
    assert worst_verdict(Verdict.BLOCK, Verdict.WARN, Verdict.ALLOW) == Verdict.BLOCK
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.INFO


def test_tx_from_dict_normalises_and_round_trips():
    tx = Tx.from_dict({"sender": U.upper().replace("0X", "0x"), "to": TOKEN, "value": "5",
                       "chain_id": "10", "data": None})
    assert tx.sender == U and tx.data == "0x" and tx.value == 5 and tx.chain_id == 10
    assert Tx.from_dict(tx.to_dict()) == tx


def test_account_info_properties():
    assert AccountInfo("0x1").is_fresh and not AccountInfo("0x1").is_contract
    assert AccountInfo("0x1", code_size=10).is_contract and not AccountInfo("0x1", 10).is_fresh
    assert not AccountInfo("0x1", nonce=1).is_fresh and not AccountInfo("0x1", balance=1).is_fresh


def test_lp_event_fraction():
    assert LPEvent("remove", "p", 25.0, 100.0).fraction == 0.25
    assert LPEvent("remove", "p", 250.0, 100.0).fraction == 1.0  # clamped
    assert LPEvent("remove", "p", 5.0, None).fraction is None
    assert LPEvent("remove", "p", 5.0, 0.0).fraction is None


def test_call_frame_accepts_geth_and_native_layouts():
    raw = {"type": "call", "from": U.upper().replace("0X", "0x"), "to": ROUTER, "value": "0x10",
           "input": "0xa9059cbb" + "00" * 64, "error": "execution reverted",
           "calls": [{"type": "DELEGATECALL", "from": ROUTER, "to": EVIL, "calls": None}]}
    f = CallFrame.from_dict(raw)
    assert f.kind == "CALL" and f.sender == U and f.value == 16 and f.error
    assert f.selector == "0xa9059cbb" and f.calls[0].kind == "DELEGATECALL"
    assert CallFrame.from_dict(f.to_dict()).to_dict() == f.to_dict()
    assert CallFrame.from_dict({"value": "7", "kind": "create"}).value == 7
    assert CallFrame("CALL", U, ROUTER, input="0x12").selector == "0x12"
    assert [d for d, _ in f.walk()] == [0, 1]


def test_sim_result_json_round_trip_with_every_field_populated():
    sim = SimResult.from_dict({
        "success": True, "gas_used": 5, "revert_reason": None,
        "approvals": [{"token": TOKEN, "owner": U, "spender": EVIL, "amount": 1, "via": "permit2",
                       "expiration": 9}],
        "transfers": [{"token": TOKEN, "sender": U, "recipient": EVIL, "amount": 2,
                       "sender_balance_before": 10, "kind": "erc20", "operator": None}],
        "swap": {"amount_in": 1.0, "min_out": 1.0, "reserve_in": 5.0, "reserve_out": 5.0},
        "path_swap": {"amount_in": 1.0, "min_out": 0.5,
                      "hops": [{"reserve_in": 5.0, "reserve_out": 5.0}]},
        "swap_v3": {"amount_in": 1.0, "min_out": 0.5, "sqrt_price": 2.0, "liquidity": 9.0,
                    "ticks": [{"tick": 5, "liquidity_net": -3.0}]},
        "operator_approvals": [{"token": TOKEN, "owner": U, "operator": EVIL, "approved": True}],
        "permits": [{"token": TOKEN, "owner": U, "spender": EVIL, "amount": 3, "deadline": 4}],
        "lp_events": [{"action": "remove", "pool": "p", "liquidity": 1.0, "pool_total": 2.0}],
        "accounts": {EVIL.upper().replace("0X", "0x"): {"address": EVIL, "code_size": 3}},
        "honeypot": {"mode": "simulate", "buy_ok": True, "sell_ok": False, "amount_in": 1.0,
                     "bought": 2.0, "returned": 0.0, "loss_fraction": 1.0},
        "call_tree": {"type": "CALL", "from": U, "to": ROUTER, "calls": []},
        "chain_id": 1, "block_timestamp": 5, "call_kind": "erc20_approve", "decoded": {"a": 1},
        "eth_receive_reverts": False, "labels": {EVIL: "evil"},
    })
    assert EVIL in sim.accounts and sim.swap_v3.ticks[0].tick == 5
    again = SimResult.from_dict(json.loads(json.dumps(sim.to_dict())))
    assert again.to_dict() == sim.to_dict()
    assert sim.all_counterparties() == {EVIL}
    assert PathSwap.from_dict(sim.path_swap.__dict__ | {"hops": [{"reserve_in": 1, "reserve_out": 2}]})
    assert V3Swap.from_dict({"amount_in": 1, "min_out": 0, "sqrt_price": 1, "liquidity": 1}).fee == 0.003


def test_transfer_defaults_and_finding_round_trip():
    t = Transfer(TOKEN, U, EVIL, 5)
    assert t.kind == "erc20" and t.operator is None and t.sender_balance_before is None
    f = Finding("RULE", Severity.HIGH, "msg", {"k": 1})
    assert Finding.from_dict(f.to_dict()) == f and f.to_dict()["severity"] == "HIGH"
    with pytest.raises(KeyError):
        Finding.from_dict({"rule": "x", "severity": "NOPE", "message": ""})


@pytest.mark.parametrize("raw,fragment", [
    ({"sender": U}, "missing to"),
    ({"to": TOKEN}, "missing sender"),
    ({}, "missing sender and to"),
    ({"sender": "0x1234", "to": TOKEN}, "sender '0x1234' is not a 20-byte hex address"),
    ({"sender": U, "to": "vitalik.eth"}, "to 'vitalik.eth'"),
    ({"sender": U, "to": "0x" + "zz" * 20}, "20-byte hex address"),
])
def test_tx_validation_messages_name_the_problem(raw, fragment):
    with pytest.raises(ValueError, match=fragment):
        Tx.from_dict(raw)
