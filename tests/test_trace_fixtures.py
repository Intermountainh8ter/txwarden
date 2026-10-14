"""Call-tree rules against JSON trace fixtures shaped like geth's ``callTracer`` output.

The fixtures in ``tests/fixtures`` are hand-written and use synthetic addresses for the unknown
contracts; they are NOT recordings from a node (each file says so in its ``description``).
"""
import json
from pathlib import Path

import pytest

from txwarden.effects import trace_transfers
from txwarden.models import CallFrame, SimResult, Tx, Verdict
from txwarden.risk import PolicyConfig, assess

FIXTURES = Path(__file__).parent / "fixtures"
U = "0x" + "11" * 20
ATTACKER = "0x" + "de" * 20
IMPL = "0x" + "c2" * 20
LIB = "0x" + "d2" * 20
ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
HELPER = "0x" + "d3" * 20


def load(name: str) -> tuple[Tx, SimResult]:
    raw = json.loads((FIXTURES / f"{name}.json").read_text())
    assert raw["synthetic"] is True and raw["description"]
    tree = CallFrame.from_dict(raw["tree"])
    tx = Tx(U, tree.to)
    return tx, SimResult(True, call_tree=tree, transfers=trace_transfers(tx, tree))


def rules(findings) -> set[str]:
    return {f.rule for f in findings}


def test_benign_swap_trace_has_no_trace_findings():
    tx, sim = load("trace_v2_swap_benign")
    verdict, findings = assess(tx, sim, PolicyConfig(address_book={ROUTER: "router"}))
    assert verdict == Verdict.ALLOW and findings == []
    assert [f.kind for _, f in sim.call_tree.walk()].count("STATICCALL") == 3
    assert sim.transfers == []  # the pair/router moving *their* tokens is not the user's loss


def test_proxy_delegatecall_is_medium_and_silenced_by_trusting_the_implementation():
    tx, sim = load("trace_proxy_token_approve")
    verdict, findings = assess(tx, sim, PolicyConfig())
    assert verdict == Verdict.ALLOW and rules(findings) == {"PROXY_DELEGATECALL_UNKNOWN_IMPL"}
    _, findings = assess(tx, sim, PolicyConfig(trusted_implementations={IMPL}))
    assert findings == []


def test_nested_delegatecall_to_unknown_code_blocks_and_the_pull_is_found():
    tx, sim = load("trace_drainer_delegatecall")
    verdict, findings = assess(tx, sim, PolicyConfig())
    assert verdict == Verdict.BLOCK
    deleg = next(f for f in findings if f.rule == "DELEGATECALL_TO_UNKNOWN")
    assert deleg.data["to"] == LIB and deleg.data["depth"] == 2
    pull = next(f for f in findings if f.rule == "UNTRUSTED_PULL_IN_TRACE")
    assert pull.data["recipient"] == ATTACKER and pull.data["operator"] == HELPER
    # trusting the library alone would still leave the token pull flagged
    _, findings = assess(tx, sim, PolicyConfig(trusted_implementations={LIB}))
    assert "DELEGATECALL_TO_UNKNOWN" not in rules(findings)


def test_proxy_shaped_claim_contract_is_caught_by_the_token_pull_not_the_delegatecall():
    tx, sim = load("trace_claim_proxy_pull")
    verdict, findings = assess(tx, sim, PolicyConfig())
    assert rules(findings) == {"PROXY_DELEGATECALL_UNKNOWN_IMPL", "UNTRUSTED_PULL_IN_TRACE"}
    assert verdict == Verdict.WARN  # HIGH: pulls need a balance/denylist hit to become CRITICAL
    # once the attacker is denylisted (or the balance is known to be drained) it blocks
    assert assess(tx, sim, PolicyConfig(denylist={ATTACKER}))[0] == Verdict.BLOCK
    # and trusting the claim contract as a spender is the documented way to accept the pull
    assert "UNTRUSTED_PULL_IN_TRACE" not in rules(
        assess(tx, sim, PolicyConfig(trusted_spenders={tx.to}))[1])


def test_selfdestruct_blocks():
    tx, sim = load("trace_selfdestruct")
    verdict, findings = assess(tx, sim, PolicyConfig())
    assert verdict == Verdict.BLOCK and "SELFDESTRUCT_IN_TRACE" in rules(findings)
    hit = next(f for f in findings if f.rule == "SELFDESTRUCT_IN_TRACE")
    assert hit.data == {"depth": 2, "from": LIB, "to": ATTACKER, "kind": "SELFDESTRUCT"}


def test_create2_warns_and_can_be_switched_off():
    tx, sim = load("trace_create2_factory")
    verdict, findings = assess(tx, sim, PolicyConfig())
    assert verdict == Verdict.WARN and rules(findings) == {"CONTRACT_CREATION_IN_TRACE"}
    assert assess(tx, sim, PolicyConfig(flag_contract_creation=False))[1] == []


def test_denylisted_address_deep_in_the_tree_blocks():
    tx, sim = load("trace_denylisted_nested")
    verdict, findings = assess(tx, sim, PolicyConfig(denylist={ATTACKER}))
    assert verdict == Verdict.BLOCK and "DENYLISTED_IN_TRACE" in rules(findings)
    assert assess(tx, sim, PolicyConfig())[0] == Verdict.ALLOW


def test_frame_errors_parse_and_do_not_change_the_verdict():
    tx, sim = load("trace_reverted_frame_with_error")
    assert sim.call_tree.calls[0].error == "execution reverted"
    assert assess(tx, sim, PolicyConfig())[0] == Verdict.ALLOW


@pytest.mark.parametrize("name", sorted(p.stem for p in FIXTURES.glob("trace_*.json")))
def test_every_fixture_round_trips_through_the_model(name):
    _, sim = load(name)
    again = CallFrame.from_dict(sim.call_tree.to_dict())
    assert again.to_dict() == sim.call_tree.to_dict()
