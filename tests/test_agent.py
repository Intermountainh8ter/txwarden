from txwarden.agent import TxWardenAgent
from txwarden.llm import Reply, ScriptedLLM
from txwarden.models import Approval, SimResult, Tx, Verdict
from txwarden.risk import UNLIMITED, PolicyConfig
from txwarden.simulator import FixtureSimulator

U = "0x" + "11" * 20
TOKEN = "0x" + "cc" * 20
BAD = "0x" + "bb" * 20
TX = Tx(sender=U, to=TOKEN, data="0xfixture")
SIM = FixtureSimulator({"0xfixture": SimResult(True, approvals=[Approval(TOKEN, U, BAD, UNLIMITED)])})


def use(i, name):
    return {"type": "tool_use", "id": i, "name": name, "input": {}}


def test_agent_blocks_even_if_model_says_proceed():
    llm = ScriptedLLM([
        Reply([use("1", "simulate_transaction")], "tool_use"),
        Reply([use("2", "assess_risk")], "tool_use"),
        Reply([{"type": "text", "text": "Looks fine, go ahead and sign!"}], "end_turn"),
    ])
    r = TxWardenAgent(llm, SIM, PolicyConfig()).review(TX, "approve usdc")
    assert r.verdict == Verdict.BLOCK
    assert r.tool_calls == ["simulate_transaction", "assess_risk"]
    assert any(f.rule == "UNLIMITED_APPROVAL_UNKNOWN" for f in r.findings)


def test_agent_fails_closed_if_model_skips_assessment():
    llm = ScriptedLLM([Reply([{"type": "text", "text": "All good."}], "end_turn")])
    r = TxWardenAgent(llm, SIM).review(TX)
    assert r.verdict == Verdict.BLOCK


def test_assess_before_simulate_returns_error_not_verdict():
    llm = ScriptedLLM([
        Reply([use("1", "assess_risk")], "tool_use"),
        Reply([{"type": "text", "text": "done"}], "end_turn"),
    ])
    r = TxWardenAgent(llm, SIM).review(TX)
    assert r.verdict == Verdict.BLOCK  # no valid assessment -> fail closed
    assert "error" in llm.calls[1][-1]["content"][0]["content"]
