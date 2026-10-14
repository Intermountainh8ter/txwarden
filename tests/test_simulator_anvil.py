"""AnvilSimulator end to end against an in-memory JSON-RPC chain (``FakeChain``)."""
import json

import pytest

from txwarden.abi import encode_call
from txwarden.models import Tx
from txwarden.risk import PolicyConfig
from txwarden.simulator import (
    AnvilSimulator,
    FixtureSimulator,
    RecordingTransport,
    RpcError,
    SimulatorOptions,
    StaticSimulator,
    decode_revert,
    http_transport,
    replay_transport,
)

from .helpers import (
    EVIL,
    FRIEND,
    NFPM,
    OTHER,
    ROUTER,
    STRANGER,
    TOKEN,
    USDC,
    WETH,
    E,
    FakeChain,
    U,
    V3PoolState,
    approve_calldata,
    error_data,
    revert,
    set_approval_for_all_calldata,
    transfer_calldata,
    v2_swap_calldata,
    v3_single_calldata,
)

PAIR = "0x" + "99" * 20
POOL = "0x" + "98" * 20


def sim_for(chain: FakeChain, **opts) -> AnvilSimulator:
    return AnvilSimulator(transport=chain.rpc, options=SimulatorOptions(**opts))


def basic_chain() -> FakeChain:
    c = FakeChain()
    c.add_token(TOKEN, {U: 10**24})
    c.add_token(USDC, {U: 10**12})
    c.add_token(WETH)
    c.contract(ROUTER)
    c.add_pair(WETH, TOKEN, PAIR, 1000 * E, 2_000_000 * E)
    return c


# --------------------------------------------------------------------------- basics

def test_environment_fields_and_gas():
    c = basic_chain()
    c.chain_id, c.timestamp = 10, 1_800_000_000
    c.gas["0x095ea7b3"] = 46_123
    r = sim_for(c).simulate(Tx(U, TOKEN, approve_calldata(STRANGER, 5)))
    assert r.success and r.gas_used == 46_123
    assert r.chain_id == 10 and r.block_timestamp == 1_800_000_000
    assert r.call_kind == "erc20_approve" and r.decoded["args"]["amount"] == 5
    assert r.approvals[0].spender == STRANGER


def test_account_probe_marks_fresh_and_contract_counterparties():
    c = basic_chain()
    c.nonces[FRIEND], c.eth_balances[FRIEND] = 4, 10**18
    r = sim_for(c).simulate(Tx(U, TOKEN, transfer_calldata(STRANGER, 5)))
    assert r.accounts[STRANGER].is_fresh and not r.accounts[STRANGER].is_contract
    assert r.accounts[TOKEN].is_contract and r.accounts[TOKEN].code_size == 5
    r = sim_for(c).simulate(Tx(U, TOKEN, transfer_calldata(FRIEND, 5)))
    assert not r.accounts[FRIEND].is_fresh and U not in r.accounts


def test_account_probe_can_be_disabled():
    r = sim_for(basic_chain(), account_probe=False).simulate(
        Tx(U, TOKEN, transfer_calldata(STRANGER, 5)))
    assert r.accounts == {}


def test_erc20_transfer_gets_sender_balance_from_chain():
    r = sim_for(basic_chain()).simulate(Tx(U, TOKEN, transfer_calldata(STRANGER, 10**23)))
    t = r.transfers[0]
    assert t.sender_balance_before == 10**24 and t.amount == 10**23


def test_eth_value_transfer_is_recorded_with_balance():
    c = basic_chain()
    c.eth_balances[U] = 5 * E
    r = sim_for(c).simulate(Tx(U, STRANGER, "0x", E))
    t = r.transfers[0]
    assert t.kind == "eth" and t.amount == E and t.sender_balance_before == 5 * E


def test_set_approval_for_all_is_extracted():
    r = sim_for(basic_chain()).simulate(Tx(U, TOKEN, set_approval_for_all_calldata(EVIL)))
    assert r.operator_approvals[0].operator == EVIL


# --------------------------------------------------------------------------- reverts

def test_revert_reason_is_decoded_from_error_data():
    c = basic_chain()
    c.reverts[(TOKEN, "0xa9059cbb")] = "ERC20: transfer amount exceeds balance"
    r = sim_for(c).simulate(Tx(U, TOKEN, transfer_calldata(STRANGER, 1)))
    assert not r.success
    assert r.revert_reason == "ERC20: transfer amount exceeds balance"
    assert r.gas_used == 0 and r.eth_receive_reverts is None


def test_reverting_payable_call_probes_plain_eth_receive():
    c = basic_chain()
    c.reverts[(ROUTER, "0x7ff36ab5")] = "nope"
    c.reject_eth.add(ROUTER)
    data = encode_call("swapExactETHForTokens(uint256,address[],address,uint256)",
                       [0, [WETH, TOKEN], U, 2**40])
    r = sim_for(c).simulate(Tx(U, ROUTER, data, E))
    assert not r.success and r.eth_receive_reverts is True
    c.reject_eth.clear()
    r = sim_for(c).simulate(Tx(U, ROUTER, data, E))
    assert not r.success and r.eth_receive_reverts is False


def test_custom_transport_error_message_is_used_as_reason():
    def rpc(method, params):
        if method == "eth_call":
            raise RuntimeError("boom")
        return "0x1"
    r = AnvilSimulator(transport=rpc).simulate(Tx(U, TOKEN, "0x"))
    assert not r.success and r.revert_reason == "boom"


def test_missing_optional_methods_degrade_instead_of_failing():
    c = basic_chain()
    c.supports_trace = False
    c.supports_simulate = False

    def rpc(method, params):
        if method in ("eth_chainId", "eth_getBlockByNumber", "eth_getCode"):
            raise RpcError("Method not found", -32601)
        return c.rpc(method, params)

    r = AnvilSimulator(transport=rpc).simulate(Tx(U, TOKEN, approve_calldata(STRANGER, 5)))
    assert r.success and r.chain_id is None and r.block_timestamp is None
    assert r.accounts == {} and r.call_tree is None


def test_constructor_requires_a_backend():
    with pytest.raises(ValueError):
        AnvilSimulator()
    sim = AnvilSimulator(rpc_url="http://127.0.0.1:1", v2_factory="0x" + "AB" * 20)
    assert sim.factory == "0x" + "ab" * 20


# --------------------------------------------------------------------------- V2 swaps

def test_v2_swap_reserve_orientation_in_both_directions():
    c = basic_chain()
    sim = sim_for(c, honeypot=False)
    r = sim.simulate(Tx(U, ROUTER, v2_swap_calldata(10 * E, 1, [TOKEN, WETH])))
    assert r.swap.reserve_in == pytest.approx(2_000_000 * E)
    assert r.swap.reserve_out == pytest.approx(1000 * E)
    r = sim.simulate(Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN])))
    assert r.swap.reserve_in == pytest.approx(1000 * E)
    assert r.swap.reserve_out == pytest.approx(2_000_000 * E)
    assert r.swap.amount_in == E and r.swap.min_out == 1


def test_v2_multihop_builds_a_path_swap():
    c = basic_chain()
    c.add_pair(WETH, USDC, "0x" + "97" * 20, 500 * E, 10**15)
    r = sim_for(c, honeypot=False).simulate(
        Tx(U, ROUTER, v2_swap_calldata(10 * E, 1, [TOKEN, WETH, USDC])))
    assert r.swap is None and len(r.path_swap.hops) == 2
    assert r.path_swap.hops[1].reserve_in == pytest.approx(500 * E)


def test_swap_with_missing_pair_has_no_swap_context():
    c = basic_chain()
    r = sim_for(c, honeypot=False).simulate(
        Tx(U, ROUTER, v2_swap_calldata(10, 1, [TOKEN, OTHER])))
    assert r.swap is None and r.path_swap is None


# --------------------------------------------------------------------------- V3 swaps

def v3_chain(ticks: dict[int, int] | None = None, tick: int = 76_000) -> FakeChain:
    c = basic_chain()
    sqrt_x96 = int(1.0001 ** (tick / 2) * 2**96)
    c.add_v3_pool(USDC, WETH, 500, POOL, V3PoolState(
        sqrt_x96, tick, 10**18, 10, ticks or {}))
    return c


def test_v3_pool_state_and_direction():
    c = v3_chain()
    zero_for_one = int(USDC, 16) < int(WETH, 16)
    r = sim_for(c, honeypot=False).simulate(
        Tx(U, ROUTER, v3_single_calldata(USDC, WETH, 500, 10**6, 1)))
    v3 = r.swap_v3
    assert v3.zero_for_one is zero_for_one and v3.fee == pytest.approx(0.0005)
    assert v3.sqrt_price == pytest.approx(1.0001 ** 38_000, rel=1e-9) and v3.liquidity == 1e18
    assert v3.ticks == ()
    r = sim_for(c, honeypot=False).simulate(
        Tx(U, ROUTER, v3_single_calldata(WETH, USDC, 500, 10**6, 1)))
    assert r.swap_v3.zero_for_one is (not zero_for_one)


def test_v3_initialised_ticks_are_read_from_the_bitmap_including_negative_ticks():
    ticks = {75_960: 5 * 10**17, 76_050: -5 * 10**17, -120: 7, -20_000: -7}
    c = v3_chain(ticks)
    r = sim_for(c, honeypot=False, tick_words=100).simulate(
        Tx(U, ROUTER, v3_single_calldata(USDC, WETH, 500, 10**6, 1)))
    got = {t.tick: t.liquidity_net for t in r.swap_v3.ticks}
    assert got == {75_960: 5e17, 76_050: -5e17, -120: 7.0, -20_000: -7.0}
    assert [t.tick for t in r.swap_v3.ticks] == sorted(got)


def test_v3_tick_scan_can_be_disabled_and_is_bounded():
    ticks = {76_000 + 10 * i: 1 for i in range(1, 30)}
    c = v3_chain(ticks)
    r = sim_for(c, honeypot=False, v3_ticks=False).simulate(
        Tx(U, ROUTER, v3_single_calldata(USDC, WETH, 500, 10**6, 1)))
    assert r.swap_v3.ticks == ()
    r = sim_for(c, honeypot=False, max_ticks=5).simulate(
        Tx(U, ROUTER, v3_single_calldata(USDC, WETH, 500, 10**6, 1)))
    assert len(r.swap_v3.ticks) == 5
    assert min(abs(t.tick - 76_000) for t in r.swap_v3.ticks) == 10  # nearest ticks are kept


def test_v3_missing_pool_leaves_swap_context_empty():
    c = basic_chain()
    r = sim_for(c, honeypot=False).simulate(
        Tx(U, ROUTER, v3_single_calldata(USDC, WETH, 3000, 10**6, 1)))
    assert r.swap_v3 is None


# --------------------------------------------------------------------------- honeypot probe

def buy_tx() -> Tx:
    data = encode_call("swapExactETHForTokens(uint256,address[],address,uint256)",
                       [1, [WETH, TOKEN], U, 2**40])
    return Tx(U, ROUTER, data, E)


def test_honest_token_round_trip_loses_only_fees():
    r = sim_for(basic_chain()).simulate(buy_tx())
    hp = r.honeypot
    assert hp.mode == "simulate" and hp.buy_ok and hp.sell_ok and hp.taxes_observable
    assert 0.005 < hp.loss_fraction < 0.02  # two 0.3% fees plus a little impact
    assert hp.returned < hp.amount_in


def test_honeypot_sell_reverts_in_both_sell_variants():
    c = basic_chain()
    c.tokens[TOKEN].honeypot = True
    hp = sim_for(c).simulate(buy_tx()).honeypot
    assert hp.buy_ok and not hp.sell_ok and hp.loss_fraction == 1.0
    assert "TRANSFER_FAILED" in (hp.sell_revert_reason or "")


def test_fee_on_transfer_token_is_detected_through_the_fot_sell_path():
    c = basic_chain()
    c.tokens[TOKEN].buy_tax = 0.10
    c.tokens[TOKEN].sell_tax = 0.10
    hp = sim_for(c).simulate(buy_tx()).honeypot
    assert hp.buy_ok and hp.sell_ok
    assert "fee-on-transfer" in hp.note and "buy tax 10.0%" in hp.note
    assert hp.loss_fraction > 0.15  # about 1 - 0.9 * 0.9 plus pool fees


def test_buy_tax_only_is_visible_in_the_note():
    c = basic_chain()
    c.tokens[TOKEN].buy_tax = 0.05
    hp = sim_for(c).simulate(buy_tx()).honeypot
    assert hp.sell_ok and "buy tax 5.0%" in hp.note
    assert hp.loss_fraction > 0.05


def test_buy_that_reverts_is_reported():
    c = basic_chain()
    c.pairs.clear()
    hp = sim_for(c).simulate(Tx(
        U, ROUTER, encode_call("swapExactETHForTokens(uint256,address[],address,uint256)",
                               [1, [WETH, OTHER], U, 2**40]), E)).honeypot
    assert hp is not None and not hp.buy_ok and "PAIR_NOT_FOUND" in hp.note


def test_node_without_simulate_v1_falls_back_to_router_quotes():
    c = basic_chain()
    c.supports_simulate = False
    hp = sim_for(c).simulate(buy_tx()).honeypot
    assert hp.mode == "quote" and not hp.taxes_observable and hp.buy_ok and hp.sell_ok
    assert "eth_simulateV1" in hp.note


def test_quote_fallback_reports_unquotable_sell_as_failed():
    c = basic_chain()
    c.supports_simulate = False
    c.reverts[(ROUTER, "0xd06ca61f")] = "no route"
    hp = sim_for(c).simulate(buy_tx()).honeypot
    assert hp.mode == "quote" and not hp.buy_ok


def test_honeypot_probe_skipped_for_known_tokens_and_weth_and_when_disabled():
    c = basic_chain()
    assert sim_for(c, known_tokens={TOKEN.upper().replace("0X", "0x")}).simulate(
        buy_tx()).honeypot is None
    assert sim_for(c, honeypot=False).simulate(buy_tx()).honeypot is None
    weth_out = Tx(U, ROUTER, v2_swap_calldata(10, 1, [TOKEN, WETH]))
    assert sim_for(c).simulate(weth_out).honeypot is None


# --------------------------------------------------------------------------- liquidity

def test_v2_remove_liquidity_reads_pair_total_supply():
    c = basic_chain()
    c.tokens[PAIR] = c.tokens[WETH].__class__(total_supply=10**22)
    data = encode_call("removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
                       [WETH, TOKEN, 6 * 10**21, 0, 0, U, 2**40])
    r = sim_for(c).simulate(Tx(U, ROUTER, data))
    e = r.lp_events[0]
    assert e.action == "remove" and e.pool == PAIR and e.protocol == "v2"
    assert e.pool_total == 10**22 and e.fraction == pytest.approx(0.6)


def test_v2_add_liquidity_event_and_unknown_pair():
    c = basic_chain()
    data = encode_call("addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
                       [WETH, OTHER, 1, 1, 0, 0, U, 2**40])
    r = sim_for(c).simulate(Tx(U, ROUTER, data))
    e = r.lp_events[0]
    assert e.action == "add" and e.pool_total is None


def test_v3_decrease_liquidity_resolves_position_to_pool():
    c = v3_chain()
    c.positions[7] = (USDC, WETH, 500, 10**18)
    data = encode_call("decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
                       [(7, 6 * 10**17, 0, 0, 2**40)])
    r = sim_for(c).simulate(Tx(U, NFPM, data))
    e = r.lp_events[0]
    assert e.protocol == "v3" and e.pool == POOL and e.pool_total == 1e18
    assert e.fraction == pytest.approx(0.6)


def test_v3_decrease_liquidity_with_unknown_position_still_reports_event():
    c = v3_chain()
    data = encode_call("decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
                       [(99, 5, 0, 0, 2**40)])
    e = sim_for(c).simulate(Tx(U, NFPM, data)).lp_events[0]
    assert e.pool == "v3-position-99" and e.pool_total is None and e.fraction is None


# --------------------------------------------------------------------------- trace

def test_call_tree_is_parsed_from_geth_call_tracer_output():
    c = basic_chain()
    c.trace = {"type": "CALL", "from": U, "to": ROUTER, "value": "0x0", "input": "0x12345678",
               "calls": [{"type": "DELEGATECALL", "from": ROUTER, "to": EVIL, "input": "0x",
                          "calls": [{"type": "SELFDESTRUCT", "from": EVIL, "to": OTHER}]}]}
    r = sim_for(c).simulate(Tx(U, TOKEN, approve_calldata(STRANGER, 1)))
    kinds = [(d, f.kind) for d, f in r.call_tree.walk()]
    assert kinds == [(0, "CALL"), (1, "DELEGATECALL"), (2, "SELFDESTRUCT")]
    assert r.call_tree.calls[0].to == EVIL


def test_trace_can_be_disabled_or_unsupported_or_garbage():
    c = basic_chain()
    c.trace = {"type": "CALL", "from": U, "to": TOKEN}
    assert sim_for(c, trace=False).simulate(Tx(U, TOKEN, "0x")).call_tree is None
    c.supports_trace = False
    assert sim_for(c).simulate(Tx(U, TOKEN, "0x")).call_tree is None
    c.supports_trace = True
    c.trace = {"unexpected": True}
    assert sim_for(c).simulate(Tx(U, TOKEN, "0x")).call_tree is None


# --------------------------------------------------------------------------- transports

def test_decode_revert_variants():
    assert decode_revert(error_data("hi")) == "hi"
    assert decode_revert("0x4e487b71" + "00" * 31 + "11") == "Panic(0x11)"
    assert decode_revert({"data": error_data("nested")}) == "nested"
    assert decode_revert(None) is None and decode_revert("0x") is None
    assert decode_revert("0x08c379a0ff") is None  # truncated
    assert revert("x").revert_reason() == "x"
    assert RpcError("plain", 3, None).revert_reason() == "plain"
    assert RpcError("The method eth_foo does not exist").unsupported
    assert RpcError("whatever", -32601).unsupported and not RpcError("whatever", 3).unsupported


def test_recording_then_replaying_a_session_gives_the_same_result(tmp_path):
    c = basic_chain()
    rec = RecordingTransport(c.rpc)
    tx = Tx(U, ROUTER, v2_swap_calldata(10 * E, 1, [TOKEN, WETH]))
    live = AnvilSimulator(transport=rec, options=SimulatorOptions(honeypot=False)).simulate(tx)
    path = tmp_path / "session.json"
    rec.save(path, "unit test session")
    assert json.loads(path.read_text())["description"] == "unit test session"
    replayed = AnvilSimulator(transport=replay_transport(path),
                              options=SimulatorOptions(honeypot=False)).simulate(tx)
    assert replayed.to_dict() == live.to_dict()
    with pytest.raises(RpcError):
        replay_transport(path)("eth_call", [{"to": "0x00"}, "latest"])


def test_recording_transport_records_errors_and_reraises(tmp_path):
    c = basic_chain()
    c.reverts[(TOKEN, "0xa9059cbb")] = "bad"
    rec = RecordingTransport(c.rpc)
    r = AnvilSimulator(transport=rec).simulate(Tx(U, TOKEN, transfer_calldata(STRANGER, 1)))
    assert not r.success
    assert any("error" in x for x in rec.records)
    rec.save(tmp_path / "s.json")
    replay = replay_transport(tmp_path / "s.json")
    with pytest.raises(RpcError) as ei:
        replay("eth_call", [{"from": U, "to": TOKEN, "data": transfer_calldata(STRANGER, 1),
                             "value": "0x0"}, "latest"])
    assert ei.value.revert_reason() == "bad"


def test_fixture_and_static_simulators(tmp_path):
    from txwarden.models import SimResult

    sim = SimResult(True, gas_used=5)
    path = tmp_path / "f.json"
    path.write_text(json.dumps({"0xaa": sim.to_dict()}))
    fs = FixtureSimulator.from_json(path)
    assert fs.simulate(Tx(U, TOKEN, "0xaa")).gas_used == 5
    with pytest.raises(KeyError):
        fs.simulate(Tx(U, TOKEN, "0xbb"))

    r = StaticSimulator().simulate(Tx(U, TOKEN, approve_calldata(EVIL, 3), 7))
    assert r.approvals[0].spender == EVIL
    assert [t.kind for t in r.transfers] == ["eth"]  # attached value is a transfer to tx.to
    swap = StaticSimulator().simulate(Tx(U, ROUTER, v2_swap_calldata(1, 1, [TOKEN, WETH])))
    assert swap.swap is None and swap.call_kind == "v2_swap_exact_tokens_for_tokens"
    lp = StaticSimulator().simulate(Tx(U, ROUTER, encode_call(
        "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
        [WETH, TOKEN, 9, 0, 0, U, 2**40])))
    assert lp.lp_events[0].action == "remove" and lp.lp_events[0].pool_total is None


def test_http_transport_errors_are_wrapped():
    call = http_transport("http://127.0.0.1:1", timeout=0.5)
    with pytest.raises(RpcError, match="cannot reach"):
        call("eth_chainId", [])


# --------------------------------------------------------------------------- fail-closed behaviour

def test_transport_failure_is_reported_as_unavailable_not_as_a_revert():
    from txwarden.risk import assess

    def rpc(method, params):
        raise RpcError("cannot reach http://127.0.0.1:8545: [Errno 111] Connection refused",
                       transport=True)

    r = AnvilSimulator(transport=rpc).simulate(Tx(U, TOKEN, approve_calldata(EVIL, 2**255)))
    assert not r.success and r.revert_reason is None and "Connection refused" in r.error
    assert r.approvals == [] and r.call_kind == "erc20_approve"
    verdict, findings = assess(Tx(U, TOKEN), r)
    assert verdict.value == "BLOCK" and [f.rule for f in findings] == ["SIMULATION_UNAVAILABLE"]


@pytest.mark.parametrize("message,code", [
    ("missing trie node 0xabc (path )", -32000), ("header not found", -32000),
    ("daily request count exceeded, request rate limited", -32005),
    ("HTTP 502 from https://rpc", 502), ("Too Many Requests", 429),
])
def test_node_side_infrastructure_errors_are_not_reverts(message, code):
    def rpc(method, params):
        if method == "eth_call":
            raise RpcError(message, code)
        return "0x1"

    r = AnvilSimulator(transport=rpc).simulate(Tx(U, TOKEN, "0x"))
    assert r.error == message and not r.success


def test_a_revert_that_mentions_infrastructure_words_is_still_a_revert():
    c = basic_chain()
    c.reverts[(TOKEN, "0xa9059cbb")] = "rate limit exceeded for this account"
    r = sim_for(c).simulate(Tx(U, TOKEN, transfer_calldata(STRANGER, 1)))
    assert r.error is None and not r.success and "rate limit" in r.revert_reason
    assert RpcError("execution reverted: timeout", 3).infrastructure is False
    assert RpcError("request timed out", None).infrastructure is True
    assert RpcError("boom", transport=True).infrastructure is True


def test_gas_estimation_failure_on_infrastructure_is_also_unavailable():
    def rpc(method, params):
        if method == "eth_estimateGas":
            raise RpcError("service unavailable", 503, transport=True)
        return "0x"

    assert AnvilSimulator(transport=rpc).simulate(Tx(U, TOKEN, "0x")).error == "service unavailable"


# --------------------------------------------------------------------------- incomplete analysis

def test_missing_pool_marks_swap_state_incomplete_and_assessment_warns():
    from txwarden.risk import assess

    c = basic_chain()
    tx = Tx(U, ROUTER, v2_swap_calldata(10, 1, [TOKEN, OTHER]))
    r = sim_for(c, honeypot=False).simulate(tx)
    assert any(x.startswith("swap_state") for x in r.incomplete)
    verdict, findings = assess(tx, r)
    assert verdict.value == "WARN" and "ANALYSIS_INCOMPLETE" in {f.rule for f in findings}


def test_second_swap_in_a_universal_router_call_is_flagged_as_unassessed():
    from txwarden.abi import encode, encode_v3_path

    from .helpers import ur_calldata

    path = encode_v3_path([USDC, WETH], [500])
    swap = "0x" + encode(["address", "uint256", "uint256", "bytes", "bool"],
                         [U, 100, 90, path, True]).hex()
    c = v3_chain()
    r = sim_for(c, honeypot=False).simulate(Tx(U, ROUTER, ur_calldata(bytes([0, 0]), [swap, swap])))
    assert r.swap_v3 is not None
    assert any("only the first of 2 swaps" in x for x in r.incomplete)


def test_lp_removal_without_pool_totals_is_flagged():
    c = basic_chain()
    data = encode_call("removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
                       [WETH, OTHER, 5, 0, 0, U, 2**40])
    r = sim_for(c).simulate(Tx(U, ROUTER, data))
    assert any(x.startswith("lp_state") for x in r.incomplete)


def test_skipped_optional_probes_are_listed_for_transparency():
    c = basic_chain()
    c.supports_trace = False

    def rpc(method, params):
        if method == "eth_getCode":
            raise RpcError("Method not found", -32601)
        return c.rpc(method, params)

    r = AnvilSimulator(transport=rpc).simulate(Tx(U, TOKEN, approve_calldata(STRANGER, 5)))
    assert set(r.incomplete) == {"account_probe", "call_trace"}
    clean = basic_chain()
    clean.trace = {"type": "CALL", "from": U, "to": TOKEN}
    assert sim_for(clean).simulate(Tx(U, TOKEN, approve_calldata(STRANGER, 5))).incomplete == []


def test_static_simulator_declares_what_it_could_not_check():
    sim = StaticSimulator()
    approve = sim.simulate(Tx(U, TOKEN, approve_calldata(EVIL, 5)))
    assert approve.incomplete == ["chain_state"]
    swap = sim.simulate(Tx(U, ROUTER, v2_swap_calldata(1, 1, [TOKEN, WETH])))
    assert [x.split(":")[0] for x in swap.incomplete] == ["chain_state", "swap_state"]
    lp = sim.simulate(Tx(U, ROUTER, encode_call(
        "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
        [WETH, TOKEN, 9, 0, 0, U, 2**40])))
    assert [x.split(":")[0] for x in lp.incomplete] == ["chain_state", "lp_state"]


# --------------------------------------------------------------------------- output and trace

def test_swap_output_recipients_are_recorded_and_flagged():
    from txwarden.risk import assess

    c = basic_chain()
    tx = Tx(U, ROUTER, v2_swap_calldata(10 * E, 1, [TOKEN, WETH], to=STRANGER))
    r = sim_for(c, honeypot=False).simulate(tx)
    assert r.output_recipients == [STRANGER]
    assert "SWAP_RECIPIENT_MISMATCH" in {f.rule for f in assess(tx, r)[1]}
    own = sim_for(c, honeypot=False).simulate(Tx(U, ROUTER, v2_swap_calldata(10, 1, [TOKEN, WETH])))
    assert own.output_recipients == [U]
    assert "SWAP_RECIPIENT_MISMATCH" not in {f.rule for f in assess(Tx(U, ROUTER), own)[1]}


def test_universal_router_sweep_to_a_stranger_is_seen():
    from txwarden.abi import encode

    from .helpers import ur_calldata

    sweep = "0x" + encode(["address", "address", "uint256"], [USDC, STRANGER, 0]).hex()
    r = sim_for(basic_chain()).simulate(Tx(U, ROUTER, ur_calldata(bytes([0x04]), [sweep])))
    assert r.output_recipients == [STRANGER]


def test_trace_derived_token_pull_is_added_with_balance_and_recipient_probe():
    from txwarden.risk import assess

    claim, helper = "0x" + "d1" * 20, "0x" + "d3" * 20
    pull = encode_call("transferFrom(address,address,uint256)", [U, EVIL, 95 * 10**22])
    c = basic_chain()
    c.contract(claim)
    c.trace = {"type": "CALL", "from": U, "to": claim, "input": "0x4e71d92d", "calls": [
        {"type": "CALL", "from": claim, "to": helper, "input": "0x", "calls": [
            {"type": "CALL", "from": helper, "to": TOKEN, "input": pull},
            {"type": "STATICCALL", "from": helper, "to": TOKEN, "input": pull},
            {"type": "CALL", "from": helper, "to": TOKEN, "input": pull, "error": "reverted"}]}]}
    tx = Tx(U, claim, "0x4e71d92d")
    r = sim_for(c, honeypot=False).simulate(tx)
    pulls = [t for t in r.transfers if t.recipient == EVIL]
    assert len(pulls) == 1  # static-call and failed frames are not movements
    t = pulls[0]
    assert t.sender == U and t.operator == helper and t.sender_balance_before == 10**24
    assert EVIL in r.accounts and r.accounts[EVIL].is_fresh
    verdict, findings = assess(tx, r, PolicyConfig(denylist=set()))
    rules = {f.rule for f in findings}
    assert {"UNTRUSTED_PULL_IN_TRACE", "NEAR_FULL_BALANCE_TO_NEW_ADDRESS",
            "TRANSFER_TO_FRESH_ADDRESS"} <= rules
    assert verdict.value == "WARN"


def test_trace_pull_already_visible_in_calldata_is_not_double_counted():
    pull = encode_call("transferFrom(address,address,uint256)", [U, STRANGER, 5])
    c = basic_chain()
    c.trace = {"type": "CALL", "from": U, "to": TOKEN, "input": pull, "calls": [
        {"type": "CALL", "from": TOKEN, "to": TOKEN, "input": pull}]}
    r = sim_for(c).simulate(Tx(U, TOKEN, pull))
    assert len([t for t in r.transfers if t.recipient == STRANGER]) == 1
