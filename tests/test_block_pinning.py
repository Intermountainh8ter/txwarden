"""Block pinning: the same transaction gets the state of the block it is pinned to."""
import pytest

from txwarden.abi import encode_call
from txwarden.amm import amount_out
from txwarden.models import Tx, Verdict
from txwarden.risk import PolicyConfig, assess
from txwarden.simulator import (
    AnvilSimulator,
    RecordingTransport,
    RpcError,
    SimulatorOptions,
    http_transport,
    normalize_block,
    replay_transport,
)

from .fake_history import HistoricalChain
from .fake_rpc import FakeRpcServer
from .helpers import (
    ROUTER,
    TOKEN,
    USDC,
    WETH,
    E,
    FakeChain,
    U,
    approve_calldata,
    v2_swap_calldata,
)

PAIR = "0x" + "99" * 20
SWAP_ETH = encode_call("swapExactETHForTokens(uint256,address[],address,uint256)",
                       [0, [WETH, TOKEN], U, 2**40])


def pool_chain(weth_reserve: int, token_reserve: int, timestamp: int) -> FakeChain:
    c = FakeChain(timestamp=timestamp)
    c.add_token(TOKEN, {U: 10**24})
    c.add_token(USDC, {U: 10**12})
    c.add_token(WETH)
    c.contract(ROUTER)
    c.add_pair(WETH, TOKEN, PAIR, weth_reserve, token_reserve)
    c.eth_balances[U] = 5 * E
    return c


def two_block_world() -> HistoricalChain:
    """Block 99: a deep pool. Block 100: someone moved the price and drained most of the pool."""
    h = HistoricalChain(head=101)
    h.set_state(90, pool_chain(1000 * E, 2_000_000 * E, 1_700_000_000))
    h.set_state(100, pool_chain(10 * E, 20_000 * E, 1_700_001_200))
    return h


def sim_at(h: HistoricalChain, block) -> AnvilSimulator:
    return AnvilSimulator(transport=h.rpc, block=block, options=SimulatorOptions(trace=False))


# --------------------------------------------------------------------------- normalisation

@pytest.mark.parametrize("given,expected", [
    ("latest", "latest"), ("LATEST", "latest"), ("  latest ", "latest"),
    (0, "0x0"), (255, "0xff"), (19_000_000, "0x121eac0"),
    ("0xff", "0xff"), ("0xFF", "0xff"), ("0x00ff", "0xff"), ("0x0", "0x0"), ("0X10", "0x10"),
])
def test_normalize_block_accepts_latest_ints_and_hex(given, expected):
    assert normalize_block(given) == expected


@pytest.mark.parametrize("bad", [-1, True, False, "pending", "safe", "finalized", "earliest", "",
                                 "123", "0x", "0xzz", "0x-1", 1.5, None, b"0x1", "latest!"])
def test_normalize_block_rejects_everything_else(bad):
    with pytest.raises(ValueError, match="block"):
        normalize_block(bad)


def test_normalize_block_error_does_not_echo_unbounded_input():
    with pytest.raises(ValueError) as e:
        normalize_block("x" * 5000)
    assert len(str(e.value)) < 200


def test_constructor_normalises_and_validates_the_block():
    assert AnvilSimulator(transport=lambda m, p: None).block == "latest"
    assert AnvilSimulator(transport=lambda m, p: None, block=100).block == "0x64"
    assert AnvilSimulator(transport=lambda m, p: None, block="0x0064").block == "0x64"
    with pytest.raises(ValueError):
        AnvilSimulator(transport=lambda m, p: None, block="pending")


# --------------------------------------------------------------------------- request shapes

def block_params(log):
    """(method, block argument) for every logged request that carries one."""
    pos = {"eth_call": 1, "eth_getCode": 1, "eth_getBalance": 1, "eth_getTransactionCount": 1,
           "eth_simulateV1": 1, "debug_traceCall": 1, "eth_getBlockByNumber": 0}
    return [(m, p[pos[m]]) for m, p in log if m in pos]


def swap_world() -> FakeChain:
    c = pool_chain(1000 * E, 2_000_000 * E, 1_700_000_000)
    c.trace = {"type": "CALL", "from": U, "to": ROUTER, "value": "0x0", "input": "0x",
               "calls": []}
    return c


def test_default_requests_use_latest_and_estimate_gas_has_no_block_argument():
    c = swap_world()
    AnvilSimulator(transport=c.rpc).simulate(Tx(U, ROUTER, SWAP_ETH, E))
    seen = block_params(c.log)
    assert {m for m, _ in seen} == {"eth_call", "eth_getCode", "eth_getBalance",
                                    "eth_getTransactionCount", "eth_simulateV1",
                                    "debug_traceCall", "eth_getBlockByNumber"}
    assert {b for _, b in seen} == {"latest"}
    estimates = [p for m, p in c.log if m == "eth_estimateGas"]
    assert estimates and all(len(p) == 1 for p in estimates)


def test_every_state_request_carries_the_pinned_block():
    c = swap_world()
    AnvilSimulator(transport=c.rpc, block=1234).simulate(Tx(U, ROUTER, SWAP_ETH, E))
    seen = block_params(c.log)
    assert {m for m, _ in seen} == {"eth_call", "eth_getCode", "eth_getBalance",
                                    "eth_getTransactionCount", "eth_simulateV1",
                                    "debug_traceCall", "eth_getBlockByNumber"}
    assert {b for _, b in seen} == {"0x4d2"}
    assert next(p for m, p in c.log if m == "eth_estimateGas")[1] == "0x4d2"
    assert "latest" not in repr(c.log)


def test_pinned_revert_probe_for_plain_eth_receive_is_pinned_too():
    c = swap_world()
    c.reverts[(ROUTER, "0x7ff36ab5")] = "nope"
    c.reject_eth.add(ROUTER)
    res = AnvilSimulator(transport=c.rpc, block=77).simulate(Tx(U, ROUTER, SWAP_ETH, E))
    assert not res.success and res.eth_receive_reverts is True
    probes = [p for m, p in c.log if m == "eth_call" and p[0].get("data") == "0x"]
    assert probes and probes[0][1] == "0x4d"
    assert "latest" not in repr(c.log)


def test_v3_pool_and_lp_reads_are_pinned():
    from .helpers import V3PoolState, v3_single_calldata

    c = swap_world()
    c.add_v3_pool(WETH, USDC, 3000, "0x" + "98" * 20,
                  V3PoolState(2**96 * 1000, 76000, 10**18, ticks={75960: 10**17, 76080: -10**17}))
    res = AnvilSimulator(transport=c.rpc, block="0x10").simulate(
        Tx(U, ROUTER, v3_single_calldata(WETH, USDC, 3000, E, 1)))
    assert res.swap_v3 is not None
    pools = [p for m, p in c.log if m == "eth_call" and p[0]["to"] == "0x" + "98" * 20]
    assert len(pools) >= 4 and all(p[1] == "0x10" for p in pools)


def test_pinned_requests_go_over_http_unchanged():
    h = two_block_world()
    with FakeRpcServer(h.rpc) as srv:
        sim = AnvilSimulator(transport=http_transport(srv.url), block=99,
                             options=SimulatorOptions(trace=False))
        res = sim.simulate(Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN])))
    assert res.success and res.swap.reserve_in == pytest.approx(1000 * E)
    on_wire = [(r["method"], r["params"]) for r in srv.requests]
    assert ("eth_estimateGas", [{"from": U, "to": ROUTER, "data": v2_swap_calldata(
        E, 1, [WETH, TOKEN]), "value": "0x0"}, "0x63"]) in on_wire
    assert {b for _, b in block_params(on_wire)} == {"0x63"}


# --------------------------------------------------------------------------- different state

def test_same_transaction_sees_different_pool_state_at_two_pinned_blocks():
    h = two_block_world()
    tx = Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN]))
    before, after = sim_at(h, 99).simulate(tx), sim_at(h, 100).simulate(tx)
    assert before.swap.reserve_in == pytest.approx(1000 * E)
    assert after.swap.reserve_in == pytest.approx(10 * E)
    assert before.block_timestamp == 1_700_000_000 + 9 * 12  # nine blocks after its keyframe
    assert after.block_timestamp == 1_700_001_200


def test_same_transaction_gets_different_verdicts_at_two_pinned_blocks():
    """1 WETH is a rounding error in a 1000 WETH pool and a 9% move in a 10 WETH pool."""
    h = two_block_world()
    clean = amount_out(E, 1000 * E, 2_000_000 * E)  # what the deep pool would pay
    tx = Tx(U, ROUTER, v2_swap_calldata(E, int(clean * 0.995), [WETH, TOKEN]))
    policy = PolicyConfig(trusted_spenders={ROUTER})
    v_deep, f_deep = assess(tx, sim_at(h, 99).simulate(tx), policy)
    v_thin, f_thin = assess(tx, sim_at(h, 100).simulate(tx), policy)
    rules_deep, rules_thin = {f.rule for f in f_deep}, {f.rule for f in f_thin}
    assert v_deep == Verdict.ALLOW, rules_deep
    assert v_thin in (Verdict.WARN, Verdict.BLOCK), rules_thin
    assert {"PRICE_IMPACT_HIGH", "PRICE_IMPACT_EXTREME"} & rules_thin
    assert not {"PRICE_IMPACT_HIGH", "PRICE_IMPACT_EXTREME"} & rules_deep


def test_latest_follows_the_head_not_a_stale_block():
    h = two_block_world()
    tx = Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN]))
    assert AnvilSimulator(transport=h.rpc, options=SimulatorOptions(trace=False)
                          ).simulate(tx).swap.reserve_in == pytest.approx(10 * E)
    assert sim_at(h, 101).simulate(tx).swap.reserve_in == pytest.approx(10 * E)
    assert sim_at(h, 90).simulate(tx).swap.reserve_in == pytest.approx(1000 * E)


def test_account_state_is_read_at_the_pinned_block():
    """A recipient that is fresh at block 99 but active at block 100."""
    h = HistoricalChain(head=101)
    h.set_state(90, pool_chain(1000 * E, 2_000_000 * E, 1_700_000_000))
    new = h.set_state(100, pool_chain(1000 * E, 2_000_000 * E, 1_700_001_200))
    spender = "0x" + "44" * 20
    new.nonces[spender], new.eth_balances[spender] = 9, E
    tx = Tx(U, TOKEN, approve_calldata(spender, 5))
    r99, r100 = sim_at(h, 99).simulate(tx), sim_at(h, 100).simulate(tx)
    assert r99.accounts[spender].is_fresh
    assert not r100.accounts[spender].is_fresh and r100.accounts[spender].nonce == 9


def test_revert_depends_on_the_pinned_block():
    """A call that reverts at block 99 succeeds at block 100."""
    h = HistoricalChain(head=101)
    early = h.set_state(90, pool_chain(1000 * E, 2_000_000 * E, 1_700_000_000))
    early.reverts[(ROUTER, "0x38ed1739")] = "UniswapV2Router: EXPIRED"
    h.set_state(100, pool_chain(1000 * E, 2_000_000 * E, 1_700_001_200))
    tx = Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN]))
    assert not sim_at(h, 99).simulate(tx).success
    assert sim_at(h, 99).simulate(tx).revert_reason == "UniswapV2Router: EXPIRED"
    assert sim_at(h, 100).simulate(tx).success


def test_pinning_n_minus_one_excludes_the_state_change_made_inside_block_n():
    """The documented semantics: state of block N is invisible when pinned to N - 1."""
    h = two_block_world()  # the pool was drained inside block 100
    victim_block = 100
    tx = Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN]))
    seen_by_wallet = sim_at(h, victim_block - 1).simulate(tx)
    assert seen_by_wallet.swap.reserve_in == pytest.approx(1000 * E)


# --------------------------------------------------------------------------- failure modes

def test_pruned_state_is_an_infrastructure_failure_not_a_revert():
    h = two_block_world()
    h.prune_before = 95
    tx = Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN]))
    res = sim_at(h, 99).simulate(tx)
    assert res.success and res.swap is not None  # inside the retained window: fine
    res = sim_at(h, 94).simulate(tx)
    assert not res.success and res.error and "missing trie node" in res.error
    assert res.revert_reason is None
    verdict, findings = assess(tx, res, PolicyConfig())
    assert verdict == Verdict.BLOCK and findings[0].rule == "SIMULATION_UNAVAILABLE"


def test_future_block_is_reported_as_unavailable():
    h = two_block_world()
    res = sim_at(h, 5000).simulate(Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN])))
    assert not res.success and res.error and "header not found" in res.error


@pytest.mark.parametrize("message", [
    "state at block #123 is pruned", "State is not available for block 5",
    "unknown block", "block not found", "no state available for block",
    "missing trie node 0xab (path )", "historical state 0x1 is not available",
])
def test_archive_failures_are_infrastructure_errors(message):
    assert RpcError(message, -32000).infrastructure


def test_a_revert_that_mentions_pruning_is_still_a_revert():
    from .helpers import revert

    assert not revert("tokens pruned from the pool").infrastructure
    assert not RpcError("execution reverted: unknown block", 3).infrastructure


# --------------------------------------------------------------------------- record / replay

def test_recorded_session_replays_only_for_the_same_block(tmp_path):
    h = two_block_world()
    tx = Tx(U, ROUTER, v2_swap_calldata(E, 1, [WETH, TOKEN]))
    rec = RecordingTransport(h.rpc)
    live = AnvilSimulator(transport=rec, block=99, options=SimulatorOptions(trace=False)
                          ).simulate(tx)
    path = tmp_path / "session.json"
    rec.save(path, "pinned at 99")
    replayed = AnvilSimulator(transport=replay_transport(path), block=99,
                              options=SimulatorOptions(trace=False)).simulate(tx)
    assert replayed.swap == live.swap and replayed.success
    other = AnvilSimulator(transport=replay_transport(path), block=100,
                           options=SimulatorOptions(trace=False)).simulate(tx)
    assert not other.success and other.error and "no recorded response" in other.error
