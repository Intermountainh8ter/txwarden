"""Opt-in tests against a real node. Skipped unless ``TXWARDEN_LIVE_RPC`` is set.

    TXWARDEN_LIVE_RPC=https://<your mainnet or mainnet-fork endpoint> pytest -m live -v

They assume Ethereum mainnet (chain id 1) and only use read-only ``eth_call`` / ``eth_estimateGas``
from a well-known funded address, so nothing is sent. Optional node features (``debug_traceCall``,
``eth_simulateV1``) are allowed to be missing; the assertions below do not depend on them.

STATUS: the author could not run these against a real node (no outbound access to Ethereum
endpoints from the development sandbox). They have only been exercised against the in-memory
``FakeChain`` served over HTTP. Treat the live path as unverified until you have run them.
"""
from __future__ import annotations

import os

import pytest

from txwarden.abi import encode_call
from txwarden.addressbook import AddressBook
from txwarden.models import Tx, Verdict
from txwarden.risk import PolicyConfig, assess
from txwarden.simulator import AnvilSimulator, http_transport

RPC = os.environ.get("TXWARDEN_LIVE_RPC")
pytestmark = [pytest.mark.live,
              pytest.mark.skipif(not RPC, reason="set TXWARDEN_LIVE_RPC to a mainnet endpoint")]

RICH = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # a famous, well-funded mainnet address
ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


@pytest.fixture(scope="module")
def sim() -> AnvilSimulator:
    s = AnvilSimulator(rpc_url=RPC)
    chain = int(s.rpc("eth_chainId", []), 16)
    if chain != 1:
        pytest.skip(f"these tests assume Ethereum mainnet, node reports chain id {chain}")
    return s


def test_node_is_reachable_and_http_transport_works():
    call = http_transport(RPC)
    assert int(call("eth_blockNumber", []), 16) > 0


def test_every_builtin_address_book_entry_has_code_on_chain(sim):
    """Validates the shipped address book against the chain (burn addresses excepted)."""
    book = AddressBook.builtin()
    missing = []
    for lbl in book.entries():
        if lbl.kind == "burn":
            continue
        code = sim.rpc("eth_getCode", [lbl.address, "latest"])
        if code in ("0x", "0x0", None):
            missing.append(lbl.name)
    assert not missing, f"no code at: {missing}"


def test_bounded_approval_to_the_router_is_reviewed_without_surprises(sim):
    tx = Tx(RICH.lower(), USDC.lower(), encode_call("approve(address,uint256)", [ROUTER, 1]))
    res = sim.simulate(tx)
    assert res.success, res.revert_reason or res.error
    assert res.chain_id == 1 and res.gas_used > 20_000
    verdict, findings = assess(tx, res, PolicyConfig(trusted_spenders={ROUTER}, expected_chain_id=1))
    assert verdict == Verdict.ALLOW, [f.rule for f in findings]


def test_unlimited_approval_to_a_fresh_address_blocks(sim):
    stranger = "0x" + os.urandom(20).hex()
    tx = Tx(RICH.lower(), USDC.lower(), encode_call("approve(address,uint256)", [stranger, 2**256 - 1]))
    res = sim.simulate(tx)
    assert res.success and res.accounts[stranger].is_fresh
    verdict, findings = assess(tx, res, PolicyConfig())
    assert verdict == Verdict.BLOCK and findings[0].rule == "UNLIMITED_APPROVAL_UNKNOWN"


def test_v2_eth_to_usdc_swap_reads_real_reserves(sim):
    data = encode_call("swapExactETHForTokens(uint256,address[],address,uint256)",
                       [0, [WETH, USDC], RICH, 2**40])
    tx = Tx(RICH.lower(), ROUTER.lower(), data, 10**16)
    res = sim.simulate(tx)
    assert res.success, res.revert_reason or res.error
    assert res.swap is not None and res.swap.reserve_in > 1e18 and res.swap.reserve_out > 1e9
    verdict, findings = assess(tx, res, PolicyConfig(trusted_spenders={ROUTER}))
    assert "SLIPPAGE_TOLERANCE_EXTREME" in {f.rule for f in findings}  # min_out of 0
    assert verdict == Verdict.BLOCK
    if res.honeypot is not None:  # only when the node supports the probe
        assert res.honeypot.buy_ok


def test_reverting_call_is_reported_with_the_nodes_reason(sim):
    # transferFrom without an allowance reverts on every ERC-20; the exact text varies by token
    data = encode_call("transferFrom(address,address,uint256)", [WETH, RICH, 10**30])
    res = sim.simulate(Tx(RICH.lower(), USDC.lower(), data))
    assert not res.success and res.error is None and res.revert_reason
