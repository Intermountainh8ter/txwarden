"""(Re)generate the recorded RPC sessions in ``tests/fixtures/rpc_*.json``.

    python -m tests.make_fixtures

The sessions are recorded with ``RecordingTransport`` from the in-memory ``FakeChain`` in
``tests/helpers.py``. They exercise the real record/replay and HTTP code paths, but they are NOT
recordings from a real node (each file says so). To record a real session, run
``txwarden review tx.json --rpc <url> --record session.json`` against a node you trust.
"""
from __future__ import annotations

import json
from pathlib import Path

from txwarden.abi import encode_call
from txwarden.models import Tx
from txwarden.simulator import AnvilSimulator, RecordingTransport, SimulatorOptions

from .helpers import ROUTER, STRANGER, TOKEN, WETH, E, FakeChain, U, approve_calldata

FIXTURES = Path(__file__).parent / "fixtures"
PAIR = "0x" + "99" * 20


def chain() -> FakeChain:
    c = FakeChain()
    c.add_token(TOKEN, {U: 10**24})
    c.add_token(WETH)
    c.contract(ROUTER)
    c.add_pair(WETH, TOKEN, PAIR, 5000 * E, 10_000_000 * E)
    c.eth_balances[U] = 100 * E
    return c


def scenarios() -> dict[str, tuple[str, Tx, FakeChain]]:
    swap = encode_call("swapExactETHForTokens(uint256,address[],address,uint256)",
                       [int(E * 1.99e3 * 0.995), [WETH, TOKEN], U, 2**40])
    out: dict[str, tuple[str, Tx, FakeChain]] = {
        "rpc_swap_tight": ("swapExactETHForTokens, 1 ETH into a 5000 ETH pool, 0.5% floor",
                           Tx(U, ROUTER, swap, E), chain()),
        "rpc_unlimited_approve": ("approve(stranger, uint256 max) on an ERC-20",
                                  Tx(U, TOKEN, approve_calldata(STRANGER, 2**256 - 1)), chain()),
    }
    c = chain()
    c.reverts[(ROUTER, swap[:10])] = "UniswapV2Router: EXPIRED"
    out["rpc_revert"] = ("the same swap reverting with a reason", Tx(U, ROUTER, swap, E), c)
    c = chain()
    c.tokens[TOKEN].honeypot = True
    out["rpc_honeypot"] = ("a buy that works and a sell that always reverts",
                           Tx(U, ROUTER, swap, E), c)
    return out


def record(name: str, description: str, tx: Tx, c: FakeChain) -> dict:
    rec = RecordingTransport(c.rpc)
    AnvilSimulator(transport=rec, options=SimulatorOptions()).simulate(tx)
    return {"description": f"{description}. Recorded from tests/helpers.FakeChain, not a real node.",
            "tx": tx.to_dict(), "records": rec.records}


def build_all() -> dict[str, dict]:
    return {name: record(name, *args) for name, args in scenarios().items()}


def main() -> None:
    FIXTURES.mkdir(exist_ok=True)
    for name, data in build_all().items():
        (FIXTURES / f"{name}.json").write_text(json.dumps(data, indent=1) + "\n")
        print("wrote", FIXTURES / f"{name}.json")


if __name__ == "__main__":
    main()
