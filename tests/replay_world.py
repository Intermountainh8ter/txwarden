"""A synthetic world for replay tests: labelled cases whose transactions live on a fake archive node.

Everything is invented: hashes are ``0x000...0n``, tokens and pools are the repo's test constants.
The cases are chosen so each outcome the runner can record is represented exactly once.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

from txwarden.abi import encode_call
from txwarden.amm import amount_out

from .fake_history import HistoricalChain, fake_hash
from .helpers import ROUTER, TOKEN, USDC, WETH, E, FakeChain, U, approve_calldata, v2_swap_calldata

PAIR = "0x" + "99" * 20
HEAD = 1_000
OTHER_TOKEN = "0x" + "ee" * 20  # no pair exists for it


def base_state(timestamp: int = 1_700_000_000) -> FakeChain:
    c = FakeChain(timestamp=timestamp)
    c.add_token(TOKEN, {U: 10**24})
    c.add_token(USDC, {U: 10**12})
    c.add_token(WETH)
    c.add_token(OTHER_TOKEN)
    c.contract(ROUTER)
    c.add_pair(WETH, TOKEN, PAIR, 1000 * E, 2_000_000 * E)
    c.eth_balances[U] = 100 * E
    return c


def clean_out(amount_in: int) -> int:
    return int(amount_out(amount_in, 1000 * E, 2_000_000 * E))


def swap(amount_in: int, min_out: int, path: list[str] | None = None) -> str:
    return v2_swap_calldata(amount_in, min_out, path or [WETH, TOKEN])


@dataclass
class World:
    chain: HistoricalChain
    rows: list[tuple[str, str, str]] = field(default_factory=list)  # (hash, label, note)

    def csv(self) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["tx_hash", "label", "source", "notes"])
        writer.writerows((h, label, "EXAMPLE", note) for h, label, note in self.rows)
        return buf.getvalue()


# case numbers, so tests can refer to them by name
LOOSE_SANDWICHED, MODERATE_SANDWICHED, TIGHT_SANDWICHED = 1, 2, 3
TIGHT_ORDINARY, TIGHT_ORDINARY_2, LOOSE_ORDINARY = 4, 5, 6
NOT_A_SWAP, NOT_FOUND, NO_POOL, CREATION, PENDING, REVERTS = 7, 8, 9, 10, 11, 12


def build_world() -> World:
    h = HistoricalChain(head=HEAD)
    h.set_state(100, base_state())
    reverting = base_state(1_700_100_000)
    reverting.reverts[(ROUTER, "0x38ed1739")] = "UniswapV2Router: EXPIRED"
    h.set_state(350, reverting)

    def add(n: int, label: str, note: str, data: str | None, block: int | None = 200,
            to: str | None = ROUTER, value: int = 0, register: bool = True) -> None:
        if register:
            h.add_tx(fake_hash(n), U, to, data or "0x", value, block)
        w.rows.append((fake_hash(n), label, note))

    w = World(h)
    add(LOOSE_SANDWICHED, "sandwiched", "20 WETH with min_out 1", swap(20 * E, 1))
    add(MODERATE_SANDWICHED, "sandwiched", "5 WETH, 2% tolerance",
        swap(5 * E, int(clean_out(5 * E) * 0.98)))
    add(TIGHT_SANDWICHED, "sandwiched", "1 WETH, 0.1% tolerance (label noise)",
        swap(E, int(clean_out(E) * 0.999)))
    add(TIGHT_ORDINARY, "ordinary", "1 WETH, 0.1% tolerance", swap(E, int(clean_out(E) * 0.999)))
    add(TIGHT_ORDINARY_2, "ordinary", "2 WETH, 0.1% tolerance",
        swap(2 * E, int(clean_out(2 * E) * 0.999)))
    add(LOOSE_ORDINARY, "ordinary", "10 WETH, loose slippage", swap(10 * E, 1))
    add(NOT_A_SWAP, "sandwiched", "an approval", approve_calldata("0x" + "44" * 20, 5),
        to=TOKEN)
    add(NOT_FOUND, "ordinary", "unknown to the node", None, register=False)
    add(NO_POOL, "sandwiched", "pair does not exist", swap(E, 1, [WETH, OTHER_TOKEN]))
    add(CREATION, "ordinary", "contract creation", "0x6080", to=None)
    add(PENDING, "sandwiched", "not mined", swap(E, 1), block=None)
    add(REVERTS, "ordinary", "reverts at the pinned block", swap(E, 1), block=400)
    return w


def swap_eth_calldata(min_out: int = 0) -> str:
    return encode_call("swapExactETHForTokens(uint256,address[],address,uint256)",
                       [min_out, [WETH, TOKEN], U, 2**40])
