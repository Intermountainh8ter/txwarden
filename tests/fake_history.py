"""A fake *archive* node for block-pinned tests: one ``FakeChain`` state per block.

``HistoricalChain.rpc`` has the same ``(method, params)`` shape as ``FakeChain.rpc`` (so it plugs
into ``AnvilSimulator(transport=...)`` or ``FakeRpcServer(handler=...)``) but resolves the block
parameter of every state-dependent request and answers from the state that was current then.

States are keyframes: the state set for block ``b`` stays in force for every later block until a
newer keyframe replaces it, so a test only declares the blocks where something changed. Nothing
here is real chain data: hashes, addresses and reserves are synthetic.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from txwarden.simulator import RpcError

from .helpers import FakeChain

MOCK_CLIENT_VERSION = "txwarden-fakechain/1.0"
BLOCK_TIME = 12


def fake_hash(n: int) -> str:
    """An obviously synthetic 32-byte transaction hash (``0x000...0n``)."""
    return "0x" + f"{n:064x}"


@dataclass
class HistoricalChain:
    head: int
    chain_id: int = 1
    client_version: str = MOCK_CLIENT_VERSION
    prune_before: int | None = None  # states for blocks older than this are "pruned"
    states: dict[int, FakeChain] = field(default_factory=dict)
    txs: dict[str, dict[str, Any]] = field(default_factory=dict)
    log: list[tuple[str, list[Any]]] = field(default_factory=list)

    # ---- configuration helpers
    def set_state(self, block: int, chain: FakeChain) -> FakeChain:
        """``chain`` is the state at the end of ``block`` (and later, until replaced)."""
        chain.chain_id = self.chain_id
        self.states[block] = chain
        return chain

    def add_tx(self, tx_hash: str, sender: str, to: str | None, data: str, value: int = 0,
               block: int | None = None, *, chain_id: int | None = None, **extra: Any
               ) -> dict[str, Any]:
        tx: dict[str, Any] = {
            "hash": tx_hash, "from": sender, "to": to, "input": data, "value": hex(value),
            "blockNumber": None if block is None else hex(block),
            "transactionIndex": None if block is None else "0x0", "nonce": "0x0",
            "gas": "0x30d40", "type": "0x2",
        }
        if chain_id is not None:
            tx["chainId"] = hex(chain_id)
        tx.update(extra)
        self.txs[tx_hash.lower()] = tx
        return tx

    # ---- block resolution
    def resolve(self, tag: Any) -> int:
        if tag in (None, "latest", "pending", "safe", "finalized"):
            return self.head
        if tag == "earliest":
            return 0
        if isinstance(tag, str) and tag.startswith("0x"):
            n = int(tag, 16)
        elif isinstance(tag, int):
            n = tag
        else:
            raise RpcError(f"invalid block tag {tag!r}", -32602)
        if n > self.head:
            raise RpcError("header not found", -32000)
        return n

    def state_at(self, number: int) -> FakeChain:
        if self.prune_before is not None and number < self.prune_before:
            raise RpcError(f"missing trie node {number:064x} (path ) state 0x{number:x} "
                           "is not available", -32000)
        keys = [b for b in self.states if b <= number]
        if not keys:
            raise RpcError("header not found", -32000)
        return self.states[max(keys)]

    # ---- transport
    def rpc(self, method: str, params: list[Any]) -> Any:
        self.log.append((method, json.loads(json.dumps(params))))
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_blockNumber":
            return hex(self.head)
        if method == "web3_clientVersion":
            return self.client_version
        if method == "eth_getTransactionByHash":
            return self.txs.get(str(params[0]).lower())
        position = {"eth_call": 1, "eth_estimateGas": 1, "eth_getCode": 1, "eth_getBalance": 1,
                    "eth_getTransactionCount": 1, "eth_simulateV1": 1, "debug_traceCall": 1,
                    "eth_getBlockByNumber": 0}.get(method)
        if position is None:
            raise RpcError(f"Method not found: {method}", -32601)
        tag = params[position] if len(params) > position else "latest"
        number = self.resolve(tag)
        state = self.state_at(number)
        if method == "eth_getBlockByNumber":
            return {"number": hex(number),
                    "timestamp": hex(state.timestamp + (number - max(
                        b for b in self.states if b <= number)) * BLOCK_TIME)}
        return state.rpc(method, params)

    # ---- inspection
    def blocks_requested(self, method: str) -> list[Any]:
        """The block parameter of every logged request of ``method`` (None when absent)."""
        position = {"eth_getBlockByNumber": 0, "debug_traceCall": 1}.get(method, 1)
        return [p[position] if len(p) > position else None
                for m, p in self.log if m == method]


class FakeClock:
    """Deterministic time for rate-limit and backoff tests: ``sleep`` just advances ``now``."""

    def __init__(self, start: float = 1_000.0):
        self.t = start
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds

    def wall(self) -> str:
        return "2026-01-01T00:00:00+00:00"
