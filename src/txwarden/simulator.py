"""Simulators: a fixture backend for tests/evals and a JSON-RPC backend for an Anvil fork."""
from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol

from .models import Approval, SimResult, Swap, Transfer, Tx

APPROVE = "0x095ea7b3"  # approve(address,uint256)
TRANSFER = "0xa9059cbb"  # transfer(address,uint256)
V2_SWAP_EXACT_IN = "0x38ed1739"  # swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
GET_PAIR = "0xe6a43905"  # getPair(address,address)
GET_RESERVES = "0x0902f1ac"  # getReserves()
BALANCE_OF = "0x70a08231"  # balanceOf(address)

UNISWAP_V2_FACTORY = "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"


class Simulator(Protocol):
    def simulate(self, tx: Tx) -> SimResult: ...


class FixtureSimulator:
    """Returns pre-recorded results keyed by a caller-chosen id (used by tests and evals)."""

    def __init__(self, fixtures: dict[str, SimResult]):
        self.fixtures = fixtures

    def simulate(self, tx: Tx) -> SimResult:
        key = tx.data
        if key not in self.fixtures:
            raise KeyError(f"no fixture for calldata {key!r}")
        return self.fixtures[key]


def _word(n: int) -> str:
    return f"{n:064x}"


def _addr(word: str) -> str:
    return "0x" + word[-40:]


def decode_calldata(data: str) -> dict[str, Any]:
    """Decode the handful of selectors the guard understands. Unknown selectors -> kind=unknown."""
    d = data.removeprefix("0x")
    sel, body = "0x" + d[:8], d[8:]
    words = [body[i:i + 64] for i in range(0, len(body), 64)]
    if sel == APPROVE and len(words) >= 2:
        return {"kind": "approve", "spender": _addr(words[0]), "amount": int(words[1], 16)}
    if sel == TRANSFER and len(words) >= 2:
        return {"kind": "transfer", "to": _addr(words[0]), "amount": int(words[1], 16)}
    if sel == V2_SWAP_EXACT_IN and len(words) >= 7:
        path_off = int(words[2], 16) // 32
        n = int(words[path_off], 16)
        path = [_addr(words[path_off + 1 + i]) for i in range(n)]
        return {
            "kind": "v2_swap",
            "amount_in": int(words[0], 16),
            "min_out": int(words[1], 16),
            "path": path,
            "to": _addr(words[3]),
        }
    return {"kind": "unknown", "selector": sel}


Transport = Callable[[str, list[Any]], Any]


def http_transport(url: str) -> Transport:
    def call(method: str, params: list[Any]) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            out = json.loads(resp.read())
        if "error" in out:
            raise RuntimeError(out["error"])
        return out["result"]

    return call


class AnvilSimulator:
    """Dry-runs a transaction against an Anvil/Hardhat fork via ``eth_call``.

    Decodes ERC-20 approve/transfer and Uniswap V2 ``swapExactTokensForTokens`` calldata,
    checks that the call executes, and pulls pair reserves for AMM analysis. Anything else is
    simulated for revert/gas only.
    """

    def __init__(self, rpc_url: str | None = None, transport: Transport | None = None,
                 v2_factory: str = UNISWAP_V2_FACTORY):
        if transport is None:
            if rpc_url is None:
                raise ValueError("rpc_url or transport required")
            transport = http_transport(rpc_url)
        self.rpc = transport
        self.factory = v2_factory

    def _call(self, to: str, data: str, sender: str | None = None) -> str:
        obj = {"to": to, "data": data}
        if sender:
            obj["from"] = sender
        return self.rpc("eth_call", [obj, "latest"])

    def simulate(self, tx: Tx) -> SimResult:
        res = SimResult(success=True)
        call = {"from": tx.sender, "to": tx.to, "data": tx.data, "value": hex(tx.value)}
        try:
            self.rpc("eth_call", [call, "latest"])
            res.gas_used = int(self.rpc("eth_estimateGas", [call]), 16)
        except RuntimeError as e:
            res.success = False
            res.revert_reason = str(e)
            return res

        dec = decode_calldata(tx.data)
        if dec["kind"] == "approve":
            res.approvals.append(Approval(tx.to, tx.sender, dec["spender"], dec["amount"]))
        elif dec["kind"] == "transfer":
            bal = int(self._call(tx.to, BALANCE_OF + _word(int(tx.sender, 16))), 16)
            res.transfers.append(Transfer(tx.to, tx.sender, dec["to"], dec["amount"], bal))
        elif dec["kind"] == "v2_swap" and len(dec["path"]) == 2:
            t_in, t_out = dec["path"]
            pair = _addr(self._call(self.factory, GET_PAIR + _word(int(t_in, 16)) + _word(int(t_out, 16))))
            raw = self._call(pair, GET_RESERVES)[2:]
            r0, r1 = int(raw[:64], 16), int(raw[64:128], 16)
            # V2 orders reserves by token address.
            reserve_in, reserve_out = (r0, r1) if int(t_in, 16) < int(t_out, 16) else (r1, r0)
            res.swap = Swap(float(dec["amount_in"]), float(dec["min_out"]),
                            float(reserve_in), float(reserve_out))
        return res
