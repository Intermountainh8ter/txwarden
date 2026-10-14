"""Shared test helpers: an in-memory JSON-RPC "chain" and address constants."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from txwarden.abi import decode, encode, encode_call
from txwarden.amm import amount_out
from txwarden.simulator import RpcError

U = "0x" + "11" * 20          # user
FRIEND = "0x" + "22" * 20
STRANGER = "0x" + "33" * 20
ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
V2_FACTORY = "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"
V3_FACTORY = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
NFPM = "0xc36442b4a4522e871399cd717abdd847ab11fe88"
TOKEN = "0x" + "cc" * 20
EVIL = "0x" + "de" * 20
OTHER = "0x" + "bb" * 20
E = 10**18


def w(n: int) -> str:
    return f"{n % (1 << 256):064x}"


def words(*ns: int) -> str:
    return "0x" + "".join(w(n) for n in ns)


def error_data(msg: str) -> str:
    return "0x08c379a0" + encode(["string"], [msg]).hex()


def revert(msg: str) -> RpcError:
    return RpcError(f"execution reverted: {msg}", 3, error_data(msg))


@dataclass
class TokenState:
    balances: dict[str, int] = field(default_factory=dict)
    total_supply: int = 10**27
    buy_tax: float = 0.0  # fraction lost when buying through the router
    sell_tax: float = 0.0  # fraction lost when selling
    honeypot: bool = False  # sells always revert
    revert_transfer: str | None = None


@dataclass
class V3PoolState:
    sqrt_price_x96: int
    tick: int
    liquidity: int
    tick_spacing: int = 60
    ticks: dict[int, int] = field(default_factory=dict)  # tick -> liquidityNet


@dataclass
class FakeChain:
    """Enough of an Ethereum node to drive ``AnvilSimulator`` end to end.

    Configure tokens, V2 pairs, V3 pools, accounts and reverts, then pass ``chain.rpc`` as the
    transport. ``eth_simulateV1`` chains a buy / approve / sell sequence with a tiny token model
    so honeypots and fee-on-transfer tokens can be exercised.
    """

    chain_id: int = 1
    timestamp: int = 1_700_000_000
    tokens: dict[str, TokenState] = field(default_factory=dict)
    pairs: dict[tuple[str, str], tuple[str, int, int]] = field(default_factory=dict)
    v3_pools: dict[tuple[str, str, int], tuple[str, V3PoolState]] = field(default_factory=dict)
    positions: dict[int, tuple[str, str, int, int]] = field(default_factory=dict)
    code: dict[str, str] = field(default_factory=dict)  # address -> bytecode hex
    nonces: dict[str, int] = field(default_factory=dict)
    eth_balances: dict[str, int] = field(default_factory=dict)
    reverts: dict[tuple[str, str], str] = field(default_factory=dict)  # (to, selector) -> msg
    reject_eth: set[str] = field(default_factory=set)
    gas: dict[str, int] = field(default_factory=dict)  # selector -> gas
    default_gas: int = 50_000
    supports_simulate: bool = True
    trace: dict[str, Any] | None = None
    supports_trace: bool = True
    log: list[tuple[str, Any]] = field(default_factory=list)

    # ---- configuration helpers
    def add_token(self, addr: str, balances: dict[str, int] | None = None, **kw: Any) -> TokenState:
        t = TokenState(dict(balances or {}), **kw)
        self.tokens[addr.lower()] = t
        self.code.setdefault(addr.lower(), "0x6080604052")
        return t

    def add_pair(self, a: str, b: str, pair: str, reserve_a: int, reserve_b: int) -> None:
        a, b = a.lower(), b.lower()
        if int(a, 16) < int(b, 16):
            self.pairs[(a, b)] = (pair.lower(), reserve_a, reserve_b)
        else:
            self.pairs[(b, a)] = (pair.lower(), reserve_b, reserve_a)
        self.code.setdefault(pair.lower(), "0x6080604052")

    def add_v3_pool(self, a: str, b: str, fee: int, pool: str, state: V3PoolState) -> None:
        a, b = sorted((a.lower(), b.lower()), key=lambda x: int(x, 16))
        self.v3_pools[(a, b, fee)] = (pool.lower(), state)
        self.code.setdefault(pool.lower(), "0x6080604052")

    def contract(self, addr: str) -> None:
        self.code[addr.lower()] = "0x6080604052"

    # ---- helpers
    def _pair(self, a: str, b: str) -> tuple[str, int, int] | None:
        a, b = a.lower(), b.lower()
        key = (a, b) if int(a, 16) < int(b, 16) else (b, a)
        p = self.pairs.get(key)
        if p is None:
            return None
        pair, r0, r1 = p
        return (pair, r0, r1) if key == (a, b) else (pair, r1, r0)

    def _quote(self, amount: int, path: list[str]) -> list[int]:
        amounts = [amount]
        for a, b in pairwise(path):
            p = self._pair(a, b)
            if p is None:
                raise revert("UniswapV2Library: PAIR_NOT_FOUND")
            amounts.append(int(amount_out(amounts[-1], p[1], p[2])))
        return amounts

    # ---- eth_call dispatch
    def _eth_call(self, call: dict[str, Any], sim_balances: dict[str, dict[str, int]] | None = None
                  ) -> str:
        to = str(call.get("to", "")).lower()
        data = str(call.get("data", "0x"))
        value = int(call.get("value", "0x0"), 16)
        sel = data[:10] if len(data) >= 10 else "0x"
        if (to, sel) in self.reverts:
            raise revert(self.reverts[(to, sel)])
        if data == "0x" and value and to in self.reject_eth:
            raise revert("no receive")
        if data == "0x":
            return "0x"
        body = "0x" + data[10:]
        # ERC-20 surface
        tok = self.tokens.get(to)
        if tok is not None:
            if sel == "0x70a08231":
                (owner,) = decode(["address"], body)
                bal = (sim_balances or {}).get(to, tok.balances).get(owner.lower(),
                                                                      tok.balances.get(owner.lower(), 0))
                return words(bal)
            if sel == "0x18160ddd":
                return words(tok.total_supply)
            if sel in ("0x095ea7b3", "0xa9059cbb", "0x23b872dd"):
                if tok.revert_transfer and sel != "0x095ea7b3":
                    raise revert(tok.revert_transfer)
                return words(1)
            return "0x"
        if to == V2_FACTORY and sel == "0xe6a43905":
            a, b = decode(["address", "address"], body)
            p = self._pair(a, b)
            return words(int(p[0], 16) if p else 0)
        for pair, r0, r1 in self.pairs.values():
            if to == pair and sel == "0x0902f1ac":
                return words(r0, r1, self.timestamp)
        if to == ROUTER:
            if sel == "0xd06ca61f":
                amount, path = decode(["uint256", "address[]"], body)
                return "0x" + encode(["uint256[]"], [self._quote(amount, path)]).hex()
            return "0x"
        if to == V3_FACTORY and sel == "0x1698ee82":
            a, b, fee = decode(["address", "address", "uint24"], body)
            a, b = sorted((a.lower(), b.lower()), key=lambda x: int(x, 16))
            pool = self.v3_pools.get((a, b, fee))
            return words(int(pool[0], 16) if pool else 0)
        for pool, st in self.v3_pools.values():
            if to != pool:
                continue
            if sel == "0x3850c7bd":
                return words(st.sqrt_price_x96, st.tick, 0, 1, 1, 0, 1)
            if sel == "0x1a686502":
                return words(st.liquidity)
            if sel == "0xd0c93a7c":
                return words(st.tick_spacing)
            if sel == "0x5339c296":
                (word_pos,) = decode(["int16"], body)
                bitmap = 0
                for t in st.ticks:
                    compressed = t // st.tick_spacing
                    if compressed >> 8 == word_pos:
                        bitmap |= 1 << (compressed & 255)
                return words(bitmap)
            if sel == "0xf30dba93":
                (t,) = decode(["int24"], body)
                net = st.ticks.get(t, 0)
                return words(0, net, 0, 0, 0, 0, 0, 1)
        if to == NFPM and sel == "0x99fbab88":
            (tid,) = decode(["uint256"], body)
            if tid not in self.positions:
                raise revert("Invalid token ID")
            t0, t1, fee, liq = self.positions[tid]
            return "0x" + encode(
                ["uint96", "address", "address", "address", "uint24", "int24", "int24", "uint128",
                 "uint256", "uint256", "uint128", "uint128"],
                [0, U, t0, t1, fee, -100, 100, liq, 0, 0, 0, 0]).hex()
        return "0x"

    # ---- eth_simulateV1
    def _simulate(self, params: list[Any]) -> list[dict[str, Any]]:
        if not self.supports_simulate:
            raise RpcError("Method not found", -32601)
        block = params[0]["blockStateCalls"][0]
        sim_balances: dict[str, dict[str, int]] = {}
        results = []
        for call in block["calls"]:
            to = str(call.get("to", "")).lower()
            data = str(call.get("data", "0x"))
            sender = str(call.get("from", U)).lower()
            value = int(call.get("value", "0x0"), 16)
            sel = data[:10]
            body = "0x" + data[10:]
            try:
                if to == ROUTER and sel == "0x7ff36ab5":  # swapExactETHForTokens
                    _min, path, _to, _dl = decode(["uint256", "address[]", "address", "uint256"],
                                                  body)
                    amounts = self._quote(value, path)
                    token = path[-1].lower()
                    tok = self.tokens[token]
                    got = int(amounts[-1] * (1 - tok.buy_tax))
                    bals = sim_balances.setdefault(token, dict(tok.balances))
                    bals[sender] = bals.get(sender, 0) + got
                    ret = "0x" + encode(["uint256[]"], [amounts]).hex()
                elif to == ROUTER and sel in ("0x18cbafe5", "0x791ac947"):  # sell variants
                    amt, _min, path, _to, _dl = decode(
                        ["uint256", "uint256", "address[]", "address", "uint256"], body)
                    token = path[0].lower()
                    tok = self.tokens[token]
                    if tok.honeypot:
                        raise revert("TRANSFER_FAILED")
                    bals = sim_balances.setdefault(token, dict(tok.balances))
                    if bals.get(sender, 0) < amt:
                        raise revert("TransferHelper: TRANSFER_FROM_FAILED")
                    if tok.sell_tax > 0 and sel == "0x18cbafe5":
                        raise revert("UniswapV2: K")
                    received = int(amt * (1 - tok.sell_tax))
                    amounts = self._quote(received, path)
                    bals[sender] -= amt
                    ret = "0x" + encode(["uint256[]"], [amounts]).hex() if sel == "0x18cbafe5" \
                        else "0x"
                else:
                    ret = self._eth_call(call, sim_balances)
                results.append({"status": "0x1", "returnData": ret, "gasUsed": "0x5208"})
            except RpcError as e:
                results.append({"status": "0x0", "returnData": "0x",
                                "error": {"code": e.code, "message": e.message, "data": e.data}})
        return [{"calls": results}]

    # ---- transport
    def rpc(self, method: str, params: list[Any]) -> Any:
        self.log.append((method, json.loads(json.dumps(params))))
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getBlockByNumber":
            return {"number": "0x10", "timestamp": hex(self.timestamp)}
        if method == "eth_call":
            return self._eth_call(params[0])
        if method == "eth_estimateGas":
            call = params[0]
            self._eth_call(call)  # reverts propagate
            sel = str(call.get("data", "0x"))[:10]
            return hex(self.gas.get(sel, self.default_gas))
        if method == "eth_getCode":
            return self.code.get(str(params[0]).lower(), "0x")
        if method == "eth_getTransactionCount":
            return hex(self.nonces.get(str(params[0]).lower(), 0))
        if method == "eth_getBalance":
            return hex(self.eth_balances.get(str(params[0]).lower(), 0))
        if method == "eth_simulateV1":
            return self._simulate(params)
        if method == "debug_traceCall":
            if not self.supports_trace:
                raise RpcError("the method debug_traceCall does not exist/is not available", -32601)
            return self.trace
        raise RpcError(f"Method not found: {method}", -32601)


def approve_calldata(spender: str, amount: int) -> str:
    return encode_call("approve(address,uint256)", [spender, amount])


def transfer_calldata(to: str, amount: int) -> str:
    return encode_call("transfer(address,uint256)", [to, amount])


def v2_swap_calldata(amount_in: int, min_out: int, path: list[str], to: str = U,
                     deadline: int = 2**40) -> str:
    return encode_call("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
                       [amount_in, min_out, path, to, deadline])


def v3_single_calldata(token_in: str, token_out: str, fee: int, amount_in: int, min_out: int,
                       recipient: str = U) -> str:
    return encode_call(
        "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
        [(token_in, token_out, fee, recipient, 2**40, amount_in, min_out, 0)])


def set_approval_for_all_calldata(operator: str, approved: bool = True) -> str:
    return encode_call("setApprovalForAll(address,bool)", [operator, approved])


def permit2_permit_calldata(owner: str, token: str, spender: str, amount: int, expiration: int,
                            sig_deadline: int = 2**40) -> str:
    return encode_call(
        "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
        [owner, ((token, amount, expiration, 0), spender, sig_deadline), "0x" + "aa" * 65])


def eip2612_permit_calldata(owner: str, spender: str, value: int, deadline: int) -> str:
    return encode_call("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                       [owner, spender, value, deadline, 27, "0x" + "01" * 32, "0x" + "02" * 32])


def ur_calldata(commands: bytes, inputs: list[str], deadline: int = 2**40) -> str:
    return encode_call("execute(bytes,bytes[],uint256)", ["0x" + commands.hex(), inputs, deadline])
