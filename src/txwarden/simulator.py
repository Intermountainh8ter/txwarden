"""Simulators: a fixture backend for tests/evals and a JSON-RPC backend for an Anvil/Geth fork.

``AnvilSimulator`` is deliberately conservative about optional node features: the main
``eth_call``/``eth_estimateGas`` decide success, and every enrichment (account probes, pool
state, ``debug_traceCall``, ``eth_simulateV1`` honeypot probes) degrades to "not available"
rather than failing the review. The risk engine treats missing data as "rule cannot fire",
which is documented in THREAT_MODEL.md as a known limitation of non-archive endpoints.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .abi import AbiError, decode, decode_call, encode_call
from .addressbook import AddressBook
from .effects import WETH, LPIntent, SwapIntent, extract_effects, trace_transfers
from .models import (
    ETH,
    AccountInfo,
    CallFrame,
    HoneypotProbe,
    Hop,
    LPEvent,
    PathSwap,
    SimResult,
    Swap,
    Transfer,
    Tx,
    V3Swap,
    V3Tick,
)

UNISWAP_V2_FACTORY = "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"
UNISWAP_V2_ROUTER = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
UNISWAP_V3_FACTORY = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
UNISWAP_V3_NFPM = "0xc36442b4a4522e871399cd717abdd847ab11fe88"

# Selectors kept as constants for the mock-transport tests that match on prefixes.
APPROVE = "0x095ea7b3"
TRANSFER = "0xa9059cbb"
V2_SWAP_EXACT_IN = "0x38ed1739"
GET_PAIR = "0xe6a43905"
GET_RESERVES = "0x0902f1ac"
BALANCE_OF = "0x70a08231"
TOTAL_SUPPLY = "0x18160ddd"
GET_POOL = "0x1698ee82"
SLOT0 = "0x3850c7bd"
LIQUIDITY = "0x1a686502"
TICK_SPACING = "0xd0c93a7c"
TICK_BITMAP = "0x5339c296"
TICKS = "0xf30dba93"
POSITIONS = "0x99fbab88"
GET_AMOUNTS_OUT = "0xd06ca61f"

ERROR_SELECTOR = "0x08c379a0"  # Error(string)
PANIC_SELECTOR = "0x4e487b71"  # Panic(uint256)
FAR_DEADLINE = 2**64
V3_FEE_DENOM = 1_000_000


class Simulator(Protocol):
    def simulate(self, tx: Tx) -> SimResult: ...


# --------------------------------------------------------------------------- fixtures

class FixtureSimulator:
    """Returns pre-recorded results keyed by calldata (used by tests and evals)."""

    def __init__(self, fixtures: dict[str, SimResult], key: Callable[[Tx], str] | None = None):
        self.fixtures = fixtures
        self.key = key or (lambda tx: tx.data)

    @classmethod
    def from_json(cls, path: str | Path) -> FixtureSimulator:
        raw = json.loads(Path(path).read_text())
        return cls({k: SimResult.from_dict(v) for k, v in raw.items()})

    def simulate(self, tx: Tx) -> SimResult:
        key = self.key(tx)
        if key not in self.fixtures:
            raise KeyError(f"no fixture for {key!r}")
        return self.fixtures[key]


class StaticSimulator:
    """Offline backend: decodes calldata and reports static effects only (no chain state).

    Used by the CLI when no RPC is configured so approvals, operator approvals and permits are
    still reviewed. Swaps are reported without pool state, so AMM rules cannot fire; the CLI
    says so.
    """

    def __init__(self, book: AddressBook | None = None):
        self.book = book or AddressBook()

    def simulate(self, tx: Tx) -> SimResult:
        call = decode_call(tx.data)
        eff = extract_effects(tx, call)
        res = SimResult(success=True, call_kind=call.kind, decoded=call.to_dict())
        res.approvals, res.operator_approvals = eff.approvals, eff.operator_approvals
        res.permits, res.transfers = eff.permits, list(eff.transfers)
        if tx.value > 0:
            res.transfers.append(Transfer(ETH, tx.sender, tx.to, tx.value, kind="eth"))
        res.lp_events = [LPEvent(lp.action, f"{lp.token_a}/{lp.token_b}", float(lp.liquidity),
                                 None, lp.protocol) for lp in eff.lp]
        res.output_recipients = list(dict.fromkeys(eff.output_recipients))
        res.incomplete = ["chain_state"]
        if eff.swaps:
            res.incomplete.append("swap_state: no pool state without an RPC")
        if any(lp.action == "remove" for lp in eff.lp):
            res.incomplete.append("lp_state: pool totals unavailable without an RPC")
        res.labels = {a: n for a, n in self.book.labels().items()
                      if a in res.all_counterparties() or a == tx.to}
        return res


# --------------------------------------------------------------------------- transport

Transport = Callable[[str, list[Any]], Any]

BlockSpec = str | int  # "latest", a non-negative integer, or a 0x-hex quantity string
_HEX_QUANTITY = re.compile(r"0x[0-9a-f]+")


def normalize_block(block: BlockSpec) -> str:
    """The JSON-RPC block parameter for ``block``: ``"latest"`` or a minimal ``0x`` quantity.

    Integers and hex strings are canonicalised (``0x00ff`` -> ``0xff``) because nodes reject
    quantities with leading zeros. Other tags (``pending``, ``safe``, ...) are refused on purpose:
    a pinned analysis must name a block that cannot move underneath it.
    """
    if isinstance(block, bool):  # bool is an int subclass; True would silently mean block 1
        raise ValueError(f"block must be 'latest', an integer or a 0x-hex string, got {block!r}")
    if isinstance(block, int):
        if block < 0:
            raise ValueError(f"block number must not be negative, got {block}")
        return hex(block)
    if isinstance(block, str):
        s = block.strip().lower()
        if s == "latest":
            return "latest"
        if _HEX_QUANTITY.fullmatch(s):
            return hex(int(s, 16))
    raise ValueError(
        f"block must be 'latest', an integer or a 0x-hex string, got {str(block)[:40]!r}")


_UNSUPPORTED_HINTS = ("method not found", "unknown method", "not supported")
_INFRA_HINTS = ("missing trie node", "header not found", "state not available",
                "historical state", "rate limit", "limit exceeded", "too many requests",
                "timed out", "timeout", "unauthorized", "forbidden", "invalid api key",
                "connection", "service unavailable", "bad gateway")


class RpcError(RuntimeError):
    """A JSON-RPC failure. ``transport`` marks connectivity/HTTP/format failures (as opposed to a
    node answering with an error object), which the simulator treats as "no analysis possible"."""

    def __init__(self, message: str, code: int | None = None, data: Any = None,
                 transport: bool = False):
        super().__init__(message)
        self.message, self.code, self.data, self.transport = message, code, data, transport

    @property
    def unsupported(self) -> bool:
        m = self.message.lower()
        return self.code == -32601 or "not supported" in m or "method not found" in m \
            or "does not exist" in m or "unknown method" in m

    @property
    def infrastructure(self) -> bool:
        """True when the failure says nothing about the transaction (node down, rate limited,
        pruned state) so it must not be reported as a revert."""
        if self.transport or (self.code is not None and 400 <= self.code < 600):  # HTTP status
            return True
        if self.data is not None and decode_revert(self.data) is not None:
            return False
        m = self.message.lower()
        if "revert" in m:
            return False
        # a node that does not implement eth_call/eth_estimateGas can tell us nothing either
        return self.code == -32601 or any(h in m for h in _INFRA_HINTS + _UNSUPPORTED_HINTS)

    def revert_reason(self) -> str:
        return decode_revert(self.data) or self.message


def decode_revert(data: Any) -> str | None:
    """Decode ``Error(string)`` / ``Panic(uint256)`` revert data if present."""
    if not isinstance(data, str) or not data.startswith("0x"):
        if isinstance(data, dict) and "data" in data:
            return decode_revert(data["data"])
        return None
    try:
        if data.startswith(ERROR_SELECTOR):
            return str(decode(["string"], "0x" + data[10:])[0])
        if data.startswith(PANIC_SELECTOR):
            return f"Panic(0x{decode(['uint256'], '0x' + data[10:])[0]:02x})"
    except AbiError:
        return None
    return None


def http_transport(url: str, timeout: float = 15.0) -> Transport:
    counter = {"id": 0}

    def call(method: str, params: list[Any]) -> Any:
        counter["id"] += 1
        body = json.dumps({"jsonrpc": "2.0", "id": counter["id"], "method": method,
                           "params": params}).encode()
        req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                out = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RpcError(f"HTTP {e.code} from {url}", code=e.code, transport=True) from e
        except urllib.error.URLError as e:
            raise RpcError(f"cannot reach {url}: {e.reason}", transport=True) from e
        except (TimeoutError, OSError) as e:
            raise RpcError(f"cannot reach {url}: {e}", transport=True) from e
        except ValueError as e:  # not JSON (an HTML error page, a captive portal, ...)
            raise RpcError(f"{url} did not return JSON: {e}", transport=True) from e
        if not isinstance(out, dict):
            raise RpcError("malformed JSON-RPC response", transport=True)
        if "error" in out:
            err = out["error"] or {}
            if isinstance(err, dict):
                raise RpcError(str(err.get("message", "rpc error")), err.get("code"),
                               err.get("data"))
            raise RpcError(str(err))
        return out.get("result")

    return call


@dataclass
class RecordingTransport:
    """Wraps a transport and records every request/response pair as a replayable fixture."""

    inner: Transport
    records: list[dict[str, Any]] = field(default_factory=list)

    def __call__(self, method: str, params: list[Any]) -> Any:
        rec: dict[str, Any] = {"method": method, "params": json.loads(json.dumps(params))}
        try:
            result = self.inner(method, params)
        except RpcError as e:
            rec["error"] = {"code": e.code, "message": e.message, "data": e.data,
                            "transport": e.transport}
            self.records.append(rec)
            raise
        rec["result"] = json.loads(json.dumps(result))
        self.records.append(rec)
        return result

    def save(self, path: str | Path, description: str = "") -> None:
        Path(path).write_text(json.dumps({"description": description, "records": self.records},
                                         indent=1) + "\n")


def replay_transport(path: str | Path) -> Transport:
    """Transport that answers from a recorded fixture; unknown requests raise ``RpcError``."""
    raw = json.loads(Path(path).read_text())
    table = {(r["method"], json.dumps(r["params"], sort_keys=True)): r for r in raw["records"]}

    def call(method: str, params: list[Any]) -> Any:
        rec = table.get((method, json.dumps(params, sort_keys=True)))
        if rec is None:  # not an answer from a node: nothing is known about this request
            raise RpcError(f"no recorded response for {method} {json.dumps(params)[:200]}",
                           code=-32601, transport=True)
        if "error" in rec:
            e = rec["error"]
            raise RpcError(e.get("message", "error"), e.get("code"), e.get("data"),
                           bool(e.get("transport", False)))
        return rec["result"]

    return call


# --------------------------------------------------------------------------- helpers

def _word(n: int) -> str:
    return f"{n:064x}"


def _addr(word: str) -> str:
    return "0x" + word[-40:]


def _uint(hexstr: str) -> int:
    return int(hexstr, 16) if hexstr and hexstr != "0x" else 0


def _int_word(word: str) -> int:
    """Signed integer from a sign-extended 256-bit ABI word (int24, int128, ...)."""
    n = int(word, 16)
    return n - (1 << 256) if n >> 255 else n


@dataclass
class SimulatorOptions:
    account_probe: bool = True
    trace: bool = True
    honeypot: bool = True
    v3_ticks: bool = True
    max_ticks: int = 64
    tick_words: int = 2  # bitmap words scanned on each side of the current tick
    probe_value_wei: int = 10**16
    weth: str = WETH
    v2_factory: str = UNISWAP_V2_FACTORY
    v2_router: str = UNISWAP_V2_ROUTER
    v3_factory: str = UNISWAP_V3_FACTORY
    v3_position_manager: str = UNISWAP_V3_NFPM
    known_tokens: set[str] = field(default_factory=set)  # skip honeypot probe for these

    def __post_init__(self) -> None:
        self.known_tokens = {t.lower() for t in self.known_tokens}


# --------------------------------------------------------------------------- Anvil backend

class AnvilSimulator:
    """Dry-runs a transaction against an Anvil/Hardhat/Geth fork via JSON-RPC.

    Steps: decode calldata -> ``eth_call`` + ``eth_estimateGas`` -> static effects -> account
    probes (``eth_getCode``/``eth_getTransactionCount``/``eth_getBalance``) -> pool state for
    swaps (V2 reserves, V3 slot0/liquidity/ticks) -> LP totals -> honeypot probe
    (``eth_simulateV1``, falling back to router quotes) -> ``debug_traceCall`` call tree.

    **Block pinning.** ``block`` selects the state every read is made against: ``"latest"`` (the
    default, today's behaviour), an integer, or a ``0x``-hex string. It is sent with every
    state-dependent request: ``eth_call``, ``eth_estimateGas`` (only when pinned, so the default
    request bytes are unchanged), ``eth_getBlockByNumber``, ``eth_getCode``, ``eth_getBalance``,
    ``eth_getTransactionCount``, ``eth_simulateV1`` and ``debug_traceCall``.

    To replay a *historical* transaction that was mined in block ``N``, pin to ``N - 1``: that is
    the state at the end of block ``N - 1``, which approximates what a wallet saw when the user
    signed. A front-run, if there was one, sits inside block ``N`` and is invisible at ``N - 1``.
    **Limitation:** this is a block-boundary snapshot. Transactions that precede the victim *within*
    block ``N`` (other swaps on the same pool, the attacker's own front-run, approvals) have not
    happened yet, so intra-block ordering effects are not reproduced and a transaction that depended
    on them can revert or price differently. Pinning to an old block needs a node with archive
    state; a pruned node answers "missing trie node" or similar, which is reported as an
    infrastructure failure, never as a revert.
    """

    def __init__(self, rpc_url: str | None = None, transport: Transport | None = None,
                 v2_factory: str | None = None, options: SimulatorOptions | None = None,
                 block: BlockSpec = "latest"):
        if transport is None:
            if rpc_url is None:
                raise ValueError("rpc_url or transport required")
            transport = http_transport(rpc_url)
        self.rpc = transport
        self.block = normalize_block(block)
        self.options = options or SimulatorOptions()
        if v2_factory:
            self.options.v2_factory = v2_factory.lower()
        self.factory = self.options.v2_factory

    # ---- low level
    def _call(self, to: str, data: str, sender: str | None = None, value: int = 0) -> str:
        obj: dict[str, Any] = {"to": to, "data": data}
        if sender:
            obj["from"] = sender
        if value:
            obj["value"] = hex(value)
        return self.rpc("eth_call", [obj, self.block])

    def _estimate_params(self, call: dict[str, Any]) -> list[Any]:
        # unpinned requests stay byte-identical to what earlier versions sent
        return [call] if self.block == "latest" else [call, self.block]

    def _try(self, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except (RuntimeError, AbiError, ValueError, KeyError, TypeError, IndexError):
            return None

    # ---- main
    def simulate(self, tx: Tx) -> SimResult:
        opt = self.options
        res = SimResult(success=True)
        call = {"from": tx.sender, "to": tx.to, "data": tx.data, "value": hex(tx.value)}

        res.chain_id = self._try(lambda: _uint(self.rpc("eth_chainId", [])))
        header = self._try(lambda: self.rpc("eth_getBlockByNumber", [self.block, False]))
        if isinstance(header, dict) and header.get("timestamp"):
            res.block_timestamp = _uint(header["timestamp"])

        dec = decode_call(tx.data)
        res.call_kind, res.decoded = dec.kind, dec.to_dict()
        eff = extract_effects(tx, dec, opt.weth)

        try:
            self.rpc("eth_call", [call, self.block])
            res.gas_used = _uint(self.rpc("eth_estimateGas", self._estimate_params(call)))
        except RuntimeError as e:  # RpcError or a custom transport's own error
            if isinstance(e, RpcError) and e.infrastructure:
                # nothing was learned about the transaction: report that, never "it reverts"
                res.success, res.error = False, e.message
                return res
            res.success = False
            res.revert_reason = e.revert_reason() if isinstance(e, RpcError) else str(e)
            if tx.value > 0:
                res.eth_receive_reverts = self._eth_receive_reverts(tx)

        res.approvals = eff.approvals
        res.operator_approvals = eff.operator_approvals
        res.permits = eff.permits
        res.output_recipients = list(dict.fromkeys(eff.output_recipients))
        res.transfers = self._with_balances(tx, eff.transfers)
        if tx.value > 0:
            bal = self._try(lambda: _uint(self.rpc("eth_getBalance", [tx.sender, self.block])))
            res.transfers.append(Transfer(ETH, tx.sender, tx.to, tx.value, bal, kind="eth"))

        if opt.trace:
            res.call_tree = self._trace(call)
            if res.call_tree is None:
                res.incomplete.append("call_trace")
            else:
                known = {(t.token, t.recipient, t.amount, t.token_id) for t in res.transfers}
                extra = [t for t in trace_transfers(tx, res.call_tree, opt.weth)
                         if (t.token, t.recipient, t.amount, t.token_id) not in known]
                res.transfers.extend(self._with_balances(tx, extra))

        if opt.account_probe:
            targets = res.all_counterparties() | {tx.to}
            targets.discard(tx.sender)
            for a in sorted(targets):
                info = self._account(a)
                if info is not None:
                    res.accounts[a] = info
            if not all(a in res.accounts for a in targets):
                res.incomplete.append("account_probe")

        if res.success and eff.swaps:
            self._attach_swap(res, eff.swaps[0])
            if not (res.swap or res.path_swap or res.swap_v3):
                res.incomplete.append("swap_state: pool state not found for the first swap")
            elif len(eff.swaps) > 1:
                res.incomplete.append(
                    f"swap_state: only the first of {len(eff.swaps)} swaps was assessed")
        if res.success:
            res.lp_events = [self._lp_event(tx, lp) for lp in eff.lp]
            if any(e.action == "remove" and e.pool_total is None for e in res.lp_events):
                res.incomplete.append("lp_state: pool total supply unavailable")
        if res.success and opt.honeypot and eff.swaps:
            s = eff.swaps[0]
            if s.token_out.lower() not in opt.known_tokens and s.token_out.lower() != opt.weth:
                res.honeypot = self._probe_honeypot(tx, s.token_out)
                if res.honeypot is None:
                    res.incomplete.append("honeypot_probe")
        return res

    # ---- enrichment
    def _with_balances(self, tx: Tx, transfers: list[Transfer]) -> list[Transfer]:
        out = []
        for t in transfers:
            if t.kind == "erc20" and t.sender == tx.sender and t.sender_balance_before is None:
                bal = self._try(lambda t=t: _uint(self._call(t.token, BALANCE_OF
                                                             + _word(int(tx.sender, 16)))))
                t = Transfer(t.token, t.sender, t.recipient, t.amount, bal, t.kind, t.operator,
                             t.token_id)
            out.append(t)
        return out

    def _account(self, address: str) -> AccountInfo | None:
        code = self._try(lambda: self.rpc("eth_getCode", [address, self.block]))
        if code is None:
            return None
        size = max(0, (len(code) - 2) // 2) if isinstance(code, str) else 0
        nonce = self._try(lambda: _uint(self.rpc("eth_getTransactionCount",
                                                 [address, self.block])))
        bal = self._try(lambda: _uint(self.rpc("eth_getBalance", [address, self.block])))
        return AccountInfo(address, size, nonce or 0, bal or 0)

    def _eth_receive_reverts(self, tx: Tx) -> bool | None:
        try:
            self.rpc("eth_call", [{"from": tx.sender, "to": tx.to, "data": "0x",
                                   "value": hex(tx.value)}, self.block])
            return False
        except RuntimeError:
            return True

    def _v2_reserves(self, t_in: str, t_out: str) -> tuple[float, float] | None:
        pair = _addr(self._call(self.factory, GET_PAIR + _word(int(t_in, 16))
                                + _word(int(t_out, 16))))
        if int(pair, 16) == 0:
            return None
        raw = self._call(pair, GET_RESERVES)[2:]
        r0, r1 = int(raw[:64], 16), int(raw[64:128], 16)
        reserve_in, reserve_out = (r0, r1) if int(t_in, 16) < int(t_out, 16) else (r1, r0)
        return float(reserve_in), float(reserve_out)

    def _attach_swap(self, res: SimResult, s: SwapIntent) -> None:
        if s.protocol == "v2":
            hops = []
            for a, b in zip(s.path, s.path[1:]):
                r = self._try(lambda a=a, b=b: self._v2_reserves(a, b))
                if r is None:
                    return
                hops.append(Hop(r[0], r[1]))
            if len(hops) == 1:
                res.swap = Swap(float(s.amount_in), float(s.min_out), hops[0].reserve_in,
                                hops[0].reserve_out)
            else:
                res.path_swap = PathSwap(float(s.amount_in), float(s.min_out), tuple(hops))
        elif s.protocol == "v3" and len(s.path) == 2 and s.fees:
            v3 = self._try(lambda: self._v3_state(s.path[0], s.path[1], s.fees[0]))
            if v3 is not None:
                res.swap_v3 = V3Swap(float(s.amount_in), float(s.min_out), v3["sqrt_price"],
                                     v3["liquidity"], s.fees[0] / V3_FEE_DENOM, v3["zero_for_one"],
                                     v3["ticks"])

    def _v3_state(self, t_in: str, t_out: str, fee: int) -> dict[str, Any]:
        pool = _addr(self._call(self.options.v3_factory,
                                GET_POOL + _word(int(t_in, 16)) + _word(int(t_out, 16))
                                + _word(fee)))
        if int(pool, 16) == 0:
            raise KeyError("no pool")
        slot0 = self._call(pool, SLOT0)[2:]
        sqrt_x96 = int(slot0[:64], 16)
        tick = _int_word(slot0[64:128])
        liquidity = _uint(self._call(pool, LIQUIDITY))
        zero_for_one = int(t_in, 16) < int(t_out, 16)
        ticks: tuple[V3Tick, ...] = ()
        if self.options.v3_ticks:
            ticks = self._try(lambda: self._v3_ticks(pool, tick)) or ()
        return {"sqrt_price": sqrt_x96 / 2**96, "liquidity": float(liquidity),
                "zero_for_one": zero_for_one, "ticks": ticks}

    def _v3_ticks(self, pool: str, current_tick: int) -> tuple[V3Tick, ...]:
        spacing = _int_word(self._call(pool, TICK_SPACING)[2:]) or 60
        compressed = current_tick // spacing
        word = compressed >> 8
        found: list[int] = []
        for w in range(word - self.options.tick_words, word + self.options.tick_words + 1):
            bitmap = _uint(self._call(pool, TICK_BITMAP + _word(w % (1 << 256))))
            if bitmap == 0:
                continue
            found.extend((w * 256 + bit) * spacing for bit in range(256) if bitmap >> bit & 1)
        found.sort(key=lambda t: abs(t - current_tick))
        ticks = []
        for t in found[:self.options.max_ticks]:
            raw = self._call(pool, TICKS + _word(t % (1 << 256)))[2:]
            net = _int_word(raw[64:128])
            ticks.append(V3Tick(t, float(net)))
        return tuple(sorted(ticks, key=lambda x: x.tick))

    def _lp_event(self, tx: Tx, lp: LPIntent) -> LPEvent:
        if lp.protocol == "v2":
            pair = self._try(lambda: _addr(self._call(
                self.factory, GET_PAIR + _word(int(lp.token_a, 16)) + _word(int(lp.token_b, 16)))))
            total = None
            if pair and int(pair, 16):
                total = self._try(lambda: float(_uint(self._call(pair, TOTAL_SUPPLY))))
            return LPEvent(lp.action, pair or f"{lp.token_a}/{lp.token_b}", float(lp.liquidity),
                           total, "v2")
        # v3: position -> pool -> in-range liquidity
        total = None
        pool_id = f"v3-position-{lp.token_id}"
        try:
            raw = self._call(self.options.v3_position_manager, POSITIONS + _word(lp.token_id or 0))
            words = [raw[2:][i:i + 64] for i in range(0, len(raw) - 2, 64)]
            token0, token1, fee = _addr(words[2]), _addr(words[3]), int(words[4], 16)
            pool = _addr(self._call(self.options.v3_factory, GET_POOL + _word(int(token0, 16))
                                    + _word(int(token1, 16)) + _word(fee)))
            total = float(_uint(self._call(pool, LIQUIDITY)))
            pool_id = pool
        except (RuntimeError, AbiError, ValueError, IndexError, TypeError, KeyError):
            pass  # best effort: an unresolved position leaves total=None, which simulate() reports
        return LPEvent(lp.action, pool_id, float(lp.liquidity), total, "v3")

    # ---- honeypot probe
    def _simulate_calls(self, calls: list[dict[str, Any]], overrides: dict[str, Any]
                        ) -> list[dict[str, Any]]:
        block = {"calls": calls, "stateOverrides": overrides}
        out = self.rpc("eth_simulateV1", [{"blockStateCalls": [block], "validation": False,
                                            "traceTransfers": False}, self.block])
        return out[0]["calls"]

    def _probe_honeypot(self, tx: Tx, token: str) -> HoneypotProbe | None:
        opt = self.options
        router, weth, sender, value = opt.v2_router, opt.weth, tx.sender, opt.probe_value_wei
        buy = {"from": sender, "to": router, "value": hex(value), "data": encode_call(
            "swapExactETHForTokens(uint256,address[],address,uint256)",
            [0, [weth, token], sender, FAR_DEADLINE])}
        bal = {"from": sender, "to": token, "data": BALANCE_OF + _word(int(sender, 16))}
        overrides = {sender: {"balance": hex(10**21)}}
        try:
            phase1 = self._simulate_calls([bal, buy, bal], overrides)
        except RuntimeError as e:
            if isinstance(e, RpcError) and e.unsupported:
                return self._quote_probe(tx, token)
            return None
        except (KeyError, IndexError, TypeError):
            return None
        pre, buy_res, post = phase1[0], phase1[1], phase1[2]
        if _uint(buy_res.get("status", "0x0")) != 1:
            reason = decode_revert((buy_res.get("error") or {}).get("data")) or \
                (buy_res.get("error") or {}).get("message")
            return HoneypotProbe("simulate", False, False, float(value), 0.0, 0.0, 0.0,
                                 note=f"buy reverted: {reason}")
        quoted = float(decode(["uint256[]"], buy_res["returnData"])[0][-1])
        bought = float(_uint(post.get("returnData", "0x")) - _uint(pre.get("returnData", "0x")))
        buy_tax = max(0.0, 1.0 - bought / quoted) if quoted > 0 else 0.0
        approve = {"from": sender, "to": token, "data": encode_call(
            "approve(address,uint256)", [router, int(bought)])}

        def sell_call(sig: str) -> dict[str, Any]:
            return {"from": sender, "to": router, "data": encode_call(
                sig, [int(bought), 0, [token, weth], sender, FAR_DEADLINE])}

        sell = sell_call("swapExactTokensForETH(uint256,uint256,address[],address,uint256)")
        try:
            phase2 = self._simulate_calls([buy, approve, sell], overrides)
        except (RuntimeError, KeyError, IndexError, TypeError):
            return None
        sell_res = phase2[2]
        if _uint(sell_res.get("status", "0x0")) == 1:
            returned = float(decode(["uint256[]"], sell_res["returnData"])[0][-1])
            loss = max(0.0, 1.0 - returned / value)
            return HoneypotProbe("simulate", True, True, float(value), bought, returned, loss,
                                 note=f"buy tax {buy_tax:.1%}" if buy_tax > 0.001 else "")
        reason = decode_revert((sell_res.get("error") or {}).get("data")) or \
            (sell_res.get("error") or {}).get("message") or "sell reverted"
        sell_fot = sell_call(
            "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)")
        try:
            phase3 = self._simulate_calls([buy, approve, sell_fot], overrides)
        except (RuntimeError, KeyError, IndexError, TypeError):
            return HoneypotProbe("simulate", True, False, float(value), bought, 0.0, 1.0, reason)
        if _uint(phase3[2].get("status", "0x0")) != 1:
            r2 = decode_revert((phase3[2].get("error") or {}).get("data")) or reason
            return HoneypotProbe("simulate", True, False, float(value), bought, 0.0, 1.0, r2)
        # fee-on-transfer token: sell works through the FoT variant; quote the post-tax amount,
        # assuming the sell tax mirrors the buy tax.
        quote = self._try(lambda: decode(["uint256[]"], self._call(router, encode_call(
            "getAmountsOut(uint256,address[])", [int(bought * (1 - buy_tax)), [token, weth]])))[0][-1])
        returned = float(quote or 0.0)
        loss = max(0.0, 1.0 - returned / value) if quote else 2 * buy_tax
        return HoneypotProbe("simulate", True, True, float(value), bought, returned, loss,
                             note=f"fee-on-transfer token; buy tax {buy_tax:.1%}, sell tax assumed "
                                  "symmetric")

    def _quote_probe(self, tx: Tx, token: str) -> HoneypotProbe | None:
        opt = self.options
        router, weth, value = opt.v2_router, opt.weth, opt.probe_value_wei
        try:
            buy = decode(["uint256[]"], self._call(router, encode_call(
                "getAmountsOut(uint256,address[])", [value, [weth, token]])))[0][-1]
            sell = decode(["uint256[]"], self._call(router, encode_call(
                "getAmountsOut(uint256,address[])", [int(buy), [token, weth]])))[0][-1]
        except RuntimeError as e:
            return HoneypotProbe("quote", False, False, float(value), 0.0, 0.0, 0.0,
                                 note=f"quote failed: {e}", taxes_observable=False)
        except (AbiError, IndexError):
            return None
        loss = max(0.0, 1.0 - sell / value)
        return HoneypotProbe("quote", True, True, float(value), float(buy), float(sell), loss,
                             taxes_observable=False,
                             note="node lacks eth_simulateV1; transfer taxes not observable")

    # ---- trace
    def _trace(self, call: dict[str, Any]) -> CallFrame | None:
        raw = self._try(lambda: self.rpc("debug_traceCall", [call, self.block,
                                                              {"tracer": "callTracer"}]))
        if not isinstance(raw, dict) or ("type" not in raw and "kind" not in raw):
            return None
        return self._try(lambda: CallFrame.from_dict(raw))


def decode_calldata(data: str) -> dict[str, Any]:
    """Backward-compatible flat view of ``abi.decode_call`` for the handful of original kinds."""
    call = decode_call(data)
    a = call.args
    if call.kind == "erc20_approve":
        return {"kind": "approve", "spender": a["spender"], "amount": a["amount"]}
    if call.kind == "erc20_transfer":
        return {"kind": "transfer", "to": a["to"], "amount": a["amount"]}
    if call.kind == "v2_swap_exact_tokens_for_tokens":
        return {"kind": "v2_swap", "amount_in": a["amount_in"], "min_out": a["amount_out_min"],
                "path": a["path"], "to": a["to"]}
    return {"kind": call.kind if call.kind in ("empty", "malformed") else "unknown",
            "selector": call.selector, "name": call.name}
