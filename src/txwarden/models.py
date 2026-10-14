"""Plain dataclasses shared by the simulator, risk engine, batch analyser and agent.

Everything here is JSON round-trippable through ``to_dict``/``from_dict`` so simulations can be
recorded as fixtures and replayed offline.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any

ETH = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"  # sentinel token address for native ETH


class Severity(IntEnum):
    INFO = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


VERDICT_ORDER = {Verdict.ALLOW: 0, Verdict.WARN: 1, Verdict.BLOCK: 2}


def worst_verdict(*verdicts: Verdict) -> Verdict:
    return max(verdicts, key=lambda v: VERDICT_ORDER[v], default=Verdict.ALLOW)


@dataclass(frozen=True)
class Tx:
    sender: str
    to: str
    data: str = "0x"
    value: int = 0
    chain_id: int = 1

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Tx:
        return cls(
            sender=str(d["sender"]).lower(),
            to=str(d["to"]).lower(),
            data=d.get("data") or "0x",
            value=int(d.get("value", 0)),
            chain_id=int(d.get("chain_id", 1)),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Approval:
    token: str
    owner: str
    spender: str
    amount: int
    via: str = ""  # "" for a direct ERC-20 approve, "permit2" for Permit2.approve
    expiration: int | None = None


@dataclass(frozen=True)
class OperatorApproval:
    """``setApprovalForAll`` on an ERC-721 or ERC-1155 collection."""

    token: str
    owner: str
    operator: str
    approved: bool
    standard: str = "unknown"  # erc721 | erc1155 | unknown


@dataclass(frozen=True)
class Permit:
    """A signature-based allowance the user is being asked to authorise."""

    token: str
    owner: str
    spender: str
    amount: int
    deadline: int
    kind: str = "eip2612"  # eip2612 | dai | permit2


@dataclass(frozen=True)
class Transfer:
    token: str
    sender: str
    recipient: str
    amount: int
    sender_balance_before: int | None = None
    kind: str = "erc20"  # erc20 | erc721 | erc1155 | eth
    operator: str | None = None  # who pulled the tokens (transferFrom / Permit2), if not sender
    token_id: int | None = None


@dataclass(frozen=True)
class Swap:
    """Constant-product (Uniswap V2 style) single-hop swap context.

    Amounts are in raw token units. ``reserve_in``/``reserve_out`` are pool reserves
    *before* the transaction executes. ``min_out`` is the user's slippage floor.
    """

    amount_in: float
    min_out: float
    reserve_in: float
    reserve_out: float
    fee: float = 0.003


@dataclass(frozen=True)
class Hop:
    reserve_in: float
    reserve_out: float
    fee: float = 0.003


@dataclass(frozen=True)
class PathSwap:
    """Multi-hop constant-product route (Uniswap V2 ``path`` with more than two tokens)."""

    amount_in: float
    min_out: float
    hops: tuple[Hop, ...]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PathSwap:
        return cls(float(d["amount_in"]), float(d["min_out"]),
                   tuple(Hop(**h) for h in d["hops"]))


@dataclass(frozen=True)
class V3Tick:
    tick: int
    liquidity_net: float  # liquidity added when the price crosses this tick upward


@dataclass(frozen=True)
class V3Swap:
    """Uniswap V3 concentrated-liquidity swap context.

    ``sqrt_price`` is sqrt(token1/token0) in raw units (``sqrtPriceX96 / 2**96``).
    ``liquidity`` is the in-range liquidity at ``sqrt_price``. ``ticks`` lists initialised ticks
    with their ``liquidityNet``; an empty tuple means "treat the current range as unbounded".
    """

    amount_in: float
    min_out: float
    sqrt_price: float
    liquidity: float
    fee: float = 0.003
    zero_for_one: bool = True
    ticks: tuple[V3Tick, ...] = ()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> V3Swap:
        return cls(
            float(d["amount_in"]), float(d["min_out"]), float(d["sqrt_price"]),
            float(d["liquidity"]), float(d.get("fee", 0.003)), bool(d.get("zero_for_one", True)),
            tuple(V3Tick(int(t["tick"]), float(t["liquidity_net"])) for t in d.get("ticks", ())),
        )


@dataclass(frozen=True)
class AccountInfo:
    address: str
    code_size: int = 0
    nonce: int = 0
    balance: int = 0

    @property
    def is_contract(self) -> bool:
        return self.code_size > 0

    @property
    def is_fresh(self) -> bool:
        """Never used: no code, no outgoing transactions and no ETH."""
        return self.code_size == 0 and self.nonce == 0 and self.balance == 0


@dataclass(frozen=True)
class HoneypotProbe:
    """Result of buying then selling a token in simulation."""

    mode: str  # "simulate" (state-chained calls) | "quote" (router quotes only)
    buy_ok: bool
    sell_ok: bool
    amount_in: float
    bought: float
    returned: float
    loss_fraction: float
    sell_revert_reason: str | None = None
    taxes_observable: bool = True
    note: str = ""


@dataclass(frozen=True)
class LPEvent:
    action: str  # add | remove
    pool: str
    liquidity: float
    pool_total: float | None = None
    protocol: str = "v2"

    @property
    def fraction(self) -> float | None:
        if not self.pool_total:
            return None
        return min(1.0, self.liquidity / self.pool_total)


@dataclass
class CallFrame:
    """One frame of a ``debug_traceCall`` (callTracer) style call tree."""

    kind: str  # CALL | DELEGATECALL | STATICCALL | CALLCODE | CREATE | CREATE2 | SELFDESTRUCT
    sender: str
    to: str
    value: int = 0
    input: str = "0x"
    error: str | None = None
    calls: list[CallFrame] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CallFrame:
        """Accepts both this module's ``to_dict`` layout and raw geth callTracer output."""
        value = d.get("value", 0)
        if isinstance(value, str):
            value = int(value, 16) if value.startswith("0x") else int(value or 0)
        return cls(
            kind=str(d.get("kind") or d.get("type") or "CALL").upper(),
            sender=str(d.get("sender") or d.get("from") or "").lower(),
            to=str(d.get("to") or "").lower(),
            value=int(value),
            input=d.get("input", "0x") or "0x",
            error=d.get("error"),
            calls=[cls.from_dict(c) for c in d.get("calls", []) or []],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def walk(self, depth: int = 0) -> Iterator[tuple[int, CallFrame]]:
        yield depth, self
        for c in self.calls:
            yield from c.walk(depth + 1)

    @property
    def selector(self) -> str:
        return self.input[:10] if len(self.input) >= 10 else self.input


@dataclass
class SimResult:
    success: bool
    gas_used: int = 0
    revert_reason: str | None = None
    approvals: list[Approval] = field(default_factory=list)
    transfers: list[Transfer] = field(default_factory=list)
    swap: Swap | None = None
    path_swap: PathSwap | None = None
    swap_v3: V3Swap | None = None
    operator_approvals: list[OperatorApproval] = field(default_factory=list)
    permits: list[Permit] = field(default_factory=list)
    lp_events: list[LPEvent] = field(default_factory=list)
    accounts: dict[str, AccountInfo] = field(default_factory=dict)
    honeypot: HoneypotProbe | None = None
    call_tree: CallFrame | None = None
    chain_id: int | None = None
    block_timestamp: int | None = None
    call_kind: str | None = None
    decoded: dict[str, Any] | None = None
    eth_receive_reverts: bool | None = None
    labels: dict[str, str] = field(default_factory=dict)  # token/contract names seen on-chain
    error: str | None = None  # simulator infrastructure failure (RPC down, timeout): no analysis
    incomplete: list[str] = field(default_factory=list)  # analyses the simulator could not run
    output_recipients: list[str] = field(default_factory=list)  # who receives swap/router output

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SimResult:
        swap = d.get("swap")
        path_swap = d.get("path_swap")
        swap_v3 = d.get("swap_v3")
        honeypot = d.get("honeypot")
        tree = d.get("call_tree")
        return cls(
            success=bool(d["success"]),
            gas_used=int(d.get("gas_used", 0)),
            revert_reason=d.get("revert_reason"),
            approvals=[Approval(**a) for a in d.get("approvals", [])],
            transfers=[Transfer(**t) for t in d.get("transfers", [])],
            swap=Swap(**swap) if swap else None,
            path_swap=PathSwap.from_dict(path_swap) if path_swap else None,
            swap_v3=V3Swap.from_dict(swap_v3) if swap_v3 else None,
            operator_approvals=[OperatorApproval(**o) for o in d.get("operator_approvals", [])],
            permits=[Permit(**p) for p in d.get("permits", [])],
            lp_events=[LPEvent(**e) for e in d.get("lp_events", [])],
            accounts={k.lower(): AccountInfo(**v) for k, v in d.get("accounts", {}).items()},
            honeypot=HoneypotProbe(**honeypot) if honeypot else None,
            call_tree=CallFrame.from_dict(tree) if tree else None,
            chain_id=d.get("chain_id"),
            block_timestamp=d.get("block_timestamp"),
            call_kind=d.get("call_kind"),
            decoded=d.get("decoded"),
            eth_receive_reverts=d.get("eth_receive_reverts"),
            labels=dict(d.get("labels", {})),
            error=d.get("error"),
            incomplete=list(d.get("incomplete", [])),
            output_recipients=[str(a).lower() for a in d.get("output_recipients", [])],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def all_counterparties(self) -> set[str]:
        """Every address that receives value or authority from this transaction."""
        out: set[str] = set()
        out.update(a.spender.lower() for a in self.approvals)
        out.update(o.operator.lower() for o in self.operator_approvals)
        out.update(p.spender.lower() for p in self.permits)
        out.update(t.recipient.lower() for t in self.transfers)
        return out


@dataclass
class Finding:
    rule: str
    severity: Severity
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.name,
            "message": self.message,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        return cls(d["rule"], Severity[d["severity"]], d["message"], dict(d.get("data", {})))
