"""Plain dataclasses shared by the simulator, risk engine and agent."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


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
            sender=d["sender"].lower(),
            to=d["to"].lower(),
            data=d.get("data", "0x"),
            value=int(d.get("value", 0)),
            chain_id=int(d.get("chain_id", 1)),
        )


@dataclass(frozen=True)
class Approval:
    token: str
    owner: str
    spender: str
    amount: int


@dataclass(frozen=True)
class Transfer:
    token: str
    sender: str
    recipient: str
    amount: int
    sender_balance_before: int | None = None


@dataclass(frozen=True)
class Swap:
    """Constant-product (Uniswap V2 style) swap context.

    Amounts are in raw token units. ``reserve_in``/``reserve_out`` are pool reserves
    *before* the transaction executes. ``min_out`` is the user's slippage floor.
    """

    amount_in: float
    min_out: float
    reserve_in: float
    reserve_out: float
    fee: float = 0.003


@dataclass
class SimResult:
    success: bool
    gas_used: int = 0
    revert_reason: str | None = None
    approvals: list[Approval] = field(default_factory=list)
    transfers: list[Transfer] = field(default_factory=list)
    swap: Swap | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SimResult:
        swap = d.get("swap")
        return cls(
            success=bool(d["success"]),
            gas_used=int(d.get("gas_used", 0)),
            revert_reason=d.get("revert_reason"),
            approvals=[Approval(**a) for a in d.get("approvals", [])],
            transfers=[Transfer(**t) for t in d.get("transfers", [])],
            swap=Swap(**swap) if swap else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
