"""Address labels: a built-in registry of well-known mainnet contracts plus user-supplied books.

Also home of the address-poisoning ("lookalike") check: attackers generate vanity addresses that
share the first and last few hex characters with an address the victim has interacted with,
because wallets truncate addresses to exactly that view.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from .keccak import is_checksum_address, to_checksum_address


@dataclass(frozen=True)
class Label:
    address: str  # lowercase
    name: str
    kind: str = "unknown"
    chain_id: int = 1

    @property
    def checksum(self) -> str:
        return to_checksum_address(self.address)


def lookalike(candidate: str, reference: str, prefix: int = 4, suffix: int = 4) -> bool:
    """True if ``candidate`` != ``reference`` but they match on the first ``prefix`` and last
    ``suffix`` hex characters (the parts a truncated wallet UI shows)."""
    a, b = candidate.lower().removeprefix("0x"), reference.lower().removeprefix("0x")
    if a == b or len(a) != 40 or len(b) != 40:
        return False
    return a[:prefix] == b[:prefix] and (suffix == 0 or a[-suffix:] == b[-suffix:])


class AddressBook:
    def __init__(self, entries: dict[str, Label] | None = None):
        self._entries: dict[str, Label] = dict(entries or {})

    # ---- construction
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AddressBook:
        book = cls()
        chain = int(d.get("chain_id", 1))
        for e in d.get("entries", []):
            book.add(e["address"], e["name"], e.get("kind", "unknown"), int(e.get("chain_id", chain)))
        for addr, name in d.get("labels", {}).items():  # compact {address: name} form
            book.add(addr, str(name))
        return book

    @classmethod
    def builtin(cls) -> AddressBook:
        text = resources.files("txwarden").joinpath("data/addressbook.json").read_text()
        return cls.from_dict(json.loads(text))

    @classmethod
    def load(cls, path: str | Path) -> AddressBook:
        return cls.from_dict(json.loads(Path(path).read_text()))

    def add(self, address: str, name: str, kind: str = "unknown", chain_id: int = 1) -> None:
        if not is_checksum_address(address):
            raise ValueError(f"bad address or checksum: {address}")
        self._entries[address.lower()] = Label(address.lower(), name, kind, chain_id)

    def merge(self, other: AddressBook) -> AddressBook:
        merged = AddressBook(self._entries)
        merged._entries.update(other._entries)
        return merged

    # ---- queries
    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, address: str) -> bool:
        return address.lower() in self._entries

    def get(self, address: str) -> Label | None:
        return self._entries.get(address.lower())

    def name(self, address: str) -> str | None:
        lbl = self.get(address)
        return lbl.name if lbl else None

    def by_kind(self, *kinds: str) -> set[str]:
        return {a for a, lbl in self._entries.items() if lbl.kind in kinds}

    def addresses(self) -> set[str]:
        return set(self._entries)

    def labels(self) -> dict[str, str]:
        return {a: lbl.name for a, lbl in self._entries.items()}

    def entries(self) -> list[Label]:
        return sorted(self._entries.values(), key=lambda lbl: lbl.name.lower())

    def lookalikes(self, address: str, prefix: int = 4, suffix: int = 4) -> list[Label]:
        return [lbl for lbl in self._entries.values()
                if lookalike(address, lbl.address, prefix, suffix)]

    def to_dict(self) -> dict[str, Any]:
        return {"entries": [{"address": lbl.checksum, "name": lbl.name, "kind": lbl.kind,
                             "chain_id": lbl.chain_id} for lbl in self.entries()]}
