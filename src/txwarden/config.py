"""TOML configuration for the CLI and MCP server.

Uses ``tomllib`` on Python 3.11+. On 3.10 a small built-in parser covers the subset this
project's config needs (tables, dotted tables, strings, numbers, booleans, arrays), so there is
still no runtime dependency.

Example::

    rpc_url = "http://127.0.0.1:8545"
    address_book = "~/.txwarden/book.json"

    [policy]
    trusted_spenders = ["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"]
    slippage_block = 0.03
    expected_chain_id = 1
    disabled_rules = ["GAS_ABNORMAL"]

    [policy.address_book]
    "0x1111111111111111111111111111111111111111" = "cold wallet"

    [simulator]
    honeypot = true
    trace = true
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .addressbook import AddressBook
from .risk import PolicyConfig
from .simulator import SimulatorOptions

try:  # Python 3.11+
    import tomllib as _tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.10 only
    _tomllib = None


class ConfigError(ValueError):
    pass


# --------------------------------------------------------------------------- mini TOML parser

_KEY_RE = re.compile(r'^(?:"([^"]*)"|\'([^\']*)\'|([A-Za-z0-9_\-]+))\s*=\s*(.*)$')
_TABLE_RE = re.compile(r"^\[([^\]]+)\]\s*$")


def _strip_comment(line: str) -> str:
    out, in_str, quote = [], False, ""
    for ch in line:
        if in_str:
            out.append(ch)
            if ch == quote:
                in_str = False
        elif ch in ("\"", "'"):
            in_str, quote = True, ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).strip()


def _parse_scalar(s: str) -> Any:
    s = s.strip()
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return bytes(s[1:-1], "utf-8").decode("unicode_escape")
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1]
    if s in ("true", "false"):
        return s == "true"
    if re.fullmatch(r"[+-]?\d[\d_]*", s):
        return int(s.replace("_", ""))
    if re.fullmatch(r"[+-]?(\d[\d_]*)?\.?\d[\d_]*([eE][+-]?\d+)?", s):
        return float(s.replace("_", ""))
    if s.startswith("0x"):
        return int(s, 16)
    raise ConfigError(f"cannot parse value {s!r}")


def _split_array(body: str) -> list[str]:
    parts, cur, in_str, quote, depth = [], [], False, "", 0
    for ch in body:
        if in_str:
            cur.append(ch)
            if ch == quote:
                in_str = False
            continue
        if ch in ("\"", "'"):
            in_str, quote = True, ch
            cur.append(ch)
        elif ch == "[":
            depth += 1
            cur.append(ch)
        elif ch == "]":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return [p.strip() for p in parts if p.strip()]


def _parse_value(s: str) -> Any:
    s = s.strip()
    if s.startswith("[") and s.endswith("]"):
        return [_parse_value(p) for p in _split_array(s[1:-1])]
    return _parse_scalar(s)


def _split_table_path(path: str) -> list[str]:
    parts, cur, in_str, quote = [], [], False, ""
    for ch in path:
        if in_str:
            if ch == quote:
                in_str = False
            else:
                cur.append(ch)
        elif ch in ("\"", "'"):
            in_str, quote = True, ch
        elif ch == ".":
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return parts


def _bracket_depth(s: str) -> int:
    """Net number of unclosed ``[`` outside string literals."""
    depth, in_str, quote = 0, False, ""
    for ch in s:
        if in_str:
            if ch == quote:
                in_str = False
        elif ch in ("\"", "'"):
            in_str, quote = True, ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
    return depth


def parse_toml_subset(text: str) -> dict[str, Any]:
    """Parse the TOML subset used by TxWarden configs (fallback for Python 3.10)."""
    root: dict[str, Any] = {}
    table = root
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = _strip_comment(lines[i])
        i += 1
        if not line:
            continue
        m = _TABLE_RE.match(line)
        if m:
            table = root
            for part in _split_table_path(m.group(1)):
                table = table.setdefault(part, {})
                if not isinstance(table, dict):
                    raise ConfigError(f"{part} is not a table")
            continue
        m = _KEY_RE.match(line)
        if not m:
            raise ConfigError(f"cannot parse line: {line!r}")
        key = m.group(1) or m.group(2) or m.group(3)
        value = m.group(4)
        # multi-line arrays (brackets inside strings do not count)
        while _bracket_depth(value) > 0 and i < len(lines):
            value += " " + _strip_comment(lines[i])
            i += 1
        table[key] = _parse_value(value)
    return root


def parse_toml(text: str) -> dict[str, Any]:
    if _tomllib is not None:
        try:
            return _tomllib.loads(text)
        except _tomllib.TOMLDecodeError as e:
            raise ConfigError(str(e)) from e
    return parse_toml_subset(text)


# --------------------------------------------------------------------------- app config

@dataclass
class AppConfig:
    rpc_url: str | None = None
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    simulator: SimulatorOptions = field(default_factory=SimulatorOptions)
    address_book: AddressBook = field(default_factory=AddressBook.builtin)
    trust_well_known: bool = False
    model: str | None = None

    def effective_policy(self) -> PolicyConfig:
        """Policy with address-book labels merged in (and well-known routers trusted if asked)."""
        pol = PolicyConfig.from_dict(self.policy.to_dict())
        pol.address_book = {**self.address_book.labels(), **pol.address_book}
        if self.trust_well_known:
            pol.trusted_spenders |= self.address_book.by_kind("router", "permit2")
            pol.trusted_operators |= self.address_book.by_kind("operator", "marketplace")
        return pol


def config_from_dict(d: dict[str, Any], base_dir: Path | None = None) -> AppConfig:
    cfg = AppConfig()
    cfg.rpc_url = d.get("rpc_url")
    cfg.trust_well_known = bool(d.get("trust_well_known", False))
    cfg.model = d.get("model")
    pol = dict(d.get("policy", {}))
    try:
        cfg.policy = PolicyConfig.from_dict(pol)
    except (ValueError, TypeError) as e:
        raise ConfigError(f"policy: {e}") from e
    sim = d.get("simulator", {})
    allowed = {f.name for f in fields(SimulatorOptions)}
    bad = set(sim) - allowed
    if bad:
        raise ConfigError(f"simulator: unknown keys {sorted(bad)}")
    cfg.simulator = SimulatorOptions(**sim)
    book = AddressBook.builtin() if d.get("builtin_address_book", True) else AddressBook()
    path = d.get("address_book")
    if path:
        p = Path(path).expanduser()
        if not p.is_absolute() and base_dir is not None:
            p = base_dir / p
        book = book.merge(AddressBook.load(p))
    cfg.address_book = book
    return cfg


def load_config(path: str | Path) -> AppConfig:
    p = Path(path)
    return config_from_dict(parse_toml(p.read_text()), p.parent)
