"""Generic ABI codec and calldata decoder.

- ``parse_type`` / ``encode`` / ``decode`` implement the Solidity ABI for static types, dynamic
  ``bytes``/``string``, fixed and dynamic arrays, and (nested) tuples.
- ``SELECTORS`` is a registry of the function selectors the guard understands, each with its
  canonical signature, a machine ``kind`` and a human name. Selector values are hard-coded for a
  cheap import and verified against ``keccak.selector`` in the test suite.
- ``decode_call`` turns raw calldata into a ``DecodedCall`` tree. Uniswap V3 path bytes,
  Universal Router command bytes and Multicall payloads are decoded recursively.

Decoding never raises on hostile input: malformed calldata produces ``kind="malformed"`` so the
risk engine can treat it as unknown rather than crash.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

MAX_DEPTH = 4
_WORD = 32


class AbiError(ValueError):
    """Raised on malformed types, values or data."""


# --------------------------------------------------------------------------- types

@dataclass(frozen=True)
class AbiType:
    base: str  # uint | int | address | bool | bytes | string | array | tuple
    size: int = 0  # bit width for uint/int, byte length for fixed bytes (0 = dynamic bytes)
    elem: AbiType | None = None
    length: int = -1  # array length, -1 for dynamic
    components: tuple[AbiType, ...] = ()

    @property
    def is_dynamic(self) -> bool:
        if self.base in ("string",) or (self.base == "bytes" and self.size == 0):
            return True
        if self.base == "array":
            assert self.elem is not None
            return self.length < 0 or self.elem.is_dynamic
        if self.base == "tuple":
            return any(c.is_dynamic for c in self.components)
        return False

    @property
    def static_size(self) -> int:
        if self.is_dynamic:
            return _WORD
        if self.base == "array":
            assert self.elem is not None
            return self.length * self.elem.static_size
        if self.base == "tuple":
            return sum(c.static_size for c in self.components)
        return _WORD

    def __str__(self) -> str:
        if self.base in ("uint", "int"):
            return f"{self.base}{self.size}"
        if self.base == "bytes":
            return "bytes" if self.size == 0 else f"bytes{self.size}"
        if self.base == "array":
            return f"{self.elem}[{'' if self.length < 0 else self.length}]"
        if self.base == "tuple":
            return "(" + ",".join(str(c) for c in self.components) + ")"
        return self.base


_ARRAY_RE = re.compile(r"^(.*)\[(\d*)\]$")
_NUM_RE = re.compile(r"^(u?int)(\d*)$")
_BYTES_RE = re.compile(r"^bytes(\d*)$")


def _split_top_level(s: str) -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise AbiError(f"unbalanced parentheses in {s!r}")
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if depth != 0:
        raise AbiError(f"unbalanced parentheses in {s!r}")
    if cur or parts:
        parts.append("".join(cur))
    return parts


@lru_cache(maxsize=512)
def parse_type(s: str) -> AbiType:
    s = s.replace(" ", "")
    if not s:
        raise AbiError("empty type")
    m = _ARRAY_RE.match(s)
    if m and s.endswith("]"):
        inner, n = m.group(1), m.group(2)
        # make sure the bracket belongs to the outermost level, e.g. "(uint256[])[2]"
        if inner.count("(") == inner.count(")"):
            return AbiType("array", elem=parse_type(inner), length=int(n) if n else -1)
    if s.startswith("(") and s.endswith(")"):
        body = s[1:-1]
        comps = tuple(parse_type(p) for p in _split_top_level(body)) if body else ()
        return AbiType("tuple", components=comps)
    m = _NUM_RE.match(s)
    if m:
        bits = int(m.group(2) or 256)
        if bits % 8 or not 8 <= bits <= 256:
            raise AbiError(f"bad integer width in {s!r}")
        return AbiType(m.group(1), size=bits)
    m = _BYTES_RE.match(s)
    if m:
        n = int(m.group(1) or 0)
        if n > 32:
            raise AbiError(f"bad bytes width in {s!r}")
        return AbiType("bytes", size=n)
    if s in ("address", "bool", "string"):
        return AbiType(s)
    raise AbiError(f"unknown type {s!r}")


def signature_types(signature: str) -> tuple[AbiType, ...]:
    """``"foo(address,(uint256,bytes)[])"`` -> parsed parameter types."""
    i = signature.find("(")
    if i < 0 or not signature.endswith(")"):
        raise AbiError(f"bad signature {signature!r}")
    return parse_type(signature[i:]).components


# --------------------------------------------------------------------------- encoding

def _to_int(v: Any) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 16) if v.startswith("0x") else int(v)
    raise AbiError(f"cannot coerce {v!r} to int")


def _to_bytes(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        h = v.removeprefix("0x")
        if len(h) % 2:
            raise AbiError(f"odd-length hex {v!r}")
        try:
            return bytes.fromhex(h)
        except ValueError as e:
            raise AbiError(f"not hex: {v[:16]!r}") from e
    raise AbiError(f"cannot coerce {v!r} to bytes")


def _encode_tuple(types: tuple[AbiType, ...], values: Any) -> bytes:
    values = list(values)
    if len(values) != len(types):
        raise AbiError(f"expected {len(types)} values, got {len(values)}")
    head_size = sum(t.static_size for t in types)
    heads: list[bytes] = []
    tails: list[bytes] = []
    tail_len = 0
    for t, v in zip(types, values):
        if t.is_dynamic:
            heads.append((head_size + tail_len).to_bytes(_WORD, "big"))
            enc = _encode(t, v)
            tails.append(enc)
            tail_len += len(enc)
        else:
            heads.append(_encode(t, v))
    return b"".join(heads) + b"".join(tails)


def _encode(t: AbiType, v: Any) -> bytes:
    if t.base == "uint":
        n = _to_int(v)
        if not 0 <= n < (1 << t.size):
            raise AbiError(f"{n} out of range for uint{t.size}")
        return n.to_bytes(_WORD, "big")
    if t.base == "int":
        n = _to_int(v)
        lim = 1 << (t.size - 1)
        if not -lim <= n < lim:
            raise AbiError(f"{n} out of range for int{t.size}")
        return (n % (1 << 256)).to_bytes(_WORD, "big")
    if t.base == "address":
        n = _to_int(v)
        if not 0 <= n < (1 << 160):
            raise AbiError(f"address out of range: {v!r}")
        return n.to_bytes(_WORD, "big")
    if t.base == "bool":
        return int(bool(v)).to_bytes(_WORD, "big")
    if t.base == "bytes" and t.size:
        b = _to_bytes(v)
        if len(b) > t.size:
            raise AbiError(f"bytes{t.size} value too long")
        return b.ljust(_WORD, b"\0")
    if t.base == "bytes":
        b = _to_bytes(v)
        return len(b).to_bytes(_WORD, "big") + b.ljust(-(-len(b) // _WORD) * _WORD, b"\0")
    if t.base == "string":
        b = v.encode() if isinstance(v, str) else bytes(v)
        return len(b).to_bytes(_WORD, "big") + b.ljust(-(-len(b) // _WORD) * _WORD, b"\0")
    if t.base == "array":
        assert t.elem is not None
        items = list(v)
        if t.length >= 0:
            if len(items) != t.length:
                raise AbiError(f"expected {t.length} elements, got {len(items)}")
            return _encode_tuple((t.elem,) * t.length, items)
        return len(items).to_bytes(_WORD, "big") + _encode_tuple((t.elem,) * len(items), items)
    if t.base == "tuple":
        return _encode_tuple(t.components, v)
    raise AbiError(f"cannot encode {t}")


def encode(types: list[str] | tuple[str, ...], values: Any) -> bytes:
    return _encode_tuple(tuple(parse_type(t) for t in types), values)


def encode_call(signature: str, values: Any = ()) -> str:
    """Hex calldata for ``signature`` with ``values`` (selector computed via keccak)."""
    from .keccak import selector as _selector

    return _selector(signature) + _encode_tuple(signature_types(signature), values).hex()


# --------------------------------------------------------------------------- decoding

def _word_at(data: bytes, pos: int) -> int:
    if pos < 0 or pos + _WORD > len(data):
        raise AbiError(f"read past end of data at offset {pos}")
    return int.from_bytes(data[pos:pos + _WORD], "big")


def _decode_static(t: AbiType, data: bytes, pos: int) -> Any:
    if t.base == "uint":
        n = _word_at(data, pos)
        if n >= (1 << t.size):
            raise AbiError(f"uint{t.size} overflow")
        return n
    if t.base == "int":
        n = _word_at(data, pos)
        n = n - (1 << 256) if n >> 255 else n
        lim = 1 << (t.size - 1)
        if not -lim <= n < lim:
            raise AbiError(f"int{t.size} overflow")
        return n
    if t.base == "address":
        n = _word_at(data, pos)
        if n >> 160:
            raise AbiError("address has dirty upper bits")
        return "0x" + f"{n:040x}"
    if t.base == "bool":
        n = _word_at(data, pos)
        if n > 1:
            raise AbiError("bool out of range")
        return bool(n)
    if t.base == "bytes":  # fixed
        if pos + _WORD > len(data):
            raise AbiError("read past end of data")
        return "0x" + data[pos:pos + t.size].hex()
    if t.base == "array":
        assert t.elem is not None
        return _decode_tuple((t.elem,) * t.length, data, pos)
    if t.base == "tuple":
        return _decode_tuple(t.components, data, pos)
    raise AbiError(f"cannot decode static {t}")


def _decode_dynamic(t: AbiType, data: bytes, at: int) -> Any:
    if t.base in ("bytes", "string"):
        n = _word_at(data, at)
        if at + _WORD + n > len(data):
            raise AbiError("dynamic length exceeds data")
        raw = data[at + _WORD:at + _WORD + n]
        return raw.decode("utf-8", errors="replace") if t.base == "string" else "0x" + raw.hex()
    if t.base == "array":
        assert t.elem is not None
        if t.length >= 0:
            return _decode_tuple((t.elem,) * t.length, data, at)
        n = _word_at(data, at)
        if n * _WORD > len(data):
            raise AbiError("array length exceeds data")
        return _decode_tuple((t.elem,) * n, data, at + _WORD)
    if t.base == "tuple":
        return _decode_tuple(t.components, data, at)
    raise AbiError(f"cannot decode dynamic {t}")


def _decode_tuple(types: tuple[AbiType, ...], data: bytes, base: int) -> list[Any]:
    out: list[Any] = []
    pos = base
    for t in types:
        if t.is_dynamic:
            off = _word_at(data, pos)
            if off > len(data):
                raise AbiError("offset exceeds data")
            out.append(_decode_dynamic(t, data, base + off))
            pos += _WORD
        else:
            out.append(_decode_static(t, data, pos))
            pos += t.static_size
    return out


def decode(types: list[str] | tuple[str, ...], data: bytes | str) -> list[Any]:
    raw = _to_bytes(data) if isinstance(data, str) else bytes(data)
    return _decode_tuple(tuple(parse_type(t) for t in types), raw, 0)


# --------------------------------------------------------------------------- selector registry

@dataclass(frozen=True)
class FunctionSpec:
    selector: str
    signature: str
    kind: str
    name: str
    protocol: str
    params: tuple[str, ...]

    @property
    def types(self) -> tuple[AbiType, ...]:
        return signature_types(self.signature)


_P = {  # param-name shorthands
    "approve": ("spender", "amount"),
    "transfer": ("to", "amount"),
    "transfer_from": ("from", "to", "amount"),
    "v2_tt": ("amount_in", "amount_out_min", "path", "to", "deadline"),
    "v2_tt_out": ("amount_out", "amount_in_max", "path", "to", "deadline"),
    "v2_et": ("amount_out_min", "path", "to", "deadline"),
    "v2_et_out": ("amount_out", "path", "to", "deadline"),
    "v2_add": ("token_a", "token_b", "amount_a_desired", "amount_b_desired", "amount_a_min",
               "amount_b_min", "to", "deadline"),
    "v2_add_eth": ("token", "amount_token_desired", "amount_token_min", "amount_eth_min", "to",
                   "deadline"),
    "v2_rm": ("token_a", "token_b", "liquidity", "amount_a_min", "amount_b_min", "to", "deadline"),
    "v2_rm_eth": ("token", "liquidity", "amount_token_min", "amount_eth_min", "to", "deadline"),
    "v2_rm_permit": ("token_a", "token_b", "liquidity", "amount_a_min", "amount_b_min", "to",
                     "deadline", "approve_max", "v", "r", "s"),
    "v2_rm_eth_permit": ("token", "liquidity", "amount_token_min", "amount_eth_min", "to",
                         "deadline", "approve_max", "v", "r", "s"),
}

_REGISTRY_ROWS: list[tuple[str, str, str, str, str, tuple[str, ...]]] = [
    # selector, signature, kind, human name, protocol, param names
    ("0x095ea7b3", "approve(address,uint256)", "erc20_approve", "ERC-20/721 approve", "erc20",
     _P["approve"]),
    ("0xa9059cbb", "transfer(address,uint256)", "erc20_transfer", "ERC-20 transfer", "erc20",
     _P["transfer"]),
    ("0x23b872dd", "transferFrom(address,address,uint256)", "erc20_transfer_from",
     "ERC-20/721 transferFrom", "erc20", _P["transfer_from"]),
    ("0x39509351", "increaseAllowance(address,uint256)", "erc20_increase_allowance",
     "ERC-20 increaseAllowance", "erc20", ("spender", "added_value")),
    ("0xa457c2d7", "decreaseAllowance(address,uint256)", "erc20_decrease_allowance",
     "ERC-20 decreaseAllowance", "erc20", ("spender", "subtracted_value")),
    ("0xd505accf", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
     "erc20_permit", "EIP-2612 permit", "erc20",
     ("owner", "spender", "value", "deadline", "v", "r", "s")),
    ("0x8fcbaf0c", "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
     "dai_permit", "DAI-style permit", "erc20",
     ("holder", "spender", "nonce", "expiry", "allowed", "v", "r", "s")),
    ("0x70a08231", "balanceOf(address)", "erc20_balance_of", "balanceOf", "erc20", ("owner",)),
    ("0xdd62ed3e", "allowance(address,address)", "erc20_allowance", "allowance", "erc20",
     ("owner", "spender")),
    ("0x18160ddd", "totalSupply()", "erc20_total_supply", "totalSupply", "erc20", ()),
    # ERC-721 / ERC-1155
    ("0xa22cb465", "setApprovalForAll(address,bool)", "set_approval_for_all",
     "ERC-721/1155 setApprovalForAll", "erc721", ("operator", "approved")),
    ("0x42842e0e", "safeTransferFrom(address,address,uint256)", "erc721_safe_transfer_from",
     "ERC-721 safeTransferFrom", "erc721", ("from", "to", "token_id")),
    ("0xb88d4fde", "safeTransferFrom(address,address,uint256,bytes)",
     "erc721_safe_transfer_from_data", "ERC-721 safeTransferFrom (with data)", "erc721",
     ("from", "to", "token_id", "data")),
    ("0xf242432a", "safeTransferFrom(address,address,uint256,uint256,bytes)",
     "erc1155_safe_transfer_from", "ERC-1155 safeTransferFrom", "erc1155",
     ("from", "to", "id", "amount", "data")),
    ("0x2eb2c2d6", "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
     "erc1155_safe_batch_transfer_from", "ERC-1155 safeBatchTransferFrom", "erc1155",
     ("from", "to", "ids", "amounts", "data")),
    # Permit2
    ("0x2b67b570", "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
     "permit2_permit", "Permit2 permit (single)", "permit2",
     ("owner", "permit_single", "signature")),
    ("0x2a2d80d1", "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
     "permit2_permit_batch", "Permit2 permit (batch)", "permit2",
     ("owner", "permit_batch", "signature")),
    ("0x30f28b7a",
     "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)",
     "permit2_permit_transfer_from", "Permit2 permitTransferFrom", "permit2",
     ("permit", "transfer_details", "owner", "signature")),
    ("0x87517c45", "approve(address,address,uint160,uint48)", "permit2_approve",
     "Permit2 approve", "permit2", ("token", "spender", "amount", "expiration")),
    # Uniswap V2 router
    ("0x38ed1739", "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
     "v2_swap_exact_tokens_for_tokens", "Uniswap V2 swapExactTokensForTokens", "uniswap_v2",
     _P["v2_tt"]),
    ("0x8803dbee", "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
     "v2_swap_tokens_for_exact_tokens", "Uniswap V2 swapTokensForExactTokens", "uniswap_v2",
     _P["v2_tt_out"]),
    ("0x7ff36ab5", "swapExactETHForTokens(uint256,address[],address,uint256)",
     "v2_swap_exact_eth_for_tokens", "Uniswap V2 swapExactETHForTokens", "uniswap_v2",
     _P["v2_et"]),
    ("0x4a25d94a", "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
     "v2_swap_tokens_for_exact_eth", "Uniswap V2 swapTokensForExactETH", "uniswap_v2",
     _P["v2_tt_out"]),
    ("0x18cbafe5", "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
     "v2_swap_exact_tokens_for_eth", "Uniswap V2 swapExactTokensForETH", "uniswap_v2",
     _P["v2_tt"]),
    ("0xfb3bdb41", "swapETHForExactTokens(uint256,address[],address,uint256)",
     "v2_swap_eth_for_exact_tokens", "Uniswap V2 swapETHForExactTokens", "uniswap_v2",
     _P["v2_et_out"]),
    ("0x5c11d795",
     "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
     "v2_swap_exact_tokens_for_tokens_fot",
     "Uniswap V2 swapExactTokensForTokensSupportingFeeOnTransferTokens", "uniswap_v2",
     _P["v2_tt"]),
    ("0xb6f9de95",
     "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)",
     "v2_swap_exact_eth_for_tokens_fot",
     "Uniswap V2 swapExactETHForTokensSupportingFeeOnTransferTokens", "uniswap_v2",
     _P["v2_et"]),
    ("0x791ac947",
     "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
     "v2_swap_exact_tokens_for_eth_fot",
     "Uniswap V2 swapExactTokensForETHSupportingFeeOnTransferTokens", "uniswap_v2",
     _P["v2_tt"]),
    ("0xd06ca61f", "getAmountsOut(uint256,address[])", "v2_get_amounts_out",
     "Uniswap V2 getAmountsOut", "uniswap_v2", ("amount_in", "path")),
    ("0xe8e33700",
     "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
     "v2_add_liquidity", "Uniswap V2 addLiquidity", "uniswap_v2", _P["v2_add"]),
    ("0xf305d719", "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
     "v2_add_liquidity_eth", "Uniswap V2 addLiquidityETH", "uniswap_v2", _P["v2_add_eth"]),
    ("0xbaa2abde", "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
     "v2_remove_liquidity", "Uniswap V2 removeLiquidity", "uniswap_v2", _P["v2_rm"]),
    ("0x02751cec", "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
     "v2_remove_liquidity_eth", "Uniswap V2 removeLiquidityETH", "uniswap_v2", _P["v2_rm_eth"]),
    ("0x2195995c",
     "removeLiquidityWithPermit(address,address,uint256,uint256,uint256,address,uint256,bool,uint8,bytes32,bytes32)",
     "v2_remove_liquidity_permit", "Uniswap V2 removeLiquidityWithPermit", "uniswap_v2",
     _P["v2_rm_permit"]),
    ("0xded9382a",
     "removeLiquidityETHWithPermit(address,uint256,uint256,uint256,address,uint256,bool,uint8,bytes32,bytes32)",
     "v2_remove_liquidity_eth_permit", "Uniswap V2 removeLiquidityETHWithPermit", "uniswap_v2",
     _P["v2_rm_eth_permit"]),
    ("0xaf2979eb",
     "removeLiquidityETHSupportingFeeOnTransferTokens(address,uint256,uint256,uint256,address,uint256)",
     "v2_remove_liquidity_eth_fot", "Uniswap V2 removeLiquidityETHSupportingFeeOnTransferTokens",
     "uniswap_v2", _P["v2_rm_eth"]),
    ("0xe6a43905", "getPair(address,address)", "v2_get_pair", "Uniswap V2 factory getPair",
     "uniswap_v2", ("token_a", "token_b")),
    ("0x0902f1ac", "getReserves()", "v2_get_reserves", "Uniswap V2 pair getReserves",
     "uniswap_v2", ()),
    # Uniswap V3 SwapRouter (with deadline) and SwapRouter02 (without)
    ("0x414bf389",
     "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
     "v3_exact_input_single", "Uniswap V3 exactInputSingle", "uniswap_v3", ("params",)),
    ("0xc04b8d59", "exactInput((bytes,address,uint256,uint256,uint256))", "v3_exact_input",
     "Uniswap V3 exactInput", "uniswap_v3", ("params",)),
    ("0xdb3e2198",
     "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
     "v3_exact_output_single", "Uniswap V3 exactOutputSingle", "uniswap_v3", ("params",)),
    ("0xf28c0498", "exactOutput((bytes,address,uint256,uint256,uint256))", "v3_exact_output",
     "Uniswap V3 exactOutput", "uniswap_v3", ("params",)),
    ("0x04e45aaf", "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
     "v3_exact_input_single", "Uniswap V3 exactInputSingle (SwapRouter02)", "uniswap_v3",
     ("params",)),
    ("0xb858183f", "exactInput((bytes,address,uint256,uint256))", "v3_exact_input",
     "Uniswap V3 exactInput (SwapRouter02)", "uniswap_v3", ("params",)),
    ("0x5023b4df", "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))",
     "v3_exact_output_single", "Uniswap V3 exactOutputSingle (SwapRouter02)", "uniswap_v3",
     ("params",)),
    ("0x09b81346", "exactOutput((bytes,address,uint256,uint256))", "v3_exact_output",
     "Uniswap V3 exactOutput (SwapRouter02)", "uniswap_v3", ("params",)),
    ("0x0c49ccbe", "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
     "v3_decrease_liquidity", "Uniswap V3 NFPM decreaseLiquidity", "uniswap_v3", ("params",)),
    ("0xfc6f7865", "collect((uint256,address,uint128,uint128))", "v3_collect",
     "Uniswap V3 NFPM collect", "uniswap_v3", ("params",)),
    ("0x1698ee82", "getPool(address,address,uint24)", "v3_get_pool",
     "Uniswap V3 factory getPool", "uniswap_v3", ("token_a", "token_b", "fee")),
    ("0x3850c7bd", "slot0()", "v3_slot0", "Uniswap V3 pool slot0", "uniswap_v3", ()),
    ("0x1a686502", "liquidity()", "v3_liquidity", "Uniswap V3 pool liquidity", "uniswap_v3", ()),
    ("0xd0c93a7c", "tickSpacing()", "v3_tick_spacing", "Uniswap V3 pool tickSpacing",
     "uniswap_v3", ()),
    ("0x5339c296", "tickBitmap(int16)", "v3_tick_bitmap", "Uniswap V3 pool tickBitmap",
     "uniswap_v3", ("word_pos",)),
    ("0xf30dba93", "ticks(int24)", "v3_ticks", "Uniswap V3 pool ticks", "uniswap_v3", ("tick",)),
    ("0x99fbab88", "positions(uint256)", "v3_positions", "Uniswap V3 NFPM positions",
     "uniswap_v3", ("token_id",)),
    # Multicall
    ("0xac9650d8", "multicall(bytes[])", "multicall", "Multicall", "multicall", ("data",)),
    ("0x5ae401dc", "multicall(uint256,bytes[])", "multicall_deadline",
     "Multicall (deadline)", "multicall", ("deadline", "data")),
    ("0x1f0464d1", "multicall(bytes32,bytes[])", "multicall_previous_block",
     "Multicall (previousBlockhash)", "multicall", ("previous_blockhash", "data")),
    ("0x252dba42", "aggregate((address,bytes)[])", "multicall3_aggregate",
     "Multicall3 aggregate", "multicall", ("calls",)),
    ("0x82ad56cb", "aggregate3((address,bool,bytes)[])", "multicall3_aggregate3",
     "Multicall3 aggregate3", "multicall", ("calls",)),
    ("0xbce38bd7", "tryAggregate(bool,(address,bytes)[])", "multicall3_try_aggregate",
     "Multicall3 tryAggregate", "multicall", ("require_success", "calls")),
    # Universal Router
    ("0x3593564c", "execute(bytes,bytes[],uint256)", "universal_router_execute",
     "Universal Router execute", "universal_router", ("commands", "inputs", "deadline")),
    ("0x24856bc3", "execute(bytes,bytes[])", "universal_router_execute",
     "Universal Router execute (no deadline)", "universal_router", ("commands", "inputs")),
    # WETH
    ("0xd0e30db0", "deposit()", "weth_deposit", "WETH deposit", "weth", ()),
    ("0x2e1a7d4d", "withdraw(uint256)", "weth_withdraw", "WETH withdraw", "weth", ("wad",)),
    # Misc
    ("0xf2fde38b", "transferOwnership(address)", "transfer_ownership", "transferOwnership",
     "ownable", ("new_owner",)),
    ("0x01ffc9a7", "supportsInterface(bytes4)", "supports_interface", "ERC-165 supportsInterface",
     "erc165", ("interface_id",)),
]

SELECTORS: dict[str, FunctionSpec] = {
    row[0]: FunctionSpec(*row) for row in _REGISTRY_ROWS
}
assert len(SELECTORS) == len(_REGISTRY_ROWS), "duplicate selector in registry"


def selector_for(kind_or_signature: str) -> str:
    """Look up a selector by registry kind or by exact signature."""
    for spec in SELECTORS.values():
        if spec.kind == kind_or_signature or spec.signature == kind_or_signature:
            return spec.selector
    raise KeyError(kind_or_signature)


# --------------------------------------------------------------------------- Universal Router

UR_MSG_SENDER = "0x0000000000000000000000000000000000000001"
UR_ADDRESS_THIS = "0x0000000000000000000000000000000000000002"
UR_COMMAND_MASK = 0x3F
UR_FLAG_ALLOW_REVERT = 0x80

UR_COMMANDS: dict[int, tuple[str, str, tuple[str, ...]]] = {
    0x00: ("V3_SWAP_EXACT_IN", "(address,uint256,uint256,bytes,bool)",
           ("recipient", "amount_in", "amount_out_min", "path", "payer_is_user")),
    0x01: ("V3_SWAP_EXACT_OUT", "(address,uint256,uint256,bytes,bool)",
           ("recipient", "amount_out", "amount_in_max", "path", "payer_is_user")),
    0x02: ("PERMIT2_TRANSFER_FROM", "(address,address,uint160)",
           ("token", "recipient", "amount")),
    0x03: ("PERMIT2_PERMIT_BATCH",
           "(((address,uint160,uint48,uint48)[],address,uint256),bytes)",
           ("permit_batch", "signature")),
    0x04: ("SWEEP", "(address,address,uint256)", ("token", "recipient", "amount_min")),
    0x05: ("TRANSFER", "(address,address,uint256)", ("token", "recipient", "value")),
    0x06: ("PAY_PORTION", "(address,address,uint256)", ("token", "recipient", "bips")),
    0x08: ("V2_SWAP_EXACT_IN", "(address,uint256,uint256,address[],bool)",
           ("recipient", "amount_in", "amount_out_min", "path", "payer_is_user")),
    0x09: ("V2_SWAP_EXACT_OUT", "(address,uint256,uint256,address[],bool)",
           ("recipient", "amount_out", "amount_in_max", "path", "payer_is_user")),
    0x0A: ("PERMIT2_PERMIT", "(((address,uint160,uint48,uint48),address,uint256),bytes)",
           ("permit_single", "signature")),
    0x0B: ("WRAP_ETH", "(address,uint256)", ("recipient", "amount")),
    0x0C: ("UNWRAP_WETH", "(address,uint256)", ("recipient", "amount_min")),
    0x0D: ("PERMIT2_TRANSFER_FROM_BATCH", "((address,address,uint160,address)[])", ("batch",)),
    0x0E: ("BALANCE_CHECK_ERC20", "(address,address,uint256)", ("owner", "token", "min_balance")),
    0x10: ("SEAPORT_V1_5", "(uint256,bytes)", ("value", "calldata")),
    0x11: ("LOOKS_RARE_V2", "(uint256,bytes)", ("value", "calldata")),
    0x12: ("NFTX", "(uint256,bytes)", ("value", "calldata")),
    0x13: ("CRYPTOPUNKS", "(uint256,address,uint256)", ("punk_id", "recipient", "value")),
    0x15: ("OWNER_CHECK_721", "(address,address,uint256)", ("owner", "token", "id")),
    0x16: ("OWNER_CHECK_1155", "(address,address,uint256,uint256)",
           ("owner", "token", "id", "min_balance")),
    0x17: ("SWEEP_ERC721", "(address,address,uint256)", ("token", "recipient", "id")),
    0x18: ("X2Y2_721", "(uint256,bytes,address,address,uint256)",
           ("value", "calldata", "recipient", "token", "id")),
    0x19: ("SUDOSWAP", "(uint256,bytes)", ("value", "calldata")),
    0x1A: ("NFT20", "(uint256,bytes)", ("value", "calldata")),
    0x1B: ("X2Y2_1155", "(uint256,bytes,address,address,uint256,uint256)",
           ("value", "calldata", "recipient", "token", "id", "amount")),
    0x1C: ("FOUNDATION", "(uint256,bytes,address,address,uint256)",
           ("value", "calldata", "recipient", "token", "id")),
    0x1D: ("SWEEP_ERC1155", "(address,address,uint256,uint256)",
           ("token", "recipient", "id", "amount")),
    0x1E: ("ELEMENT_MARKET", "(uint256,bytes)", ("value", "calldata")),
    0x20: ("SEAPORT_V1_4", "(uint256,bytes)", ("value", "calldata")),
    0x21: ("EXECUTE_SUB_PLAN", "(bytes,bytes[])", ("commands", "inputs")),
    0x22: ("APPROVE_ERC20", "(address,uint256)", ("token", "spender_id")),
}


# --------------------------------------------------------------------------- decoded call

@dataclass
class DecodedCall:
    selector: str
    kind: str
    name: str
    protocol: str = "unknown"
    signature: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    inner: list[DecodedCall] = field(default_factory=list)
    error: str | None = None
    target: str | None = None  # explicit target for Multicall3-style sub-calls

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "selector": self.selector, "kind": self.kind, "name": self.name,
            "protocol": self.protocol, "signature": self.signature, "args": self.args,
        }
        if self.inner:
            d["inner"] = [c.to_dict() for c in self.inner]
        if self.error:
            d["error"] = self.error
        if self.target:
            d["target"] = self.target
        return d

    def walk(self):
        """Yield this call and every nested call, depth-first."""
        yield self
        for c in self.inner:
            yield from c.walk()


def decode_v3_path(path_hex: str) -> dict[str, list[Any]]:
    """``token(20) fee(3) token(20) [fee(3) token(20) ...]`` -> tokens and fees."""
    raw = _to_bytes(path_hex)
    if len(raw) < 43 or (len(raw) - 20) % 23:
        raise AbiError(f"bad V3 path length {len(raw)}")
    tokens = ["0x" + raw[0:20].hex()]
    fees: list[int] = []
    pos = 20
    while pos < len(raw):
        fees.append(int.from_bytes(raw[pos:pos + 3], "big"))
        tokens.append("0x" + raw[pos + 3:pos + 23].hex())
        pos += 23
    return {"tokens": tokens, "fees": fees}


def encode_v3_path(tokens: list[str], fees: list[int]) -> str:
    if len(tokens) != len(fees) + 1:
        raise AbiError("path needs len(tokens) == len(fees) + 1")
    out = bytes.fromhex(tokens[0].removeprefix("0x").rjust(40, "0"))
    for fee, tok in zip(fees, tokens[1:]):
        out += fee.to_bytes(3, "big") + bytes.fromhex(tok.removeprefix("0x").rjust(40, "0"))
    return "0x" + out.hex()


_V3_SINGLE_PARAMS = {
    8: ("token_in", "token_out", "fee", "recipient", "deadline", "amount_in", "amount_out_min",
        "sqrt_price_limit_x96"),
    7: ("token_in", "token_out", "fee", "recipient", "amount_in", "amount_out_min",
        "sqrt_price_limit_x96"),
}
_V3_SINGLE_OUT_PARAMS = {
    8: ("token_in", "token_out", "fee", "recipient", "deadline", "amount_out", "amount_in_max",
        "sqrt_price_limit_x96"),
    7: ("token_in", "token_out", "fee", "recipient", "amount_out", "amount_in_max",
        "sqrt_price_limit_x96"),
}
_V3_PATH_PARAMS = {
    5: ("path", "recipient", "deadline", "amount_in", "amount_out_min"),
    4: ("path", "recipient", "amount_in", "amount_out_min"),
}
_V3_PATH_OUT_PARAMS = {
    5: ("path", "recipient", "deadline", "amount_out", "amount_in_max"),
    4: ("path", "recipient", "amount_out", "amount_in_max"),
}


def _name_tuple(names: tuple[str, ...], values: list[Any]) -> dict[str, Any]:
    return {n: v for n, v in zip(names, values)}


def _postprocess(call: DecodedCall, depth: int) -> None:
    k, a = call.kind, call.args
    if k in ("v3_exact_input_single", "v3_exact_output_single"):
        p = a["params"]
        names = (_V3_SINGLE_PARAMS if k == "v3_exact_input_single" else _V3_SINGLE_OUT_PARAMS)
        a["params"] = _name_tuple(names[len(p)], p)
    elif k in ("v3_exact_input", "v3_exact_output"):
        p = a["params"]
        names = _V3_PATH_PARAMS if k == "v3_exact_input" else _V3_PATH_OUT_PARAMS
        named = _name_tuple(names[len(p)], p)
        decoded = decode_v3_path(named["path"])
        if k == "v3_exact_output":  # exactOutput paths are encoded output-first
            decoded = {"tokens": decoded["tokens"][::-1], "fees": decoded["fees"][::-1]}
        named["path_decoded"] = decoded
        a["params"] = named
    elif k == "v3_decrease_liquidity":
        a["params"] = _name_tuple(
            ("token_id", "liquidity", "amount0_min", "amount1_min", "deadline"), a["params"])
    elif k == "v3_collect":
        a["params"] = _name_tuple(("token_id", "recipient", "amount0_max", "amount1_max"),
                                  a["params"])
    elif k == "permit2_permit":
        det, spender, sig_deadline = a["permit_single"]
        a["permit_single"] = {
            "details": _name_tuple(("token", "amount", "expiration", "nonce"), det),
            "spender": spender, "sig_deadline": sig_deadline,
        }
    elif k == "permit2_permit_batch":
        dets, spender, sig_deadline = a["permit_batch"]
        a["permit_batch"] = {
            "details": [_name_tuple(("token", "amount", "expiration", "nonce"), d) for d in dets],
            "spender": spender, "sig_deadline": sig_deadline,
        }
    elif k == "permit2_permit_transfer_from":
        (token, amount), nonce, deadline = a["permit"]
        to, requested = a["transfer_details"]
        a["permit"] = {"permitted": {"token": token, "amount": amount}, "nonce": nonce,
                       "deadline": deadline}
        a["transfer_details"] = {"to": to, "requested_amount": requested}
    elif k.startswith("multicall") and k != "multicall3_aggregate" and \
            k not in ("multicall3_aggregate3", "multicall3_try_aggregate"):
        call.inner = [decode_call(d, depth + 1) for d in a["data"]]
    elif k == "multicall3_aggregate" or k == "multicall3_try_aggregate":
        calls = []
        for target, data in a["calls"]:
            sub = decode_call(data, depth + 1)
            sub.target = target
            calls.append(sub)
        call.inner = calls
        a["calls"] = [{"target": t, "data": d} for t, d in a["calls"]]
    elif k == "multicall3_aggregate3":
        calls = []
        for target, _allow_failure, data in a["calls"]:
            sub = decode_call(data, depth + 1)
            sub.target = target
            calls.append(sub)
        call.inner = calls
        a["calls"] = [{"target": t, "allow_failure": f, "data": d} for t, f, d in a["calls"]]
    elif k == "universal_router_execute":
        call.inner = decode_universal_router(a["commands"], a["inputs"], depth + 1)
        a["commands_decoded"] = [c.name for c in call.inner]


def decode_universal_router(commands_hex: str, inputs: list[str], depth: int = 1
                            ) -> list[DecodedCall]:
    cmds = _to_bytes(commands_hex)
    out: list[DecodedCall] = []
    for i, byte in enumerate(cmds):
        cmd_type, allow_revert = byte & UR_COMMAND_MASK, bool(byte & UR_FLAG_ALLOW_REVERT)
        raw_input = inputs[i] if i < len(inputs) else "0x"
        spec = UR_COMMANDS.get(cmd_type)
        if spec is None:
            out.append(DecodedCall(f"0x{byte:02x}", "ur_unknown_command", f"UNKNOWN(0x{byte:02x})",
                                   "universal_router", args={"input": raw_input}))
            continue
        name, types, names = spec
        sub = DecodedCall(f"0x{byte:02x}", "ur_" + name.lower(), name, "universal_router",
                          signature=f"{name}{types}", args={"allow_revert": allow_revert})
        try:
            values = _decode_tuple(parse_type(types).components, _to_bytes(raw_input), 0)
            sub.args.update(_name_tuple(names, values))
            if name in ("V3_SWAP_EXACT_IN", "V3_SWAP_EXACT_OUT"):
                decoded = decode_v3_path(sub.args["path"])
                if name == "V3_SWAP_EXACT_OUT":
                    decoded = {"tokens": decoded["tokens"][::-1], "fees": decoded["fees"][::-1]}
                sub.args["path_decoded"] = decoded
            elif name == "PERMIT2_PERMIT":
                det, spender, sig_deadline = sub.args["permit_single"]
                sub.args["permit_single"] = {
                    "details": _name_tuple(("token", "amount", "expiration", "nonce"), det),
                    "spender": spender, "sig_deadline": sig_deadline,
                }
            elif name == "PERMIT2_PERMIT_BATCH":
                dets, spender, sig_deadline = sub.args["permit_batch"]
                sub.args["permit_batch"] = {
                    "details": [_name_tuple(("token", "amount", "expiration", "nonce"), d)
                                for d in dets],
                    "spender": spender, "sig_deadline": sig_deadline,
                }
            elif name == "PERMIT2_TRANSFER_FROM_BATCH":
                sub.args["batch"] = [_name_tuple(("from", "to", "amount", "token"), b)
                                     for b in sub.args["batch"]]
            elif name == "EXECUTE_SUB_PLAN" and depth < MAX_DEPTH:
                sub.inner = decode_universal_router(sub.args["commands"], sub.args["inputs"],
                                                    depth + 1)
        except (AbiError, IndexError, ValueError) as e:
            sub.kind, sub.error = "malformed", str(e)
        out.append(sub)
    return out


def decode_call(data: str, depth: int = 0) -> DecodedCall:
    """Decode calldata into a ``DecodedCall``. Never raises on bad input."""
    try:
        raw = _to_bytes(data or "0x")
    except AbiError as e:
        return DecodedCall("0x", "malformed", "malformed calldata", error=str(e))
    if len(raw) == 0:
        return DecodedCall("0x", "empty", "plain value transfer", "native")
    if len(raw) < 4:
        return DecodedCall("0x" + raw.hex(), "malformed", "calldata shorter than a selector",
                           error="short calldata")
    sel = "0x" + raw[:4].hex()
    spec = SELECTORS.get(sel)
    if spec is None:
        return DecodedCall(sel, "unknown", f"unknown selector {sel}")
    call = DecodedCall(sel, spec.kind, spec.name, spec.protocol, spec.signature)
    if depth > MAX_DEPTH:
        call.error = "nesting too deep"
        return call
    try:
        values = _decode_tuple(spec.types, raw, 4)
        call.args = _name_tuple(spec.params, values)
        _postprocess(call, depth)
    except (AbiError, IndexError, KeyError, ValueError) as e:
        call.kind, call.error = "malformed", str(e)
    return call


def describe(call: DecodedCall) -> str:
    """One-line human summary used by the CLI and the agent's tool results."""
    if call.kind == "empty":
        return "plain ETH transfer (no calldata)"
    if call.kind in ("unknown", "malformed"):
        return f"{call.name}" + (f" ({call.error})" if call.error else "")
    parts = [call.name]
    if call.inner:
        parts.append("[" + ", ".join(c.name for c in call.inner) + "]")
    return " ".join(parts)
