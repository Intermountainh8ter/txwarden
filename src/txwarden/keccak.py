"""Pure-Python Keccak-256 (the original Keccak padding that Ethereum uses, not NIST SHA3-256).

Used for function selectors and EIP-55 checksums so the package stays dependency-free. It is a
few hundred hashes per second, which is more than enough for selector tables and address books;
nothing on the hot path calls it.
"""
from __future__ import annotations

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK = (1 << 64) - 1
_RATE = 136  # bytes absorbed per permutation for a 256-bit output


def _rol(v: int, n: int) -> int:
    n %= 64
    if n == 0:
        return v
    return ((v << n) | (v >> (64 - n))) & _MASK


def _keccak_f(a: list[int]) -> None:
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        a[0] ^= rc


def keccak256(data: bytes) -> bytes:
    state = [0] * 25
    buf = bytearray(data)
    buf.append(0x01)
    while len(buf) % _RATE:
        buf.append(0)
    buf[-1] |= 0x80
    for off in range(0, len(buf), _RATE):
        block = buf[off:off + _RATE]
        for i in range(_RATE // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


def keccak256_hex(data: bytes) -> str:
    return "0x" + keccak256(data).hex()


def selector(signature: str) -> str:
    """4-byte function selector for a canonical signature such as ``approve(address,uint256)``."""
    return "0x" + keccak256(signature.encode()).hex()[:8]


def to_checksum_address(address: str) -> str:
    """EIP-55 mixed-case checksum encoding."""
    raw = address.lower().removeprefix("0x")
    if len(raw) != 40 or any(c not in "0123456789abcdef" for c in raw):
        raise ValueError(f"not a hex address: {address!r}")
    digest = keccak256(raw.encode()).hex()
    return "0x" + "".join(
        ch.upper() if int(digest[i], 16) >= 8 else ch for i, ch in enumerate(raw)
    )


def is_checksum_address(address: str) -> bool:
    """True if the address is valid EIP-55 mixed case, or all-lowercase/all-uppercase hex."""
    try:
        checksummed = to_checksum_address(address)
    except ValueError:
        return False
    body = address.removeprefix("0x")
    if body == body.lower() or body == body.upper():
        return True
    return "0x" + body == checksummed
