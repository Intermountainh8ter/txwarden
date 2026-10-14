import hashlib

import pytest

from txwarden.keccak import (
    _sponge,
    is_checksum_address,
    keccak256,
    selector,
    to_checksum_address,
)


def test_empty_input_vector():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def test_abc_vector():
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def test_multi_block_input_differs_from_single_block():
    # 200 bytes spans two 136-byte rate blocks; make sure absorption handles the boundary.
    a = keccak256(b"x" * 135)
    b = keccak256(b"x" * 136)
    c = keccak256(b"x" * 200)
    assert len({a, b, c}) == 3 and len(c) == 32


@pytest.mark.parametrize("sig,sel", [
    ("approve(address,uint256)", "0x095ea7b3"),
    ("transfer(address,uint256)", "0xa9059cbb"),
    ("transferFrom(address,address,uint256)", "0x23b872dd"),
    ("setApprovalForAll(address,bool)", "0xa22cb465"),
    ("execute(bytes,bytes[],uint256)", "0x3593564c"),
])
def test_known_selectors(sig, sel):
    assert selector(sig) == sel


@pytest.mark.parametrize("addr", [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
])
def test_eip55_examples_round_trip(addr):
    assert to_checksum_address(addr.lower()) == addr
    assert is_checksum_address(addr)


def test_bad_checksum_rejected():
    assert not is_checksum_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")


def test_all_lowercase_accepted():
    assert is_checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")


def test_non_hex_rejected():
    assert not is_checksum_address("0xzz")
    with pytest.raises(ValueError):
        to_checksum_address("hello")


def test_quick_brown_fox_vector():
    assert keccak256(b"The quick brown fox jumps over the lazy dog").hex() == (
        "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15")


def test_permutation_and_absorption_match_hashlib_sha3_on_every_block_boundary():
    """Same sponge with SHA-3's 0x06 domain byte must equal hashlib's SHA3-256 for all lengths
    around the 136-byte rate, which checks Keccak-f and multi-block absorption independently."""
    for n in [*range(0, 140), 200, 271, 272, 273, 408, 1000]:
        data = bytes((i * 7 + n) % 256 for i in range(n))
        assert _sponge(data, 0x06) == hashlib.sha3_256(data).digest(), n


def test_keccak_differs_from_nist_sha3():
    assert keccak256(b"") != hashlib.sha3_256(b"").digest()
