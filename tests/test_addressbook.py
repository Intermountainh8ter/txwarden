import json

import pytest

from txwarden.addressbook import AddressBook, lookalike
from txwarden.keccak import to_checksum_address

UNI = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"


def test_builtin_book_is_checksummed_and_contains_the_core_routers():
    book = AddressBook.builtin()
    assert len(book) >= 25
    assert book.name(UNI) == "Uniswap V2 Router02"
    assert UNI.lower() in book and UNI in book
    assert book.get("0x000000000022D473030F116dDEE9F6B43aC78BA3").kind == "permit2"
    assert {"router", "permit2"} <= {book.get(a).kind for a in book.addresses()}
    for lbl in book.entries():
        assert lbl.checksum == to_checksum_address(lbl.address)


def test_lookup_is_case_insensitive_and_unknown_is_none():
    book = AddressBook.builtin()
    assert book.get(UNI.upper().replace("0X", "0x")).name == "Uniswap V2 Router02"
    assert book.get("0x" + "00" * 19 + "99") is None and book.name("0x" + "00" * 19 + "99") is None


def test_add_rejects_bad_checksum_and_non_hex():
    book = AddressBook()
    with pytest.raises(ValueError):
        book.add("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488d", "typo")  # wrong case on last char
    with pytest.raises(ValueError):
        book.add("0x1234", "short")
    book.add(UNI.lower(), "ok")  # all-lowercase is accepted
    assert book.name(UNI) == "ok"


def test_from_dict_supports_entries_and_compact_labels_and_chain_ids():
    book = AddressBook.from_dict({
        "chain_id": 10,
        "entries": [{"address": UNI, "name": "router", "kind": "router"},
                    {"address": "0x" + "11" * 20, "name": "mine", "chain_id": 1}],
        "labels": {"0x" + "22" * 20: "cold wallet"},
    })
    assert book.get(UNI).chain_id == 10 and book.get("0x" + "11" * 20).chain_id == 1
    assert book.name("0x" + "22" * 20) == "cold wallet"
    assert book.labels()[UNI.lower()] == "router"


def test_load_merge_by_kind_and_round_trip(tmp_path):
    path = tmp_path / "book.json"
    path.write_text(json.dumps({"labels": {"0x" + "33" * 20: "friend"}}))
    mine = AddressBook.load(path)
    merged = AddressBook.builtin().merge(mine)
    assert merged.name("0x" + "33" * 20) == "friend" and merged.name(UNI)
    assert len(merged) == len(AddressBook.builtin()) + 1  # merge does not mutate the originals
    assert "0x" + "33" * 20 not in AddressBook.builtin()
    assert UNI.lower() in merged.by_kind("router")
    again = AddressBook.from_dict(merged.to_dict())
    assert again.labels() == merged.labels()
    assert [e.name.lower() for e in merged.entries()] == sorted(e.name.lower() for e in merged.entries())


def test_lookalike_matches_prefix_and_suffix_but_not_identity():
    real = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    fake = "0xA0b8" + "dead" * 8 + "eB48"
    assert lookalike(fake, real)
    assert not lookalike(real, real) and not lookalike(real.lower(), real)
    assert not lookalike("0xA0b9" + "dead" * 8 + "eB48", real)  # prefix differs
    assert not lookalike("0xA0b8" + "dead" * 8 + "eB49", real)  # suffix differs
    assert not lookalike("0x1234", real)  # malformed
    assert lookalike("0xA0b8" + "dead" * 8 + "0000", real, prefix=4, suffix=0)


def test_book_lookalikes_lists_matching_entries():
    book = AddressBook.builtin()
    fake = "0x7a25" + "00" * 16 + "488d"
    hits = book.lookalikes(fake)
    assert [h.name for h in hits] == ["Uniswap V2 Router02"]
    assert book.lookalikes(UNI) == []
