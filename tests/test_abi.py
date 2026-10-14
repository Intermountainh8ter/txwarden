import pytest

from txwarden.abi import (
    SELECTORS,
    UR_COMMANDS,
    AbiError,
    decode,
    decode_call,
    decode_universal_router,
    decode_v3_path,
    describe,
    encode,
    encode_call,
    encode_v3_path,
    parse_type,
    selector_for,
)
from txwarden.keccak import selector

A1, A2, A3 = "0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20


# --------------------------------------------------------------------------- types

@pytest.mark.parametrize("s,dynamic,static_size", [
    ("uint256", False, 32), ("uint8", False, 32), ("int24", False, 32), ("address", False, 32),
    ("bool", False, 32), ("bytes32", False, 32), ("bytes", True, 32), ("string", True, 32),
    ("uint256[]", True, 32), ("address[2]", False, 64), ("(uint256,address)", False, 64),
    ("(uint256,bytes)", True, 32), ("string[2]", True, 32), ("(address,uint160,uint48,uint48)[]",
                                                             True, 32),
])
def test_parse_type_dynamic_and_size(s, dynamic, static_size):
    t = parse_type(s)
    assert t.is_dynamic is dynamic
    assert t.static_size == static_size
    assert str(t) == s


def test_uint_alias_and_bad_widths():
    assert str(parse_type("uint")) == "uint256"
    assert str(parse_type("int")) == "int256"
    for bad in ("uint7", "uint512", "bytes33", "foo", ""):
        with pytest.raises(AbiError):
            parse_type(bad)


# --------------------------------------------------------------------------- codec

@pytest.mark.parametrize("types,values", [
    (["uint256"], [0]),
    (["uint256"], [2**256 - 1]),
    (["int8"], [-128]),
    (["int256"], [-1]),
    (["address"], [A1]),
    (["bool", "bool"], [True, False]),
    (["bytes32"], ["0x" + "ab" * 32]),
    (["bytes4"], ["0xdeadbeef"]),
    (["bytes"], ["0x"]),
    (["bytes"], ["0x" + "01" * 33]),
    (["string"], ["héllo wörld"]),
    (["uint256[]"], [[1, 2, 3]]),
    (["uint256[]"], [[]]),
    (["address[2]"], [[A1, A2]]),
    (["string[]"], [["a", "bb", "ccc"]]),
    (["(uint256,address)"], [[7, A3]]),
    (["(uint256,bytes)"], [[7, "0x1234"]]),
    (["(address,bytes)[]"], [[[A1, "0x01"], [A2, "0x0203"]]]),
    (["bytes[]"], [["0x", "0xaa", "0xbbcc"]]),
    (["(bytes,address,uint256,uint256,uint256)"], [["0x" + "cd" * 43, A1, 1, 2, 3]]),
    (["uint256", "string", "address[]", "bool"], [5, "x", [A1, A2, A3], True]),
])
def test_round_trip(types, values):
    enc = encode(types, values)
    assert len(enc) % 32 == 0
    assert decode(types, enc) == values


def test_bytes4_padding_is_right_padded():
    assert encode(["bytes4"], ["0xdeadbeef"]).hex() == "deadbeef" + "00" * 28


def test_dynamic_offsets_follow_spec():
    # encode(["uint256","string"], [1,"ab"]): head = 1, 0x40 ; tail = len 2, "ab" padded
    enc = encode(["uint256", "string"], [1, "ab"]).hex()
    assert enc[:64] == "0" * 63 + "1"
    assert enc[64:128] == "0" * 62 + "40"
    assert enc[128:192] == "0" * 63 + "2"
    assert enc[192:196] == "6162"


@pytest.mark.parametrize("value,typ", [
    (2**256, "uint256"), (-1, "uint8"), (2**7, "int8"), (2**160, "address"), ("0x" + "ff" * 5, "bytes4"),
])
def test_encode_range_checks(value, typ):
    with pytest.raises(AbiError):
        encode([typ], [value])


def test_encode_wrong_arity():
    with pytest.raises(AbiError):
        encode(["uint256", "uint256"], [1])
    with pytest.raises(AbiError):
        encode(["address[2]"], [[A1]])


@pytest.mark.parametrize("types,data", [
    (["uint256"], "0x"),
    (["uint256"], "0x" + "00" * 31),
    (["bytes"], "0x" + "00" * 31 + "20" + "ff" * 32),  # length word says 255 bytes, only 0
    (["uint256[]"], "0x" + "00" * 31 + "20" + "ff" * 32),  # absurd length
    (["string"], "0x" + "00" * 31 + "ff"),  # offset past end
    (["address"], "0x" + "ff" * 32),  # dirty upper bits
    (["bool"], "0x" + "00" * 31 + "02"),
    (["uint8"], "0x" + "00" * 30 + "0100"),
    (["int8"], "0x" + "00" * 31 + "80"),
])
def test_decode_rejects_malformed(types, data):
    with pytest.raises(AbiError):
        decode(types, data)


def test_decode_string_with_invalid_utf8_is_replaced_not_raised():
    raw = "0x" + "00" * 31 + "20" + "00" * 31 + "02" + "ff" * 2 + "00" * 30
    assert "�" in decode(["string"], raw)[0]


# --------------------------------------------------------------------------- registry

@pytest.mark.parametrize("spec", list(SELECTORS.values()), ids=lambda s: s.kind + ":" + s.selector)
def test_every_registered_selector_matches_keccak(spec):
    assert selector(spec.signature) == spec.selector
    assert len(spec.params) == len(spec.types)


@pytest.mark.parametrize("cmd", list(UR_COMMANDS), ids=lambda c: UR_COMMANDS[c][0])
def test_universal_router_command_tables_are_consistent(cmd):
    name, types, names = UR_COMMANDS[cmd]
    assert len(parse_type(types).components) == len(names)


def test_selector_for_lookup():
    assert selector_for("erc20_approve") == "0x095ea7b3"
    assert selector_for("transfer(address,uint256)") == "0xa9059cbb"
    with pytest.raises(KeyError):
        selector_for("nope")


# --------------------------------------------------------------------------- decode_call

def test_decode_approve_and_transfer_from():
    d = decode_call(encode_call("approve(address,uint256)", [A1, 2**256 - 1]))
    assert d.kind == "erc20_approve" and d.args == {"spender": A1, "amount": 2**256 - 1}
    d = decode_call(encode_call("transferFrom(address,address,uint256)", [A1, A2, 5]))
    assert d.kind == "erc20_transfer_from" and d.args["from"] == A1 and d.args["to"] == A2


def test_decode_eip2612_permit():
    d = decode_call(encode_call("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                                [A1, A2, 10, 999, 27, "0x" + "01" * 32, "0x" + "02" * 32]))
    assert d.kind == "erc20_permit"
    assert d.args["owner"] == A1 and d.args["spender"] == A2 and d.args["deadline"] == 999


def test_decode_permit2_permit_single():
    data = encode_call("permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
                       [A1, ((A3, 2**160 - 1, 2**48 - 1, 0), A2, 12345), "0x" + "aa" * 65])
    d = decode_call(data)
    assert d.kind == "permit2_permit"
    ps = d.args["permit_single"]
    assert ps["details"] == {"token": A3, "amount": 2**160 - 1, "expiration": 2**48 - 1, "nonce": 0}
    assert ps["spender"] == A2 and ps["sig_deadline"] == 12345


def test_decode_permit2_permit_transfer_from():
    sig = "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)"
    d = decode_call(encode_call(sig, [((A3, 100), 1, 2), (A2, 100), A1, "0x"]))
    assert d.kind == "permit2_permit_transfer_from"
    assert d.args["permit"]["permitted"] == {"token": A3, "amount": 100}
    assert d.args["transfer_details"] == {"to": A2, "requested_amount": 100}
    assert d.args["owner"] == A1


def test_decode_erc721_and_erc1155():
    d = decode_call(encode_call("setApprovalForAll(address,bool)", [A1, True]))
    assert d.kind == "set_approval_for_all" and d.args["approved"] is True
    d = decode_call(encode_call("safeTransferFrom(address,address,uint256,bytes)", [A1, A2, 9, "0x"]))
    assert d.kind == "erc721_safe_transfer_from_data" and d.args["token_id"] == 9
    d = decode_call(encode_call("safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
                                [A1, A2, [1, 2], [10, 20], "0x"]))
    assert d.kind == "erc1155_safe_batch_transfer_from" and d.args["amounts"] == [10, 20]


V2_SIGS = [
    ("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)", True),
    ("swapTokensForExactTokens(uint256,uint256,address[],address,uint256)", True),
    ("swapExactETHForTokens(uint256,address[],address,uint256)", False),
    ("swapTokensForExactETH(uint256,uint256,address[],address,uint256)", True),
    ("swapExactTokensForETH(uint256,uint256,address[],address,uint256)", True),
    ("swapETHForExactTokens(uint256,address[],address,uint256)", False),
    ("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)", True),
    ("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)", False),
    ("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)", True),
]


@pytest.mark.parametrize("sig,two_amounts", V2_SIGS, ids=[s.split("(")[0] for s, _ in V2_SIGS])
def test_decode_all_v2_swap_variants(sig, two_amounts):
    vals = ([1000, 900] if two_amounts else [900]) + [[A1, A2, A3], A1, 99]
    d = decode_call(encode_call(sig, vals))
    assert d.kind.startswith("v2_swap_") and d.protocol == "uniswap_v2"
    assert d.args["path"] == [A1, A2, A3] and d.args["to"] == A1 and d.args["deadline"] == 99


def test_decode_v3_exact_input_single_both_router_versions():
    sig_v1 = "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"
    sig_v2 = "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"
    d1 = decode_call(encode_call(sig_v1, [(A1, A2, 3000, A3, 99, 1000, 900, 0)]))
    d2 = decode_call(encode_call(sig_v2, [(A1, A2, 500, A3, 1000, 900, 0)]))
    for d, fee in ((d1, 3000), (d2, 500)):
        assert d.kind == "v3_exact_input_single"
        p = d.args["params"]
        assert p["token_in"] == A1 and p["token_out"] == A2 and p["fee"] == fee
        assert p["amount_in"] == 1000 and p["amount_out_min"] == 900
    assert d1.args["params"]["deadline"] == 99 and "deadline" not in d2.args["params"]


def test_v3_path_codec_and_exact_output_reversal():
    path = encode_v3_path([A1, A2, A3], [3000, 500])
    assert decode_v3_path(path) == {"tokens": [A1, A2, A3], "fees": [3000, 500]}
    d = decode_call(encode_call("exactInput((bytes,address,uint256,uint256,uint256))",
                                [(path, A1, 99, 1000, 900)]))
    assert d.args["params"]["path_decoded"]["tokens"] == [A1, A2, A3]
    d = decode_call(encode_call("exactOutput((bytes,address,uint256,uint256,uint256))",
                                [(path, A1, 99, 900, 1000)]))
    # exactOutput paths are token_out first; decoded view is normalised to token_in first
    assert d.args["params"]["path_decoded"] == {"tokens": [A3, A2, A1], "fees": [500, 3000]}
    with pytest.raises(AbiError):
        decode_v3_path("0x" + "aa" * 30)
    with pytest.raises(AbiError):
        encode_v3_path([A1], [3000])


def test_decode_universal_router_execute():
    path = encode_v3_path([A1, A2], [3000])
    inputs = [
        "0x" + encode(["address", "uint256"], ["0x" + "02".rjust(40, "0"), 10**18]).hex(),
        "0x" + encode(["address", "uint256", "uint256", "bytes", "bool"],
                      ["0x" + "01".rjust(40, "0"), 10**18, 5, path, False]).hex(),
        "0x" + encode(["(((address,uint160,uint48,uint48),address,uint256),bytes)"],
                      [[((A1, 2**160 - 1, 2**48 - 1, 0), A3, 1), "0x"]]).hex(),
    ]
    d = decode_call(encode_call("execute(bytes,bytes[],uint256)", ["0x0b800a", inputs, 99]))
    assert d.kind == "universal_router_execute"
    assert d.args["commands_decoded"] == ["WRAP_ETH", "V3_SWAP_EXACT_IN", "PERMIT2_PERMIT"]
    wrap, swap, permit = d.inner
    assert wrap.args["amount"] == 10**18 and wrap.args["allow_revert"] is False
    assert swap.args["allow_revert"] is True  # 0x80 flag
    assert swap.args["path_decoded"]["tokens"] == [A1, A2]
    assert permit.args["permit_single"]["spender"] == A3


def test_universal_router_unknown_and_malformed_commands():
    out = decode_universal_router("0x3f0b", ["0x", "0x00"])
    assert out[0].kind == "ur_unknown_command"
    assert out[1].kind == "malformed" and out[1].error


def test_universal_router_sub_plan_recurses():
    inner_inputs = ["0x" + encode(["address", "uint256"], [A1, 5]).hex()]
    sub = "0x" + encode(["bytes", "bytes[]"], ["0x0b", inner_inputs]).hex()
    out = decode_universal_router("0x21", [sub])
    assert out[0].name == "EXECUTE_SUB_PLAN" and out[0].inner[0].name == "WRAP_ETH"


def test_decode_weth_and_multicall_and_multicall3():
    assert decode_call("0xd0e30db0").kind == "weth_deposit"
    assert decode_call(encode_call("withdraw(uint256)", [5])).args == {"wad": 5}
    inner = [encode_call("approve(address,uint256)", [A1, 1]), "0xdeadbeef"]
    m = decode_call(encode_call("multicall(uint256,bytes[])", [99, inner]))
    assert m.kind == "multicall_deadline" and [c.kind for c in m.inner] == ["erc20_approve", "unknown"]
    agg = decode_call(encode_call("aggregate3((address,bool,bytes)[])",
                                  [[(A2, False, encode_call("transfer(address,uint256)", [A1, 7]))]]))
    assert agg.inner[0].target == A2 and agg.inner[0].kind == "erc20_transfer"
    assert agg.args["calls"][0]["allow_failure"] is False


def test_decode_call_never_raises_on_hostile_input():
    for data in ("0x", "0x12", "0xdeadbeef", "0x095ea7b3", "0x095ea7b3" + "ff" * 40, "zz", "0xabc"):
        d = decode_call(data)
        assert d.kind in ("empty", "malformed", "unknown")
    assert decode_call("0x").kind == "empty"
    assert decode_call("0x095ea7b3aa").kind == "malformed"


def test_nesting_depth_limited():
    data = encode_call("approve(address,uint256)", [A1, 1])
    for _ in range(6):
        data = encode_call("multicall(bytes[])", [[data]])
    d = decode_call(data)
    leaves = [c for c in d.walk() if not c.inner]
    assert leaves and all(c.error == "nesting too deep" or c.kind != "multicall" for c in leaves)


def test_describe_and_to_dict():
    d = decode_call(encode_call("multicall(bytes[])", [[encode_call("approve(address,uint256)", [A1, 1])]]))
    assert describe(d) == "Multicall [ERC-20/721 approve]"
    assert d.to_dict()["inner"][0]["kind"] == "erc20_approve"
    assert describe(decode_call("0x")) == "plain ETH transfer (no calldata)"
