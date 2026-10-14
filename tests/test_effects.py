"""Static effect extraction: every decoded call kind maps to the right approvals/transfers/swaps."""
import pytest

from txwarden.abi import (
    UR_ADDRESS_THIS,
    UR_MSG_SENDER,
    decode_call,
    encode,
    encode_call,
    encode_v3_path,
)
from txwarden.effects import UINT256_MAX, extract_effects
from txwarden.models import Tx

from .helpers import EVIL, FRIEND, OTHER, ROUTER, STRANGER, TOKEN, USDC, WETH, U, ur_calldata


def fx(sig: str, values: list, to: str = TOKEN, value: int = 0):
    tx = Tx(U, to, encode_call(sig, values), value)
    return tx, extract_effects(tx, decode_call(tx.data))


def test_erc20_approve_and_increase_allowance():
    _, e = fx("approve(address,uint256)", [EVIL, 5])
    a = e.approvals[0]
    assert (a.token, a.owner, a.spender, a.amount, a.via) == (TOKEN, U, EVIL, 5, "")
    _, e = fx("increaseAllowance(address,uint256)", [EVIL, 9])
    assert e.approvals[0].amount == 9 and e.kinds == ["erc20_increase_allowance"]


def test_erc20_transfer_and_transfer_from():
    _, e = fx("transfer(address,uint256)", [FRIEND, 7])
    t = e.transfers[0]
    assert (t.token, t.sender, t.recipient, t.amount, t.operator) == (TOKEN, U, FRIEND, 7, None)
    _, e = fx("transferFrom(address,address,uint256)", [OTHER, FRIEND, 8])
    t = e.transfers[0]
    assert t.sender == OTHER and t.recipient == FRIEND and t.operator == U


def test_nft_transfers():
    _, e = fx("safeTransferFrom(address,address,uint256)", [U, FRIEND, 42])
    t = e.transfers[0]
    assert t.kind == "erc721" and t.token_id == 42 and t.amount == 1
    _, e = fx("safeTransferFrom(address,address,uint256,bytes)", [U, FRIEND, 43, "0x"])
    assert e.transfers[0].token_id == 43
    _, e = fx("safeTransferFrom(address,address,uint256,uint256,bytes)", [U, FRIEND, 5, 9, "0x"])
    t = e.transfers[0]
    assert t.kind == "erc1155" and t.token_id == 5 and t.amount == 9
    _, e = fx("safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
              [U, FRIEND, [1, 2, 3], [10, 20, 30], "0x"])
    assert [(t.token_id, t.amount) for t in e.transfers] == [(1, 10), (2, 20), (3, 30)]


def test_set_approval_for_all():
    _, e = fx("setApprovalForAll(address,bool)", [EVIL, True])
    o = e.operator_approvals[0]
    assert o.operator == EVIL and o.approved and o.owner == U and o.token == TOKEN
    _, e = fx("setApprovalForAll(address,bool)", [EVIL, False])
    assert not e.operator_approvals[0].approved


def test_permits():
    sig = "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
    _, e = fx(sig, [U, EVIL, 10, 1234, 27, "0x" + "01" * 32, "0x" + "02" * 32])
    p = e.permits[0]
    assert (p.kind, p.spender, p.amount, p.deadline, p.owner) == ("eip2612", EVIL, 10, 1234, U)
    dai = "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)"
    _, e = fx(dai, [U, EVIL, 0, 0, True, 27, "0x" + "01" * 32, "0x" + "02" * 32])
    p = e.permits[0]
    assert p.kind == "dai" and p.amount == UINT256_MAX and p.deadline == UINT256_MAX
    _, e = fx(dai, [U, EVIL, 0, 5000, False, 27, "0x" + "01" * 32, "0x" + "02" * 32])
    assert e.permits[0].amount == 0 and e.permits[0].deadline == 5000


def test_permit2_family():
    sig = "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)"
    _, e = fx(sig, [U, ((USDC, 2**160 - 1, 2**48 - 1, 0), EVIL, 99), "0x"])
    p = e.permits[0]
    assert p.kind == "permit2" and p.token == USDC and p.spender == EVIL and p.owner == U
    batch = "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)"
    _, e = fx(batch, [U, ([(USDC, 1, 2, 0), (WETH, 3, 4, 0)], EVIL, 99), "0x"])
    assert [(p.token, p.amount) for p in e.permits] == [(USDC, 1), (WETH, 3)]
    ptf = "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)"
    _, e = fx(ptf, [((USDC, 100), 1, 2), (FRIEND, 60), U, "0x"])
    t = e.transfers[0]
    assert t.token == USDC and t.sender == U and t.recipient == FRIEND and t.amount == 60
    _, e = fx("approve(address,address,uint160,uint48)", [USDC, EVIL, 2**160 - 1, 77])
    a = e.approvals[0]
    assert a.via == "permit2" and a.expiration == 77 and a.token == USDC and a.spender == EVIL


V2_CASES = [
    # signature, values, token_in, token_out, amount_in, min_out, exact_in, eth_in, eth_out, fot
    ("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
     [100, 90, [USDC, WETH], U, 9], USDC, WETH, 100, 90, True, False, False, False),
    ("swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
     [90, 100, [USDC, WETH], U, 9], USDC, WETH, 100, 90, False, False, False, False),
    ("swapExactETHForTokens(uint256,address[],address,uint256)",
     [90, [WETH, USDC], U, 9], WETH, USDC, 55, 90, True, True, False, False),
    ("swapETHForExactTokens(uint256,address[],address,uint256)",
     [90, [WETH, USDC], U, 9], WETH, USDC, 55, 90, False, True, False, False),
    ("swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
     [100, 90, [USDC, WETH], U, 9], USDC, WETH, 100, 90, True, False, True, False),
    ("swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
     [90, 100, [USDC, WETH], U, 9], USDC, WETH, 100, 90, False, False, True, False),
    ("swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
     [100, 90, [USDC, WETH], U, 9], USDC, WETH, 100, 90, True, False, False, True),
    ("swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)",
     [90, [WETH, USDC], U, 9], WETH, USDC, 55, 90, True, True, False, True),
    ("swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
     [100, 90, [USDC, WETH], U, 9], USDC, WETH, 100, 90, True, False, True, True),
]


@pytest.mark.parametrize("sig,vals,t_in,t_out,amt,min_out,exact,eth_in,eth_out,fot", V2_CASES,
                         ids=[c[0].split("(")[0] for c in V2_CASES])
def test_v2_swap_variants(sig, vals, t_in, t_out, amt, min_out, exact, eth_in, eth_out, fot):
    _, e = fx(sig, vals, to=ROUTER, value=55)
    s = e.swaps[0]
    assert (s.protocol, s.token_in, s.token_out) == ("v2", t_in, t_out)
    assert (s.amount_in, s.min_out, s.exact_in) == (amt, min_out, exact)
    assert (s.eth_in, s.eth_out, s.fee_on_transfer) == (eth_in, eth_out, fot)
    assert s.recipient == U


def test_v2_single_token_path_yields_no_swap():
    _, e = fx("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
              [1, 1, [USDC], U, 9], to=ROUTER)
    assert e.swaps == []


def test_v3_swaps():
    single = "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"
    _, e = fx(single, [(USDC, WETH, 500, FRIEND, 9, 1000, 900, 0)], to=ROUTER)
    s = e.swaps[0]
    assert (s.protocol, s.fees, s.recipient, s.amount_in, s.min_out) == (
        "v3", (500,), FRIEND, 1000, 900)
    out_single = "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))"
    _, e = fx(out_single, [(USDC, WETH, 3000, U, 9, 900, 1000, 0)], to=ROUTER)
    s = e.swaps[0]
    assert not s.exact_in and s.amount_in == 1000 and s.min_out == 900
    path = encode_v3_path([USDC, WETH, OTHER], [500, 3000])
    _, e = fx("exactInput((bytes,address,uint256,uint256,uint256))", [(path, U, 9, 1000, 900)],
              to=ROUTER, value=1)
    s = e.swaps[0]
    assert s.path == (USDC, WETH, OTHER) and s.fees == (500, 3000) and s.eth_in
    _, e = fx("exactOutput((bytes,address,uint256,uint256,uint256))", [(path, U, 9, 900, 1000)],
              to=ROUTER)
    s = e.swaps[0]
    assert s.path == (OTHER, WETH, USDC) and not s.exact_in and s.amount_in == 1000


def test_liquidity_intents():
    _, e = fx("addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
              [USDC, WETH, 1, 1, 0, 0, U, 9], to=ROUTER)
    assert (e.lp[0].action, e.lp[0].token_a, e.lp[0].token_b) == ("add", USDC, WETH)
    _, e = fx("addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
              [USDC, 1, 0, 0, U, 9], to=ROUTER)
    assert (e.lp[0].token_a, e.lp[0].token_b) == (USDC, WETH)
    _, e = fx("removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
              [USDC, WETH, 777, 0, 0, U, 9], to=ROUTER)
    assert e.lp[0].action == "remove" and e.lp[0].liquidity == 777
    _, e = fx("removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
              [USDC, 555, 0, 0, U, 9], to=ROUTER)
    assert e.lp[0].liquidity == 555 and e.lp[0].token_b == WETH
    _, e = fx("decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
              [(12, 999, 0, 0, 9)])
    assert (e.lp[0].protocol, e.lp[0].token_id, e.lp[0].liquidity) == ("v3", 12, 999)


def test_weth_wrap_unwrap():
    tx = Tx(U, WETH, "0xd0e30db0", 5)
    assert extract_effects(tx, decode_call(tx.data)).wraps == [("wrap", 5)]
    _, e = fx("withdraw(uint256)", [6], to=WETH)
    assert e.wraps == [("unwrap", 6)]


def test_multicall_flattens_nested_effects():
    inner = [encode_call("approve(address,uint256)", [EVIL, 1]),
             encode_call("transfer(address,uint256)", [FRIEND, 2]),
             "0xdeadbeef"]
    for sig, vals in (("multicall(bytes[])", [inner]), ("multicall(uint256,bytes[])", [9, inner]),
                      ("multicall(bytes32,bytes[])", ["0x" + "00" * 32, inner])):
        _, e = fx(sig, vals, to=ROUTER)
        assert [a.spender for a in e.approvals] == [EVIL]
        assert [t.recipient for t in e.transfers] == [FRIEND]


def test_multicall3_uses_each_calls_own_target():
    approve = encode_call("approve(address,uint256)", [EVIL, 2**255])
    for sig, vals in (
        ("aggregate((address,bytes)[])", [[(USDC, approve)]]),
        ("aggregate3((address,bool,bytes)[])", [[(USDC, False, approve)]]),
        ("tryAggregate(bool,(address,bytes)[])", [False, [(USDC, approve)]]),
    ):
        _, e = fx(sig, vals, to="0xca11bde05977b3631167028862be2a173976ca11")
        assert e.approvals[0].token == USDC  # the token being approved, not Multicall3


def _ur(commands: bytes, inputs: list[str], **kw):
    tx = Tx(U, ROUTER, ur_calldata(commands, inputs), kw.get("value", 0))
    return tx, extract_effects(tx, decode_call(tx.data))


def _hex(types, values):
    return "0x" + encode(types, values).hex()


def test_universal_router_swaps_and_recipient_constants():
    me, this = UR_MSG_SENDER, UR_ADDRESS_THIS
    path = encode_v3_path([USDC, WETH], [500])
    _, e = _ur(bytes([0x00, 0x01, 0x08, 0x09]), [
        _hex(["address", "uint256", "uint256", "bytes", "bool"], [me, 100, 90, path, True]),
        _hex(["address", "uint256", "uint256", "bytes", "bool"], [this, 90, 100, path, True]),
        _hex(["address", "uint256", "uint256", "address[]", "bool"], [FRIEND, 100, 90, [USDC, WETH], True]),
        _hex(["address", "uint256", "uint256", "address[]", "bool"], [me, 90, 100, [USDC, WETH], True]),
    ])
    v3_in, v3_out, v2_in, v2_out = e.swaps
    assert v3_in.recipient == U and v3_in.exact_in and v3_in.fees == (500,)
    assert v3_out.recipient == ROUTER and not v3_out.exact_in
    assert v3_out.path == (WETH, USDC)  # exact-out paths are stored output-first
    assert v2_in.recipient == FRIEND and v2_in.amount_in == 100 and v2_in.min_out == 90
    assert not v2_out.exact_in and v2_out.amount_in == 100 and v2_out.min_out == 90


def test_universal_router_permit2_commands():
    details = (USDC, 2**160 - 1, 2**48 - 1, 0)
    single = _hex(["((address,uint160,uint48,uint48),address,uint256)", "bytes"],
                  [(details, EVIL, 9), "0x"])
    batch = _hex(["((address,uint160,uint48,uint48)[],address,uint256)", "bytes"],
                 [([details, (WETH, 5, 6, 0)], OTHER, 9), "0x"])
    pull = _hex(["address", "address", "uint160"], [USDC, ROUTER, 50])
    pull_batch = _hex(["(address,address,uint160,address)[]"], [[(U, FRIEND, 7, WETH)]])
    _, e = _ur(bytes([0x0A, 0x03, 0x02, 0x0D]), [single, batch, pull, pull_batch])
    assert [(p.spender, p.token) for p in e.permits] == [(EVIL, USDC), (OTHER, USDC), (OTHER, WETH)]
    assert all(p.owner == U and p.kind == "permit2" for p in e.permits)
    t_single, t_batch = e.transfers
    assert t_single.sender == U and t_single.recipient == ROUTER and t_single.amount == 50
    assert t_single.operator == ROUTER
    assert t_batch.recipient == FRIEND and t_batch.token == WETH and t_batch.amount == 7


def test_universal_router_sweep_transfer_pay_portion_and_wrap():
    sweep = _hex(["address", "address", "uint256"], [USDC, STRANGER, 5])
    pay = _hex(["address", "address", "uint256"], [USDC, FRIEND, 25])
    xfer = _hex(["address", "address", "uint256"], [WETH, UR_MSG_SENDER, 8])
    wrap = _hex(["address", "uint256"], [UR_ADDRESS_THIS, 10])
    unwrap = _hex(["address", "uint256"], [UR_MSG_SENDER, 4])
    _, e = _ur(bytes([0x04, 0x06, 0x05, 0x0B, 0x0C]), [sweep, pay, xfer, wrap, unwrap])
    assert [t.recipient for t in e.transfers] == [STRANGER, FRIEND, U]
    assert all(t.sender == ROUTER for t in e.transfers)  # the router holds the funds
    assert e.transfers[1].amount == 0  # PAY_PORTION carries bips, which is not an amount
    assert e.wraps == [("wrap", 10), ("unwrap", 4)]


def test_universal_router_sub_plan_and_malformed_command():
    sub = _hex(["bytes", "bytes[]"], ["0x0b", [_hex(["address", "uint256"], [ROUTER, 3])]])
    _, e = _ur(bytes([0x21, 0x04]), [sub, "0x00"])
    assert e.wraps == [("wrap", 3)]
    assert "malformed" in e.kinds


def test_unknown_selector_has_no_effects():
    tx = Tx(U, TOKEN, "0xdeadbeef")
    e = extract_effects(tx, decode_call(tx.data))
    assert e.kinds == ["unknown"]
    assert not (e.approvals or e.transfers or e.permits or e.swaps or e.operator_approvals)
