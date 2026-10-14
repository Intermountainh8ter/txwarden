"""Static effect extraction: what a decoded call *asks for*, before any chain state is consulted.

The simulator enriches these with balances, reserves and probes; the batch analyser and the
offline CLI use them directly. Everything here is a pure function of (tx, decoded call).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .abi import UR_ADDRESS_THIS, UR_MSG_SENDER, DecodedCall, decode_call
from .models import Approval, CallFrame, OperatorApproval, Permit, Transfer, Tx

WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
UINT160_MAX = 2**160 - 1
UINT48_MAX = 2**48 - 1
UINT256_MAX = 2**256 - 1


@dataclass(frozen=True)
class SwapIntent:
    protocol: str  # v2 | v3
    token_in: str
    token_out: str
    amount_in: int
    min_out: int
    exact_in: bool
    path: tuple[str, ...]
    fees: tuple[int, ...] = ()  # V3 fee tiers per hop, in hundredths of a bip
    recipient: str = ""
    eth_in: bool = False
    eth_out: bool = False
    fee_on_transfer: bool = False


@dataclass(frozen=True)
class LPIntent:
    action: str  # add | remove
    protocol: str  # v2 | v3
    token_a: str = ""
    token_b: str = ""
    liquidity: int = 0
    token_id: int | None = None


@dataclass
class StaticEffects:
    approvals: list[Approval] = field(default_factory=list)
    operator_approvals: list[OperatorApproval] = field(default_factory=list)
    permits: list[Permit] = field(default_factory=list)
    transfers: list[Transfer] = field(default_factory=list)
    swaps: list[SwapIntent] = field(default_factory=list)
    lp: list[LPIntent] = field(default_factory=list)
    wraps: list[tuple[str, int]] = field(default_factory=list)  # ("wrap"|"unwrap", amount)
    kinds: list[str] = field(default_factory=list)
    # who ends up with swap output / withdrawn liquidity / router-held funds (lowercase)
    output_recipients: list[str] = field(default_factory=list)

    def extend(self, other: StaticEffects) -> None:
        for name in ("approvals", "operator_approvals", "permits", "transfers", "swaps", "lp",
                     "wraps", "kinds", "output_recipients"):
            getattr(self, name).extend(getattr(other, name))


def _lower(a: str) -> str:
    return a.lower()


def _ur_recipient(addr: str, sender: str, router: str) -> str:
    a = addr.lower()
    if a == UR_MSG_SENDER:
        return sender
    if a == UR_ADDRESS_THIS:
        return router
    return a


def _v2_swap(kind: str, args: dict, tx: Tx, weth: str) -> SwapIntent | None:
    path = tuple(_lower(p) for p in args.get("path", ()))
    if len(path) < 2:
        return None
    eth_in = kind in ("v2_swap_exact_eth_for_tokens", "v2_swap_eth_for_exact_tokens",
                      "v2_swap_exact_eth_for_tokens_fot")
    eth_out = kind in ("v2_swap_exact_tokens_for_eth", "v2_swap_tokens_for_exact_eth",
                       "v2_swap_exact_tokens_for_eth_fot")
    exact_in = "exact_tokens_for" in kind or "exact_eth_for" in kind
    if exact_in:
        amount_in = tx.value if eth_in else int(args["amount_in"])
        min_out = int(args["amount_out_min"])
    else:  # exact output: model as "spend up to amount_in_max for at least amount_out"
        amount_in = tx.value if eth_in else int(args["amount_in_max"])
        min_out = int(args["amount_out"])
    return SwapIntent("v2", path[0], path[-1], amount_in, min_out, exact_in, path,
                      recipient=_lower(args.get("to", "")), eth_in=eth_in, eth_out=eth_out,
                      fee_on_transfer=kind.endswith("_fot"))


def _v3_single(kind: str, p: dict, tx: Tx) -> SwapIntent:
    exact_in = kind == "v3_exact_input_single"
    amount_in = int(p["amount_in"]) if exact_in else int(p["amount_in_max"])
    min_out = int(p["amount_out_min"]) if exact_in else int(p["amount_out"])
    t_in, t_out = _lower(p["token_in"]), _lower(p["token_out"])
    return SwapIntent("v3", t_in, t_out, amount_in, min_out, exact_in, (t_in, t_out),
                      (int(p["fee"]),), _lower(p["recipient"]), eth_in=tx.value > 0)


def _v3_path(kind: str, p: dict, tx: Tx) -> SwapIntent:
    exact_in = kind == "v3_exact_input"
    dec = p["path_decoded"]
    tokens = tuple(_lower(t) for t in dec["tokens"])
    amount_in = int(p["amount_in"]) if exact_in else int(p["amount_in_max"])
    min_out = int(p["amount_out_min"]) if exact_in else int(p["amount_out"])
    return SwapIntent("v3", tokens[0], tokens[-1], amount_in, min_out, exact_in, tokens,
                      tuple(int(f) for f in dec["fees"]), _lower(p["recipient"]),
                      eth_in=tx.value > 0)


def _permit2_single(details: dict, spender: str, owner: str) -> Permit:
    return Permit(_lower(details["token"]), owner, _lower(spender), int(details["amount"]),
                  int(details["expiration"]), "permit2")


def _universal_router(call: DecodedCall, tx: Tx, weth: str, eff: StaticEffects) -> None:
    router = tx.to
    for cmd in call.inner:
        a = cmd.args
        k = cmd.name
        if cmd.kind == "malformed":
            eff.kinds.append("malformed")
            continue
        if k in ("V2_SWAP_EXACT_IN", "V2_SWAP_EXACT_OUT"):
            path = tuple(_lower(p) for p in a["path"])
            exact_in = k.endswith("_IN")
            amount_in = int(a["amount_in"] if exact_in else a["amount_in_max"])
            min_out = int(a["amount_out_min"] if exact_in else a["amount_out"])
            recipient = _ur_recipient(a["recipient"], tx.sender, router)
            eff.swaps.append(SwapIntent("v2", path[0], path[-1], amount_in, min_out, exact_in,
                                        path, recipient=recipient))
            eff.output_recipients.append(recipient)
        elif k in ("V3_SWAP_EXACT_IN", "V3_SWAP_EXACT_OUT"):
            dec = a["path_decoded"]
            tokens = tuple(_lower(t) for t in dec["tokens"])
            exact_in = k.endswith("_IN")
            amount_in = int(a["amount_in"] if exact_in else a["amount_in_max"])
            min_out = int(a["amount_out_min"] if exact_in else a["amount_out"])
            recipient = _ur_recipient(a["recipient"], tx.sender, router)
            eff.swaps.append(SwapIntent("v3", tokens[0], tokens[-1], amount_in, min_out, exact_in,
                                        tokens, tuple(int(f) for f in dec["fees"]), recipient))
            eff.output_recipients.append(recipient)
        elif k == "PERMIT2_PERMIT":
            ps = a["permit_single"]
            eff.permits.append(_permit2_single(ps["details"], ps["spender"], tx.sender))
        elif k == "PERMIT2_PERMIT_BATCH":
            pb = a["permit_batch"]
            for d in pb["details"]:
                eff.permits.append(_permit2_single(d, pb["spender"], tx.sender))
        elif k == "PERMIT2_TRANSFER_FROM":
            eff.transfers.append(Transfer(_lower(a["token"]), tx.sender,
                                          _ur_recipient(a["recipient"], tx.sender, router),
                                          int(a["amount"]), operator=router))
        elif k == "PERMIT2_TRANSFER_FROM_BATCH":
            for b in a["batch"]:
                eff.transfers.append(Transfer(_lower(b["token"]), _lower(b["from"]),
                                              _ur_recipient(b["to"], tx.sender, router),
                                              int(b["amount"]), operator=router))
        elif k in ("TRANSFER", "SWEEP", "PAY_PORTION"):
            # PAY_PORTION carries basis points of the router's balance, not a token amount, so the
            # amount is unknown statically (0); the recipient is what the risk rules care about.
            amount = 0 if k == "PAY_PORTION" else int(a["value" if k == "TRANSFER" else "amount_min"])
            recipient = _ur_recipient(a["recipient"], tx.sender, router)
            eff.transfers.append(Transfer(_lower(a["token"]), router, recipient, amount,
                                          kind="erc20"))
            eff.output_recipients.append(recipient)
        elif k in ("SWEEP_ERC721", "SWEEP_ERC1155"):
            eff.output_recipients.append(_ur_recipient(a["recipient"], tx.sender, router))
        elif k == "WRAP_ETH":
            eff.wraps.append(("wrap", int(a["amount"])))
            eff.output_recipients.append(_ur_recipient(a["recipient"], tx.sender, router))
        elif k == "UNWRAP_WETH":
            eff.wraps.append(("unwrap", int(a["amount_min"])))
            eff.output_recipients.append(_ur_recipient(a["recipient"], tx.sender, router))
        elif k == "EXECUTE_SUB_PLAN":
            sub = DecodedCall(cmd.selector, "universal_router_execute", "sub plan",
                              "universal_router", inner=cmd.inner)
            _universal_router(sub, tx, weth, eff)
        eff.kinds.append(cmd.kind)


def extract_effects(tx: Tx, call: DecodedCall, weth: str = WETH) -> StaticEffects:
    eff = StaticEffects()
    k, a = call.kind, call.args
    token = tx.to
    sender = tx.sender
    eff.kinds.append(k)

    if k == "erc20_approve":
        eff.approvals.append(Approval(token, sender, _lower(a["spender"]), int(a["amount"])))
    elif k == "erc20_increase_allowance":
        eff.approvals.append(Approval(token, sender, _lower(a["spender"]), int(a["added_value"])))
    elif k == "erc20_transfer":
        eff.transfers.append(Transfer(token, sender, _lower(a["to"]), int(a["amount"])))
    elif k == "erc20_transfer_from":
        eff.transfers.append(Transfer(token, _lower(a["from"]), _lower(a["to"]), int(a["amount"]),
                                      operator=sender))
    elif k in ("erc721_safe_transfer_from", "erc721_safe_transfer_from_data"):
        eff.transfers.append(Transfer(token, _lower(a["from"]), _lower(a["to"]), 1, kind="erc721",
                                      operator=sender, token_id=int(a["token_id"])))
    elif k == "erc1155_safe_transfer_from":
        eff.transfers.append(Transfer(token, _lower(a["from"]), _lower(a["to"]), int(a["amount"]),
                                      kind="erc1155", operator=sender, token_id=int(a["id"])))
    elif k == "erc1155_safe_batch_transfer_from":
        for tid, amt in zip(a["ids"], a["amounts"]):
            eff.transfers.append(Transfer(token, _lower(a["from"]), _lower(a["to"]), int(amt),
                                          kind="erc1155", operator=sender, token_id=int(tid)))
    elif k == "set_approval_for_all":
        eff.operator_approvals.append(OperatorApproval(token, sender, _lower(a["operator"]),
                                                       bool(a["approved"])))
    elif k == "erc20_permit":
        eff.permits.append(Permit(token, _lower(a["owner"]), _lower(a["spender"]), int(a["value"]),
                                  int(a["deadline"]), "eip2612"))
    elif k == "dai_permit":
        amount = UINT256_MAX if a["allowed"] else 0
        expiry = int(a["expiry"]) or UINT256_MAX  # expiry 0 means "never expires"
        eff.permits.append(Permit(token, _lower(a["holder"]), _lower(a["spender"]), amount, expiry,
                                  "dai"))
    elif k == "permit2_permit":
        ps = a["permit_single"]
        eff.permits.append(_permit2_single(ps["details"], ps["spender"], _lower(a["owner"])))
    elif k == "permit2_permit_batch":
        pb = a["permit_batch"]
        for d in pb["details"]:
            eff.permits.append(_permit2_single(d, pb["spender"], _lower(a["owner"])))
    elif k == "permit2_permit_transfer_from":
        p, td = a["permit"], a["transfer_details"]
        eff.transfers.append(Transfer(_lower(p["permitted"]["token"]), _lower(a["owner"]),
                                      _lower(td["to"]), int(td["requested_amount"]),
                                      operator=sender))
    elif k == "permit2_approve":
        eff.approvals.append(Approval(_lower(a["token"]), sender, _lower(a["spender"]),
                                      int(a["amount"]), via="permit2",
                                      expiration=int(a["expiration"])))
    elif k.startswith("v2_swap_"):
        s = _v2_swap(k, a, tx, weth)
        if s:
            eff.swaps.append(s)
            eff.output_recipients.append(s.recipient)
    elif k in ("v3_exact_input_single", "v3_exact_output_single"):
        s = _v3_single(k, a["params"], tx)
        eff.swaps.append(s)
        eff.output_recipients.append(s.recipient)
    elif k in ("v3_exact_input", "v3_exact_output"):
        s = _v3_path(k, a["params"], tx)
        eff.swaps.append(s)
        eff.output_recipients.append(s.recipient)
    elif k in ("v2_add_liquidity", "v2_add_liquidity_eth"):
        ta = _lower(a.get("token_a", a.get("token", "")))
        tb = _lower(a.get("token_b", weth))
        eff.lp.append(LPIntent("add", "v2", ta, tb))
        eff.output_recipients.append(_lower(a["to"]))
    elif k.startswith("v2_remove_liquidity"):
        ta = _lower(a.get("token_a", a.get("token", "")))
        tb = _lower(a.get("token_b", weth))
        eff.lp.append(LPIntent("remove", "v2", ta, tb, int(a["liquidity"])))
        eff.output_recipients.append(_lower(a["to"]))
    elif k == "v3_collect":
        eff.output_recipients.append(_lower(a["params"]["recipient"]))
    elif k == "v3_decrease_liquidity":
        p = a["params"]
        eff.lp.append(LPIntent("remove", "v3", liquidity=int(p["liquidity"]),
                               token_id=int(p["token_id"])))
    elif k == "weth_deposit":
        eff.wraps.append(("wrap", tx.value))
    elif k == "weth_withdraw":
        eff.wraps.append(("unwrap", int(a["wad"])))
    elif k in ("multicall", "multicall_deadline", "multicall_previous_block"):
        for sub in call.inner:
            eff.extend(extract_effects(tx, sub, weth))
    elif k in ("multicall3_aggregate", "multicall3_aggregate3", "multicall3_try_aggregate"):
        for sub in call.inner:
            target = (sub.target or tx.to).lower()
            inner_tx = Tx(tx.sender, target, tx.data, 0, tx.chain_id)
            eff.extend(extract_effects(inner_tx, sub, weth))
    elif k == "universal_router_execute":
        _universal_router(call, tx, weth, eff)
    return eff


def trace_transfers(tx: Tx, tree: CallFrame, weth: str = WETH) -> list[Transfer]:
    """Token movements out of the *sender's* account that happen below the top-level call.

    Calldata decoding only sees what the top-level selector says; an opaque contract (an
    "airdrop claim", a bridge, an aggregator) can pull the user's tokens with ``transferFrom``
    from inside the call tree. Every successful ``CALL`` frame below the root is decoded with the
    same selector tables, and the transfers whose ``from`` is the sender are returned with
    ``operator`` set to the frame's caller.
    """
    user = tx.sender.lower()
    out: list[Transfer] = []
    seen: set[tuple] = set()
    for depth, frame in tree.walk():
        if depth == 0 or frame.error or frame.kind != "CALL" or len(frame.input) < 10:
            continue
        sub = Tx(frame.sender, frame.to, frame.input, frame.value, tx.chain_id)
        for t in extract_effects(sub, decode_call(frame.input), weth).transfers:
            if t.sender.lower() != user or t.kind == "eth":
                continue
            key = (t.token, t.recipient, t.amount, t.token_id, t.operator)
            if key not in seen:
                seen.add(key)
                out.append(t)
    return out
