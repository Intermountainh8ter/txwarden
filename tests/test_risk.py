from txwarden.models import Approval, SimResult, Swap, Transfer, Tx, Verdict
from txwarden.risk import UNLIMITED, PolicyConfig, assess

U = "0x" + "11" * 20
ROUTER = "0x" + "aa" * 20
EVIL = "0x" + "de" * 20
OTHER = "0x" + "bb" * 20
TOKEN = "0x" + "cc" * 20
TX = Tx(sender=U, to=TOKEN)
POL = PolicyConfig(trusted_spenders={ROUTER}, denylist={EVIL})


def rules(findings):
    return {f.rule for f in findings}


def test_clean_tx_allowed():
    v, f = assess(TX, SimResult(success=True), POL)
    assert v == Verdict.ALLOW and not f


def test_unlimited_unknown_blocks():
    sim = SimResult(True, approvals=[Approval(TOKEN, U, OTHER, UNLIMITED)])
    v, f = assess(TX, sim, POL)
    assert v == Verdict.BLOCK and "UNLIMITED_APPROVAL_UNKNOWN" in rules(f)


def test_unlimited_trusted_allowed_with_note():
    sim = SimResult(True, approvals=[Approval(TOKEN, U, ROUTER, UNLIMITED)])
    v, f = assess(TX, sim, POL)
    assert v == Verdict.ALLOW and "UNLIMITED_APPROVAL_TRUSTED" in rules(f)


def test_denylisted_target_blocks():
    v, _ = assess(Tx(sender=U, to=EVIL), SimResult(True), POL)
    assert v == Verdict.BLOCK


def test_drain_to_unknown_warns():
    sim = SimResult(True, transfers=[Transfer(TOKEN, U, OTHER, 99, 100)])
    v, f = assess(TX, sim, POL)
    assert v == Verdict.WARN and "NEAR_FULL_BALANCE_TO_NEW_ADDRESS" in rules(f)


def test_revert_warns():
    v, f = assess(TX, SimResult(False, revert_reason="EXPIRED"), POL)
    assert v == Verdict.WARN and "REVERT" in rules(f)


def test_extreme_slippage_blocks():
    swap = Swap(amount_in=10, min_out=1, reserve_in=1e6, reserve_out=1e6)
    v, f = assess(TX, SimResult(True, swap=swap), POL)
    assert v == Verdict.BLOCK and "SLIPPAGE_TOLERANCE_EXTREME" in rules(f)


def test_policy_addresses_case_insensitive():
    pol = PolicyConfig(denylist={EVIL.upper().replace("0X", "0x")})
    v, _ = assess(Tx(sender=U, to=EVIL), SimResult(True), pol)
    assert v == Verdict.BLOCK
