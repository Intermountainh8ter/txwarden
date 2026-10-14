"""One scenario per registered rule, policy-knob boundary tests and registry invariants."""
from __future__ import annotations

import math
from collections.abc import Callable

import pytest

from txwarden.amm import amount_out
from txwarden.batch import assess_bundle
from txwarden.models import (
    AccountInfo,
    Approval,
    CallFrame,
    HoneypotProbe,
    LPEvent,
    OperatorApproval,
    Permit,
    Severity,
    SimResult,
    Swap,
    Transfer,
    Tx,
    V3Swap,
    V3Tick,
    Verdict,
)
from txwarden.risk import (
    FAR_FUTURE,
    PERMIT2_UNLIMITED,
    RULES,
    UNLIMITED,
    PolicyConfig,
    assess,
    checks_for_rule,
)

from .helpers import EVIL, FRIEND, OTHER, ROUTER, STRANGER, TOKEN, U

NOW = 1_700_000_000
DAY = 86_400
TX = Tx(U, TOKEN)
POL = PolicyConfig(trusted_spenders={ROUTER}, trusted_recipients={FRIEND}, denylist={EVIL})
Scenario = Callable[[], tuple[Tx, SimResult, PolicyConfig]]


def rules_of(findings) -> set[str]:
    return {f.rule for f in findings}


def swap_sim(amount: float = 20.0, pool: float = 1000.0, tolerance: float = 0.0) -> SimResult:
    clean = amount_out(amount, pool, pool)
    return SimResult(True, swap=Swap(amount, clean * (1 - tolerance), pool, pool))


def v3_exhausted() -> SimResult:
    sp = 1.0
    ticks = (V3Tick(-100, 1e6), V3Tick(100, -1e6))
    return SimResult(True, swap_v3=V3Swap(1e6, 0.0, sp, 1e6, 0.003, True, ticks))


def tree(*frames: CallFrame) -> CallFrame:
    return CallFrame("CALL", U, TOKEN, calls=list(frames))


def probe(**kw) -> HoneypotProbe:
    base = dict(mode="simulate", buy_ok=True, sell_ok=True, amount_in=1e16, bought=1e19,
                returned=9.9e15, loss_fraction=0.01)
    return HoneypotProbe(**(base | kw))


def appr(spender: str, amount: int, via: str = "") -> Approval:
    return Approval(TOKEN, U, spender, amount, via)


def permit(spender: str, amount: int, deadline: int, kind: str = "eip2612") -> Permit:
    return Permit(TOKEN, U, spender, amount, deadline, kind)


def xfer(to: str, amount: int = 10, balance: int | None = 100, kind: str = "erc20") -> Transfer:
    return Transfer(TOKEN, U, to, amount, balance, kind)


def lookalike_of(address: str) -> str:
    return address[:6] + "0" * 32 + address[-4:]


SCENARIOS: dict[str, Scenario] = {
    "DENYLISTED_TARGET": lambda: (Tx(U, EVIL), SimResult(True), POL),
    "ADDRESS_LOOKALIKE": lambda: (
        TX, SimResult(True, approvals=[appr(lookalike_of(ROUTER), 5)]), POL),
    "CHAIN_ID_MISMATCH": lambda: (Tx(U, TOKEN, chain_id=10), SimResult(True),
                                  PolicyConfig(expected_chain_id=1)),
    "UNLIMITED_APPROVAL_UNKNOWN": lambda: (
        TX, SimResult(True, approvals=[appr(OTHER, UNLIMITED)]), POL),
    "APPROVAL_TO_DENYLISTED": lambda: (TX, SimResult(True, approvals=[appr(EVIL, 5)]), POL),
    "APPROVAL_UNKNOWN_SPENDER": lambda: (TX, SimResult(True, approvals=[appr(OTHER, 5)]), POL),
    "UNLIMITED_APPROVAL_TRUSTED": lambda: (
        TX, SimResult(True, approvals=[appr(ROUTER, UNLIMITED)]), POL),
    "APPROVAL_REVOKED": lambda: (TX, SimResult(True, approvals=[appr(OTHER, 0)]), POL),
    "OPERATOR_APPROVAL_UNKNOWN": lambda: (
        TX, SimResult(True, operator_approvals=[OperatorApproval(TOKEN, U, OTHER, True)]), POL),
    "OPERATOR_APPROVAL_DENYLISTED": lambda: (
        TX, SimResult(True, operator_approvals=[OperatorApproval(TOKEN, U, EVIL, True)]), POL),
    "OPERATOR_APPROVAL_TRUSTED": lambda: (
        TX, SimResult(True, operator_approvals=[OperatorApproval(TOKEN, U, ROUTER, True)]), POL),
    "OPERATOR_APPROVAL_REVOKED": lambda: (
        TX, SimResult(True, operator_approvals=[OperatorApproval(TOKEN, U, OTHER, False)]), POL),
    "PERMIT_UNLIMITED_UNKNOWN": lambda: (
        TX, SimResult(True, permits=[permit(OTHER, UNLIMITED, NOW + DAY)], block_timestamp=NOW), POL),
    "PERMIT_TO_DENYLISTED": lambda: (
        TX, SimResult(True, permits=[permit(EVIL, 5, NOW + DAY)], block_timestamp=NOW), POL),
    "PERMIT_UNKNOWN_SPENDER": lambda: (
        TX, SimResult(True, permits=[permit(OTHER, 5, NOW + DAY)], block_timestamp=NOW), POL),
    "PERMIT_FAR_DEADLINE": lambda: (
        TX, SimResult(True, permits=[permit(ROUTER, 5, NOW + 90 * DAY)], block_timestamp=NOW), POL),
    "PERMIT_UNLIMITED_TRUSTED": lambda: (
        TX, SimResult(True, permits=[permit(ROUTER, UNLIMITED, NOW + DAY)], block_timestamp=NOW),
        POL),
    "TRANSFER_TO_DENYLISTED": lambda: (TX, SimResult(True, transfers=[xfer(EVIL)]), POL),
    "NEAR_FULL_BALANCE_TO_NEW_ADDRESS": lambda: (
        TX, SimResult(True, transfers=[xfer(OTHER, 95)]), POL),
    "TRANSFER_TO_FRESH_ADDRESS": lambda: (
        TX, SimResult(True, transfers=[xfer(OTHER)], accounts={OTHER: AccountInfo(OTHER)}), POL),
    "TRANSFER_TO_UNKNOWN_CONTRACT": lambda: (
        TX, SimResult(True, transfers=[xfer(OTHER)],
                      accounts={OTHER: AccountInfo(OTHER, code_size=100)}), POL),
    "PRICE_IMPACT_EXTREME": lambda: (TX, swap_sim(600.0), POL),
    "PRICE_IMPACT_HIGH": lambda: (TX, swap_sim(60.0), POL),
    "SLIPPAGE_TOLERANCE_EXTREME": lambda: (TX, swap_sim(tolerance=0.2), POL),
    "SLIPPAGE_TOLERANCE_LOOSE": lambda: (TX, swap_sim(tolerance=0.01), POL),
    "SANDWICH_EXPOSURE_SEVERE": lambda: (TX, swap_sim(tolerance=0.02), POL),
    "SANDWICH_EXPOSURE": lambda: (TX, swap_sim(tolerance=0.005), POL),
    "LIQUIDITY_EXHAUSTED": lambda: (TX, v3_exhausted(), POL),
    "REVERT": lambda: (TX, SimResult(False, revert_reason="EXPIRED"), POL),
    "ETH_REJECTED_BY_CONTRACT": lambda: (
        Tx(U, TOKEN, value=5), SimResult(False, revert_reason="x", eth_receive_reverts=True), POL),
    "GAS_EXTREME": lambda: (TX, SimResult(True, gas_used=20_000_000), POL),
    "GAS_ABNORMAL": lambda: (TX, SimResult(True, gas_used=900_000, call_kind="erc20_approve"), POL),
    "SELFDESTRUCT_IN_TRACE": lambda: (
        TX, SimResult(True, call_tree=tree(CallFrame("SELFDESTRUCT", OTHER, STRANGER))), POL),
    "DELEGATECALL_TO_UNKNOWN": lambda: (
        TX, SimResult(True, call_tree=tree(CallFrame("CALL", TOKEN, OTHER, calls=[
            CallFrame("DELEGATECALL", OTHER, STRANGER)]))), POL),
    "PROXY_DELEGATECALL_UNKNOWN_IMPL": lambda: (
        TX, SimResult(True, call_tree=tree(CallFrame("DELEGATECALL", TOKEN, OTHER))), POL),
    "CONTRACT_CREATION_IN_TRACE": lambda: (
        TX, SimResult(True, call_tree=tree(CallFrame("CREATE2", TOKEN, OTHER))), POL),
    "DENYLISTED_IN_TRACE": lambda: (
        TX, SimResult(True, call_tree=tree(CallFrame("CALL", TOKEN, EVIL))), POL),
    "HONEYPOT_SELL_REVERTS": lambda: (
        TX, SimResult(True, honeypot=probe(sell_ok=False, loss_fraction=1.0,
                                           sell_revert_reason="TRANSFER_FAILED")), POL),
    "ROUND_TRIP_LOSS_SEVERE": lambda: (
        TX, SimResult(True, honeypot=probe(loss_fraction=0.4)), POL),
    "ROUND_TRIP_LOSS": lambda: (TX, SimResult(True, honeypot=probe(loss_fraction=0.1)), POL),
    "LP_REMOVAL_MAJORITY": lambda: (
        TX, SimResult(True, lp_events=[LPEvent("remove", "pool", 80.0, 100.0)]), POL),
    "LP_REMOVAL_LARGE": lambda: (
        TX, SimResult(True, lp_events=[LPEvent("remove", "pool", 30.0, 100.0)]), POL),
}

BUNDLE_SCENARIOS = {
    "BUNDLE_APPROVE_THEN_PULL": lambda: (
        [Tx(U, TOKEN), Tx(U, OTHER)],
        [SimResult(True, approvals=[appr(OTHER, UNLIMITED)]), SimResult(True)]),
    "BUNDLE_ADD_THEN_REMOVE_LIQUIDITY": lambda: (
        [Tx(U, ROUTER), Tx(U, ROUTER)],
        [SimResult(True, lp_events=[LPEvent("add", "Pool", 5.0, 100.0)]),
         SimResult(True, lp_events=[LPEvent("remove", "pool", 5.0, 100.0)])]),
    "BUNDLE_CUMULATIVE_DRAIN": lambda: (
        [Tx(U, TOKEN), Tx(U, TOKEN)],
        [SimResult(True, transfers=[xfer(OTHER, 50, 100)]),
         SimResult(True, transfers=[xfer(STRANGER, 45, 100)])]),
    "BUNDLE_MIXED_CHAIN_IDS": lambda: (
        [Tx(U, TOKEN, chain_id=1), Tx(U, TOKEN, chain_id=137)],
        [SimResult(True), SimResult(True)]),
}


@pytest.mark.parametrize("rule", sorted(SCENARIOS))
def test_rule_fires_with_registered_severity_and_verdict(rule):
    tx, sim, pol = SCENARIOS[rule]()
    verdict, findings = assess(tx, sim, pol)
    hits = [f for f in findings if f.rule == rule]
    assert hits, f"{rule} did not fire; got {sorted(rules_of(findings))}"
    assert all(f.severity == RULES[rule].severity for f in hits)
    worst = max((RULES[r].verdict for r in rules_of(findings)),
                key=lambda v: ("ALLOW", "WARN", "BLOCK").index(v.value))
    assert verdict == worst


@pytest.mark.parametrize("rule", sorted(SCENARIOS))
def test_rule_can_be_disabled(rule):
    tx, sim, pol = SCENARIOS[rule]()
    pol = PolicyConfig.from_dict(pol.to_dict() | {"disabled_rules": [rule.lower()]})  # any case
    _, findings = assess(tx, sim, pol)
    assert rule not in rules_of(findings)


@pytest.mark.parametrize("rule", sorted(BUNDLE_SCENARIOS))
def test_bundle_rule_fires_and_can_be_disabled(rule):
    txs, sims = BUNDLE_SCENARIOS[rule]()
    review = assess_bundle(txs, sims, POL)
    hits = [f for f in review.bundle_findings if f.rule == rule]
    assert hits and hits[0].severity == RULES[rule].severity
    off = assess_bundle(txs, sims, PolicyConfig.from_dict(POL.to_dict() | {"disabled_rules": [rule]}))
    assert rule not in {f.rule for f in off.bundle_findings}


def test_every_registered_rule_has_a_scenario_and_vice_versa():
    covered = set(SCENARIOS) | set(BUNDLE_SCENARIOS)
    assert covered == set(RULES), (sorted(set(RULES) - covered), sorted(covered - set(RULES)))


def test_every_non_bundle_rule_is_emitted_by_a_registered_check():
    for rule in SCENARIOS:
        assert checks_for_rule(rule), rule


def test_registry_records_are_complete():
    for spec in RULES.values():
        assert spec.id == spec.id.upper() and " " not in spec.id
        assert spec.title and spec.category
        assert isinstance(spec.severity, Severity)
        expected = {Severity.CRITICAL: Verdict.BLOCK, Severity.HIGH: Verdict.WARN}.get(
            spec.severity, Verdict.ALLOW)
        assert spec.verdict == expected
        for field in spec.config:
            assert field in PolicyConfig().to_dict(), (spec.id, field)


# --------------------------------------------------------------------------- verdict semantics

def test_clean_transaction_is_allowed_with_no_findings():
    assert assess(TX, SimResult(True), POL) == (Verdict.ALLOW, [])


def test_info_and_medium_findings_do_not_change_the_verdict():
    for rule in ("APPROVAL_REVOKED", "UNLIMITED_APPROVAL_TRUSTED", "TRANSFER_TO_UNKNOWN_CONTRACT",
                 "OPERATOR_APPROVAL_TRUSTED", "OPERATOR_APPROVAL_REVOKED", "PERMIT_UNLIMITED_TRUSTED",
                 "PROXY_DELEGATECALL_UNKNOWN_IMPL"):
        tx, sim, pol = SCENARIOS[rule]()
        verdict, findings = assess(tx, sim, pol)
        assert rule in rules_of(findings) and verdict == Verdict.ALLOW, rule


def test_worst_finding_decides_the_verdict():
    sim = SimResult(True, approvals=[appr(OTHER, 5), appr(OTHER, UNLIMITED)])
    verdict, findings = assess(TX, sim, POL)
    assert verdict == Verdict.BLOCK
    assert rules_of(findings) == {"APPROVAL_UNKNOWN_SPENDER", "UNLIMITED_APPROVAL_UNKNOWN"}


def test_failed_simulation_skips_swap_math_but_still_reports_static_effects():
    sim = SimResult(False, revert_reason="x", swap=Swap(1000, 1, 1e6, 1e6),
                    approvals=[appr(OTHER, UNLIMITED)])
    _, findings = assess(TX, sim, POL)
    assert {"REVERT", "UNLIMITED_APPROVAL_UNKNOWN"} <= rules_of(findings)
    assert not rules_of(findings) & {"SLIPPAGE_TOLERANCE_EXTREME", "PRICE_IMPACT_EXTREME"}


# --------------------------------------------------------------------------- approvals

def test_permit2_unlimited_is_uint160_max_not_uint255():
    big = appr(OTHER, PERMIT2_UNLIMITED, via="permit2")
    assert "UNLIMITED_APPROVAL_UNKNOWN" in rules_of(assess(TX, SimResult(True, approvals=[big]), POL)[1])
    erc20_same_number = appr(OTHER, PERMIT2_UNLIMITED)
    assert rules_of(assess(TX, SimResult(True, approvals=[erc20_same_number]), POL)[1]) == {
        "APPROVAL_UNKNOWN_SPENDER"}


def test_approval_threshold_is_two_to_the_255():
    assert "UNLIMITED_APPROVAL_UNKNOWN" in rules_of(assess(
        TX, SimResult(True, approvals=[appr(OTHER, 2**255)]), POL)[1])
    assert "UNLIMITED_APPROVAL_UNKNOWN" not in rules_of(assess(
        TX, SimResult(True, approvals=[appr(OTHER, 2**255 - 1)]), POL)[1])


def test_trusted_lists_are_case_insensitive_and_operators_inherit_trusted_spenders():
    pol = PolicyConfig(trusted_spenders={ROUTER.upper().replace("0X", "0x")})
    sim = SimResult(True, operator_approvals=[OperatorApproval(TOKEN, U, ROUTER, True)])
    assert rules_of(assess(TX, sim, pol)[1]) == {"OPERATOR_APPROVAL_TRUSTED"}
    pol2 = PolicyConfig(trusted_operators={OTHER})
    assert pol2.is_trusted_operator(OTHER) and not pol2.is_trusted_spender(OTHER)


# --------------------------------------------------------------------------- permits

def test_permit_without_block_timestamp_only_flags_never_expiring_deadlines():
    near = SimResult(True, permits=[permit(ROUTER, 5, NOW + 365 * DAY)])
    assert "PERMIT_FAR_DEADLINE" not in rules_of(assess(TX, near, POL)[1])
    never = SimResult(True, permits=[permit(ROUTER, 5, FAR_FUTURE)])
    assert "PERMIT_FAR_DEADLINE" in rules_of(assess(TX, never, POL)[1])


def test_permit_deadline_window_is_configurable():
    sim = SimResult(True, permits=[permit(ROUTER, 5, NOW + 10 * DAY)], block_timestamp=NOW)
    assert "PERMIT_FAR_DEADLINE" not in rules_of(assess(TX, sim, POL)[1])
    tight = PolicyConfig(trusted_spenders={ROUTER}, permit_deadline_warn_s=5 * DAY)
    assert "PERMIT_FAR_DEADLINE" in rules_of(assess(TX, sim, tight)[1])


def test_permit2_permit_unlimited_uses_uint160_threshold():
    sim = SimResult(True, permits=[permit(OTHER, PERMIT2_UNLIMITED, NOW + DAY, "permit2")],
                    block_timestamp=NOW)
    assert "PERMIT_UNLIMITED_UNKNOWN" in rules_of(assess(TX, sim, POL)[1])


def test_zero_amount_permit_is_a_revocation_and_not_flagged():
    sim = SimResult(True, permits=[permit(OTHER, 0, FAR_FUTURE)], block_timestamp=NOW)
    assert rules_of(assess(TX, sim, POL)[1]) == set()


# --------------------------------------------------------------------------- transfers

def test_transfers_to_self_trusted_or_booked_addresses_are_never_flagged():
    pol = PolicyConfig(trusted_recipients={FRIEND}, address_book={OTHER: "cold wallet"})
    for to in (U, FRIEND, OTHER):
        sim = SimResult(True, transfers=[xfer(to, 100)], accounts={to: AccountInfo(to)})
        assert rules_of(assess(TX, sim, pol)[1]) == set(), to


def test_transfers_not_sent_by_the_user_are_ignored_except_for_denylist():
    other_sender = Transfer(TOKEN, OTHER, STRANGER, 100, 100)
    assert rules_of(assess(TX, SimResult(True, transfers=[other_sender]), POL)[1]) == set()
    to_evil = Transfer(TOKEN, OTHER, EVIL, 1, 100)
    assert rules_of(assess(TX, SimResult(True, transfers=[to_evil]), POL)[1]) == {
        "TRANSFER_TO_DENYLISTED"}


def test_drain_fraction_is_configurable_and_needs_a_known_balance():
    sim = SimResult(True, transfers=[xfer(OTHER, 60)])
    assert "NEAR_FULL_BALANCE_TO_NEW_ADDRESS" not in rules_of(assess(TX, sim, POL)[1])
    assert "NEAR_FULL_BALANCE_TO_NEW_ADDRESS" in rules_of(
        assess(TX, sim, PolicyConfig(drain_fraction=0.5))[1])
    unknown_balance = SimResult(True, transfers=[xfer(OTHER, 10**30, balance=None)])
    assert rules_of(assess(TX, unknown_balance, POL)[1]) == set()


def test_fresh_and_contract_recipient_flags_can_be_turned_off():
    fresh = SimResult(True, transfers=[xfer(OTHER)], accounts={OTHER: AccountInfo(OTHER)})
    assert rules_of(assess(TX, fresh, PolicyConfig(flag_fresh_recipients=False))[1]) == set()
    contract = SimResult(True, transfers=[xfer(OTHER)],
                         accounts={OTHER: AccountInfo(OTHER, code_size=9)})
    assert rules_of(assess(TX, contract, PolicyConfig(flag_contract_recipients=False))[1]) == set()


def test_eth_transfers_to_contracts_are_not_flagged_as_token_loss():
    contract = SimResult(True, transfers=[xfer(OTHER, kind="eth")],
                         accounts={OTHER: AccountInfo(OTHER, code_size=9)})
    assert rules_of(assess(TX, contract, POL)[1]) == set()


# --------------------------------------------------------------------------- lookalikes

def test_lookalike_of_the_senders_own_address_is_flagged():
    sim = SimResult(True, transfers=[xfer(lookalike_of(U))])
    assert "ADDRESS_LOOKALIKE" in rules_of(assess(TX, sim, POL)[1])


def test_lookalike_window_is_configurable_and_known_addresses_are_exempt():
    near = ROUTER[:6] + "1" * 32 + ROUTER[-4:]
    sim = SimResult(True, approvals=[appr(near, 5)])
    assert "ADDRESS_LOOKALIKE" in rules_of(assess(TX, sim, POL)[1])
    strict = PolicyConfig(trusted_spenders={ROUTER}, lookalike_prefix=8, lookalike_suffix=8)
    assert "ADDRESS_LOOKALIKE" not in rules_of(assess(TX, sim, strict)[1])
    trusted_both = PolicyConfig(trusted_spenders={ROUTER, near})
    assert "ADDRESS_LOOKALIKE" not in rules_of(assess(TX, sim, trusted_both)[1])


def test_lookalike_is_reported_once_per_candidate_even_with_several_matches():
    other_known = ROUTER[:6] + "7" * 32 + ROUTER[-4:]
    pol = PolicyConfig(trusted_spenders={ROUTER, other_known})
    sim = SimResult(True, approvals=[appr(lookalike_of(ROUTER), 5)])
    assert sum(f.rule == "ADDRESS_LOOKALIKE" for f in assess(TX, sim, pol)[1]) == 1


# --------------------------------------------------------------------------- swaps

def test_swap_thresholds_move_with_policy():
    sim = swap_sim(tolerance=0.002)
    assert rules_of(assess(TX, sim, POL)[1]) == set()  # 17 bps extraction < 30
    assert "SANDWICH_EXPOSURE" in rules_of(assess(TX, sim, PolicyConfig(sandwich_warn_bps=10))[1])
    assert "SANDWICH_EXPOSURE_SEVERE" in rules_of(
        assess(TX, sim, PolicyConfig(sandwich_warn_bps=5, sandwich_block_bps=15))[1])
    assert "SLIPPAGE_TOLERANCE_LOOSE" in rules_of(
        assess(TX, sim, PolicyConfig(slippage_warn=0.001))[1])
    assert "SLIPPAGE_TOLERANCE_EXTREME" in rules_of(
        assess(TX, sim, PolicyConfig(slippage_block=0.001))[1])
    assert "PRICE_IMPACT_HIGH" in rules_of(assess(TX, sim, PolicyConfig(impact_warn_bps=100))[1])
    assert "PRICE_IMPACT_EXTREME" in rules_of(assess(TX, sim, PolicyConfig(impact_block_bps=100))[1])


def test_swap_with_min_out_above_clean_output_has_no_tolerance_and_no_sandwich():
    clean = amount_out(20.0, 1000.0, 1000.0)
    sim = SimResult(True, swap=Swap(20.0, clean * 1.5, 1000.0, 1000.0))
    assert rules_of(assess(TX, sim, POL)[1]) == set()


def test_multihop_and_v3_swaps_are_assessed_too():
    from txwarden.models import Hop, PathSwap

    hops = (Hop(1000.0, 1000.0), Hop(1000.0, 1000.0))
    path = SimResult(True, path_swap=PathSwap(20.0, 0.0, hops))
    assert "SLIPPAGE_TOLERANCE_EXTREME" in rules_of(assess(TX, path, POL)[1])
    sp = math.sqrt(1.0)
    v3 = SimResult(True, swap_v3=V3Swap(20.0, 1.0, sp, math.sqrt(1000.0 * 1000.0)))
    assert "SLIPPAGE_TOLERANCE_EXTREME" in rules_of(assess(TX, v3, POL)[1])


def test_min_fill_fraction_is_configurable():
    tx, sim, _ = SCENARIOS["LIQUIDITY_EXHAUSTED"]()
    assert "LIQUIDITY_EXHAUSTED" not in rules_of(assess(tx, sim, PolicyConfig(min_fill_fraction=0.0))[1])


# --------------------------------------------------------------------------- revert / gas / chain

def test_revert_without_reason_and_eth_rejection_requires_value():
    verdict, f = assess(TX, SimResult(False), POL)
    assert verdict == Verdict.WARN and "unknown" in f[0].message
    no_value = SimResult(False, eth_receive_reverts=True)
    assert "ETH_REJECTED_BY_CONTRACT" not in rules_of(assess(TX, no_value, POL)[1])


def test_gas_thresholds_and_typical_costs():
    ok = SimResult(True, gas_used=60_000, call_kind="erc20_approve")
    assert rules_of(assess(TX, ok, POL)[1]) == set()
    unknown_kind = SimResult(True, gas_used=1_300_000, call_kind="mystery")
    assert "GAS_ABNORMAL" in rules_of(assess(TX, unknown_kind, POL)[1])  # 250k default x 5
    zero = SimResult(True, gas_used=0)
    assert rules_of(assess(TX, zero, POL)[1]) == set()
    loose = PolicyConfig(gas_abnormal_multiple=1000.0, gas_block_absolute=50_000_000)
    huge = SimResult(True, gas_used=20_000_000, call_kind="erc20_approve")
    assert rules_of(assess(TX, huge, loose)[1]) == set()


def test_chain_id_policy_beats_simulator_and_simulator_is_the_fallback():
    sim = SimResult(True, chain_id=10)
    assert rules_of(assess(Tx(U, TOKEN, chain_id=10), sim, PolicyConfig(expected_chain_id=10))[1]) == set()
    assert "CHAIN_ID_MISMATCH" in rules_of(assess(Tx(U, TOKEN, chain_id=1), sim, POL)[1])
    assert rules_of(assess(Tx(U, TOKEN, chain_id=10), sim, POL)[1]) == set()


# --------------------------------------------------------------------------- trace

def test_trace_known_delegatecall_targets_are_quiet_and_unknown_are_not():
    frames = tree(CallFrame("CALL", TOKEN, OTHER, calls=[CallFrame("DELEGATECALL", OTHER, STRANGER)]))
    sim = SimResult(True, call_tree=frames)
    assert "DELEGATECALL_TO_UNKNOWN" in rules_of(assess(TX, sim, POL)[1])
    trusted = PolicyConfig(trusted_implementations={STRANGER})
    assert "DELEGATECALL_TO_UNKNOWN" not in rules_of(assess(TX, sim, trusted)[1])
    booked = PolicyConfig(address_book={STRANGER: "library"})
    assert "DELEGATECALL_TO_UNKNOWN" not in rules_of(assess(TX, sim, booked)[1])
    off = PolicyConfig(flag_unknown_delegatecall=False)
    assert "DELEGATECALL_TO_UNKNOWN" not in rules_of(assess(TX, sim, off)[1])


def test_self_delegatecall_and_creation_flag():
    self_call = SimResult(True, call_tree=tree(CallFrame("DELEGATECALL", OTHER, OTHER)))
    assert rules_of(assess(TX, self_call, POL)[1]) == set()
    create = SimResult(True, call_tree=tree(CallFrame("CREATE", TOKEN, OTHER)))
    assert "CONTRACT_CREATION_IN_TRACE" in rules_of(assess(TX, create, POL)[1])
    assert rules_of(assess(TX, create, PolicyConfig(flag_contract_creation=False))[1]) == set()


def test_denylisted_address_at_trace_root_is_not_double_reported():
    sim = SimResult(True, call_tree=CallFrame("CALL", U, EVIL))
    assert "DENYLISTED_IN_TRACE" not in rules_of(assess(Tx(U, TOKEN), sim, POL)[1])


# --------------------------------------------------------------------------- honeypot / lp

def test_honeypot_thresholds_and_skipped_probe_states():
    assert rules_of(assess(TX, SimResult(True, honeypot=probe(loss_fraction=0.03)), POL)[1]) == set()
    lax = PolicyConfig(honeypot_loss_warn=0.5, honeypot_loss_block=0.9)
    assert rules_of(assess(TX, SimResult(True, honeypot=probe(loss_fraction=0.4)), lax)[1]) == set()
    failed_buy = SimResult(True, honeypot=probe(buy_ok=False, sell_ok=False, loss_fraction=0.0))
    assert rules_of(assess(TX, failed_buy, POL)[1]) == set()  # nothing to conclude from a failed buy


def test_lp_add_and_unknown_pool_totals_are_ignored():
    adds = SimResult(True, lp_events=[LPEvent("add", "p", 99.0, 100.0)])
    assert rules_of(assess(TX, adds, POL)[1]) == set()
    unknown = SimResult(True, lp_events=[LPEvent("remove", "p", 99.0, None)])
    assert rules_of(assess(TX, unknown, POL)[1]) == set()
    custom = PolicyConfig(lp_removal_block_fraction=0.2, lp_removal_warn_fraction=0.1)
    pct = SimResult(True, lp_events=[LPEvent("remove", "p", 25.0, 100.0)])
    assert "LP_REMOVAL_MAJORITY" in rules_of(assess(TX, pct, custom)[1])


# --------------------------------------------------------------------------- bundles

def test_bundle_pull_by_trusted_spender_is_fine_and_order_matters():
    txs = [Tx(U, TOKEN), Tx(U, ROUTER)]
    sims = [SimResult(True, approvals=[appr(ROUTER, UNLIMITED)]), SimResult(True)]
    assert not assess_bundle(txs, sims, POL).bundle_findings
    unknown = [SimResult(True, approvals=[appr(OTHER, UNLIMITED)]), SimResult(True)]
    reversed_order = assess_bundle([Tx(U, OTHER), Tx(U, TOKEN)], list(reversed(unknown)), POL)
    assert "BUNDLE_APPROVE_THEN_PULL" not in {f.rule for f in reversed_order.bundle_findings}


def test_bundle_transfer_from_by_the_approved_spender_is_detected():
    pull = Transfer(TOKEN, U, STRANGER, 50, 100, operator=OTHER)
    txs = [Tx(U, TOKEN), Tx(OTHER, TOKEN)]
    sims = [SimResult(True, approvals=[appr(OTHER, 100)]), SimResult(True, transfers=[pull])]
    review = assess_bundle(txs, sims, POL)
    f = [x for x in review.bundle_findings if x.rule == "BUNDLE_APPROVE_THEN_PULL"]
    assert f and f[0].data == {"spender": OTHER, "grant_index": 0, "pull_index": 1}
    assert review.verdict == Verdict.BLOCK


def test_bundle_pull_visible_only_in_the_call_tree_and_permit_grants():
    txs = [Tx(U, TOKEN), Tx(U, STRANGER)]
    sims = [SimResult(True, permits=[permit(OTHER, 5, NOW)]),
            SimResult(True, call_tree=tree(CallFrame("CALL", OTHER, TOKEN)))]
    assert "BUNDLE_APPROVE_THEN_PULL" in {f.rule for f in assess_bundle(txs, sims, POL).bundle_findings}


def test_bundle_cumulative_drain_is_not_reported_when_one_transfer_already_drains():
    sims = [SimResult(True, transfers=[xfer(OTHER, 95, 100)]),
            SimResult(True, transfers=[xfer(STRANGER, 3, 100)])]
    review = assess_bundle([Tx(U, TOKEN)] * 2, sims, POL)
    assert "BUNDLE_CUMULATIVE_DRAIN" not in {f.rule for f in review.bundle_findings}
    assert review.per_tx[0].verdict == Verdict.WARN


def test_bundle_input_validation_and_empty_bundle():
    with pytest.raises(ValueError):
        assess_bundle([Tx(U, TOKEN)], [], POL)
    empty = assess_bundle([], [], POL)
    assert empty.verdict == Verdict.ALLOW and empty.to_dict()["per_tx"] == []


def test_bundle_verdict_is_worst_of_members_and_bundle_rules():
    txs = [Tx(U, TOKEN), Tx(U, TOKEN)]
    sims = [SimResult(True), SimResult(False, revert_reason="x")]
    review = assess_bundle(txs, sims, POL)
    assert review.verdict == Verdict.WARN and review.per_tx[0].verdict == Verdict.ALLOW
    assert review.to_dict()["per_tx"][1]["findings"][0]["rule"] == "REVERT"


# --------------------------------------------------------------------------- policy object

def test_policy_dict_round_trip_and_unknown_keys():
    pol = PolicyConfig(trusted_spenders={ROUTER.upper().replace("0X", "0x")}, expected_chain_id=5,
                       address_book={OTHER.upper().replace("0X", "0x"): "x"},
                       disabled_rules={"revert"}, sandwich_warn_bps=12.5)
    again = PolicyConfig.from_dict(pol.to_dict())
    assert again.to_dict() == pol.to_dict()
    assert again.trusted_spenders == {ROUTER} and again.disabled_rules == {"REVERT"}
    assert again.address_book == {OTHER: "x"}
    with pytest.raises(ValueError, match="unknown policy keys"):
        PolicyConfig.from_dict({"sandwich_warn": 1})


def test_known_addresses_include_the_sender():
    pol = PolicyConfig(trusted_recipients={FRIEND}, address_book={OTHER: "x"})
    assert pol.known_addresses(TX) == {FRIEND, OTHER, U}
    assert pol.known_addresses() == {FRIEND, OTHER}
