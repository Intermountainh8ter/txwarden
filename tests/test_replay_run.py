"""The replay runner end to end against the synthetic archive node (tests/replay_world.py)."""
import json
from pathlib import Path

import pytest

import txwarden.replay as replay_module
from txwarden.redact import Redactor
from txwarden.replay import (
    ReplayConfig,
    Replayer,
    ReplayError,
    ResultsWriter,
    endpoint_from_env,
    format_estimate,
    mock_stamped,
    parse_cases,
    read_results,
)
from txwarden.risk import PolicyConfig
from txwarden.simulator import RpcError, SimulatorOptions

from . import replay_world as rw
from .fake_history import FakeClock, fake_hash
from .replay_world import build_world


def make(world, tmp_path, raw=None, policy=None, clock=None, cache=True, **cfg_kw) -> Replayer:
    cases = parse_cases(world.csv(), "cases.csv")
    cfg = ReplayConfig(out_path=tmp_path / "results.jsonl",
                       cache_dir=tmp_path / "cache" if cache else None, rps=10_000, **cfg_kw)
    return Replayer(cases, raw or world.chain.rpc, cfg, policy or PolicyConfig(),
                    SimulatorOptions(), Redactor(), clock=clock or FakeClock())


def run(world, tmp_path, **kw):
    r = make(world, tmp_path, **kw)
    out = r.run()
    return out, (read_results(out.out_path) if out.out_path and out.out_path.exists() else None), r


def rec_for(results, n):
    return results.cases[fake_hash(n)]


# --------------------------------------------------------------------------- outcomes

def test_every_case_gets_exactly_the_outcome_its_transaction_deserves(tmp_path):
    out, results, _ = run(build_world(), tmp_path)
    assert out.stopped == "completed" and out.exit_code == 0 and len(results.cases) == 12
    expect = {
        rw.LOOSE_SANDWICHED: ("analysed", "BLOCK"), rw.MODERATE_SANDWICHED: ("analysed", "WARN"),
        rw.TIGHT_SANDWICHED: ("analysed", "ALLOW"), rw.TIGHT_ORDINARY: ("analysed", "ALLOW"),
        rw.TIGHT_ORDINARY_2: ("analysed", "ALLOW"), rw.LOOSE_ORDINARY: ("analysed", "BLOCK"),
        rw.NOT_A_SWAP: ("unsupported", None), rw.NOT_FOUND: ("error", None),
        rw.NO_POOL: ("unsupported", None), rw.CREATION: ("unsupported", None),
        rw.PENDING: ("error", None), rw.REVERTS: ("unsupported", None),
    }
    for n, (status, verdict) in expect.items():
        rec = rec_for(results, n)
        assert (rec["status"], rec["verdict"]) == (status, verdict), (n, rec)
    assert out.counts == {"analysed": 6, "unsupported": 4, "error": 2}


@pytest.mark.parametrize("n,code", [
    (rw.NOT_A_SWAP, "not_a_swap"), (rw.NOT_FOUND, "tx_not_found"),
    (rw.NO_POOL, "pool_state_unavailable"), (rw.CREATION, "contract_creation"),
    (rw.PENDING, "pending"), (rw.REVERTS, "reverts_at_pin"),
])
def test_cases_that_cannot_be_analysed_say_why_and_carry_no_verdict(n, code, tmp_path):
    _, results, _ = run(build_world(), tmp_path)
    rec = rec_for(results, n)
    assert rec["reason_code"] == code and rec["reason"] and rec["verdict"] is None
    assert "rules" not in rec and rec["status"] in ("unsupported", "error")


def test_reason_texts_are_specific(tmp_path):
    _, results, _ = run(build_world(), tmp_path)
    assert "erc20_approve" in rec_for(results, rw.NOT_A_SWAP)["reason"]
    assert "block 399" in rec_for(results, rw.REVERTS)["reason"]
    assert "EXPIRED" in rec_for(results, rw.REVERTS)["reason"]
    assert "swap_state" in rec_for(results, rw.NO_POOL)["reason"]


def test_analysed_cases_list_every_rule_and_those_that_decide_the_verdict(tmp_path):
    _, results, _ = run(build_world(), tmp_path)
    loose = rec_for(results, rw.LOOSE_SANDWICHED)
    assert {"SLIPPAGE_TOLERANCE_EXTREME", "SANDWICH_EXPOSURE_SEVERE"} <= set(loose["alerting_rules"])
    assert "CHECKS_SKIPPED" in loose["rules"] and "CHECKS_SKIPPED" not in loose["alerting_rules"]
    assert rec_for(results, rw.TIGHT_ORDINARY)["alerting_rules"] == []
    assert "call_trace" in loose["degraded"]
    assert loose["call_kind"] == "v2_swap_exact_tokens_for_tokens"


def test_label_and_source_are_carried_through(tmp_path):
    _, results, _ = run(build_world(), tmp_path)
    rec = rec_for(results, rw.LOOSE_SANDWICHED)
    assert rec["label"] == "sandwiched" and rec["source"] == "EXAMPLE"
    assert rec_for(results, rw.TIGHT_ORDINARY)["label"] == "ordinary"


def test_each_state_request_is_pinned_to_the_block_before_the_victims(tmp_path):
    w = build_world()
    _, results, _ = run(w, tmp_path)
    assert rec_for(results, rw.LOOSE_SANDWICHED)["block"] == 200
    assert rec_for(results, rw.LOOSE_SANDWICHED)["pinned_block"] == 199
    assert rec_for(results, rw.REVERTS)["pinned_block"] == 399
    state_blocks = {b for m in ("eth_call", "eth_getCode", "eth_getBalance",
                                "eth_getTransactionCount", "eth_estimateGas")
                    for b in w.chain.blocks_requested(m)}
    assert state_blocks == {hex(199), hex(399)}  # never "latest", never the victim's own block
    assert "latest" not in {b for b in w.chain.blocks_requested("eth_getBlockByNumber")}


def test_pending_and_unknown_transactions_have_no_pinned_state_requests(tmp_path):
    w = build_world()
    _, results, _ = run(w, tmp_path)
    assert "block" not in rec_for(results, rw.NOT_FOUND)
    assert "block" not in rec_for(results, rw.PENDING)


def test_the_pool_state_seen_is_the_state_before_the_victims_block(tmp_path):
    """The fake node changes the pool at block 350; a victim in block 400 is pinned at 399."""
    w = build_world()
    _, results, _ = run(w, tmp_path)
    assert rec_for(results, rw.REVERTS)["reason_code"] == "reverts_at_pin"  # state from block 350


# --------------------------------------------------------------------------- results file

def test_results_file_has_one_header_one_line_per_case_and_a_run_summary(tmp_path):
    w = build_world()
    out, results, _ = run(w, tmp_path)
    lines = [json.loads(x) for x in out.out_path.read_text().splitlines()]
    assert [x["type"] for x in lines] == ["header"] + ["case"] * 12 + ["run"]
    assert [x["tx_hash"] for x in lines[1:13]] == [h for h, _, _ in w.rows]
    run_line = lines[-1]
    assert run_line["stopped"] == "completed" and run_line["cases"] == 12
    assert run_line["rpc_calls"] == out.calls == len(w.chain.log)
    assert results.problems == []


def test_header_describes_the_run_without_any_endpoint_detail(tmp_path):
    w = build_world()
    _out, results, _ = run(w, tmp_path)
    h = results.header
    assert h["format"] == "txwarden-replay/1" and h["mock"] is True
    assert h["chain_id"] == 1 and h["head_block"] == rw.HEAD
    assert h["client_version"] == "txwarden-fakechain/1.0" and h["endpoint"] == "rpc endpoint"
    assert h["case_counts"] == {"sandwiched": 6, "ordinary": 6} and h["cases_file"] == "cases.csv"
    assert len(h["cases_sha256"]) == 64 and h["costs"]["debug_trace"] == 2.0
    assert h["txwarden_version"] and h["created_utc"].startswith("2026")


def test_per_case_call_accounting_adds_up(tmp_path):
    w = build_world()
    out, results, _ = run(w, tmp_path)
    total = sum(r["rpc_calls"] for r in results.cases.values())
    assert total + out.preflight_calls == out.calls == len(w.chain.log)
    for rec in results.cases.values():
        assert sum(rec["methods"].values()) == rec["rpc_calls"]
        assert rec["units"] >= rec["rpc_calls"] and rec["elapsed_s"] >= 0
    assert rec_for(results, rw.NOT_FOUND)["methods"] == {"eth_getTransactionByHash": 1}


def test_archive_reads_are_priced_higher_than_plain_ones(tmp_path):
    _, results, _ = run(build_world(), tmp_path)
    rec = rec_for(results, rw.LOOSE_SANDWICHED)
    assert rec["units"] > rec["rpc_calls"]
    assert rec_for(results, rw.CREATION)["units"] == 1  # one tx lookup, no state read


def test_elapsed_time_comes_from_the_injected_clock(tmp_path):
    clock = FakeClock()
    w = build_world()

    def slow(method, params):
        clock.t += 0.25
        return w.chain.rpc(method, params)

    _, results, _ = run(w, tmp_path, raw=slow, clock=clock)
    rec = rec_for(results, rw.CREATION)
    assert rec["elapsed_s"] == pytest.approx(0.25, abs=0.01)


def test_requests_are_rate_limited(tmp_path):
    clock = FakeClock()
    w = build_world()
    cases = parse_cases(w.csv(), "cases.csv")
    cfg = ReplayConfig(out_path=tmp_path / "r.jsonl", cache_dir=None, rps=10)
    r = Replayer(cases, w.chain.rpc, cfg, PolicyConfig(), SimulatorOptions(), Redactor(),
                 clock=clock)
    start = clock.t
    out = r.run()
    assert clock.t - start >= (out.calls - 1) / 10 - 1e-6


# --------------------------------------------------------------------------- MOCK stamping

@pytest.mark.parametrize("given,expected", [
    ("results.jsonl", "results.MOCK.jsonl"), ("dir/run.v2.jsonl", "dir/run.v2.MOCK.jsonl"),
    ("results", "results.MOCK"), ("x.MOCK.jsonl", "x.MOCK.jsonl"), ("MOCK_run.jsonl", "MOCK_run.jsonl"),
])
def test_mock_filename_stamp(given, expected):
    assert mock_stamped(given) == Path(expected)


def test_results_from_the_fake_node_are_stamped_everywhere(tmp_path):
    out, results, _ = run(build_world(), tmp_path)
    assert out.mock and results.mock and results.header["mock"] is True
    assert out.out_path.name == "results.MOCK.jsonl"
    assert not (tmp_path / "results.jsonl").exists()


def test_a_node_that_is_not_the_fake_is_not_stamped_unless_asked(tmp_path):
    w = build_world()
    w.chain.client_version = "Geth/v1.14.0-stable/linux-amd64/go1.22"
    out, results, _ = run(w, tmp_path)
    assert not out.mock and out.out_path.name == "results.jsonl"
    assert results.header["mock"] is False and results.header["client_version"].startswith("Geth")
    w2 = build_world()
    w2.chain.client_version = "Geth/v1.14.0"
    out2, results2, _ = run(w2, tmp_path / "forced", mock=True)
    assert out2.mock and out2.out_path.name == "results.MOCK.jsonl" and results2.mock


def test_a_node_without_web3_client_version_still_works(tmp_path):
    w = build_world()
    real = w.chain.rpc

    def no_version(method, params):
        if method == "web3_clientVersion":
            raise RpcError("Method not found", -32601)
        return real(method, params)

    out, results, _ = run(w, tmp_path, raw=no_version)
    assert results.header["client_version"] is None and not out.mock
    assert len(results.cases) == 12


def test_resume_refuses_to_mix_mock_and_real_results(tmp_path):
    w = build_world()
    w.chain.client_version = "Geth/v1.14.0"
    run(w, tmp_path, limit=2)
    r = make(w, tmp_path, mock=True)
    stamped = tmp_path / "results.MOCK.jsonl"
    stamped.write_text((tmp_path / "results.jsonl").read_text().replace('"mock":false',
                                                                        '"mock":false'))
    with pytest.raises(ReplayError, match="was written in non-MOCK mode"):
        r.run()


def test_resume_refuses_a_file_that_is_not_a_results_file(tmp_path):
    (tmp_path / "results.MOCK.jsonl").write_text('{"hello": 1}\n')
    with pytest.raises(ReplayError, match="not a replay results file"):
        make(build_world(), tmp_path).run()


# --------------------------------------------------------------------------- resume and limit

def test_limit_processes_that_many_cases_then_resume_does_the_rest(tmp_path):
    w = build_world()
    first, r1, _ = run(w, tmp_path, limit=5)
    assert first.stopped == "limit" and first.processed == 5 and first.exit_code == 0
    assert len(r1.cases) == 5
    second, r2, _ = run(w, tmp_path)
    assert second.stopped == "completed" and second.skipped == 5 and second.processed == 7
    assert len(r2.cases) == 12
    lines = [json.loads(x) for x in second.out_path.read_text().splitlines()]
    assert sum(x["type"] == "header" for x in lines) == 1
    hashes = [x["tx_hash"] for x in lines if x["type"] == "case"]
    assert hashes == [h for h, _, _ in w.rows] and len(set(hashes)) == 12
    assert [x["stopped"] for x in lines if x["type"] == "run"] == ["limit", "completed"]


def test_a_finished_file_is_a_no_op_on_rerun(tmp_path):
    w = build_world()
    run(w, tmp_path)
    before = (tmp_path / "results.MOCK.jsonl").read_text()
    out, _, _ = run(w, tmp_path)
    assert out.processed == 0 and out.skipped == 12 and out.stopped == "completed"
    assert out.calls == out.preflight_calls == 3
    added = (tmp_path / "results.MOCK.jsonl").read_text()[len(before):]
    assert [json.loads(x)["type"] for x in added.splitlines()] == ["run"]


def test_limit_zero_analyses_nothing(tmp_path):
    out, results, _ = run(build_world(), tmp_path, limit=0)
    assert out.processed == 0 and out.stopped == "limit" and results.cases == {}


def test_limit_larger_than_the_file_is_just_completed(tmp_path):
    out, _, _ = run(build_world(), tmp_path, limit=500)
    assert out.stopped == "completed" and out.processed == 12


def test_a_torn_last_line_is_ignored_and_rewritten_on_resume(tmp_path):
    w = build_world()
    run(w, tmp_path, limit=4)
    path = tmp_path / "results.MOCK.jsonl"
    text = path.read_text().rstrip("\n").rsplit("\n", 1)
    path.write_text(text[0] + "\n" + text[1][:30])  # cut the run summary mid-line, no newline
    results = read_results(path)
    assert results.problems and len(results.cases) == 4
    out, after, _ = run(w, tmp_path)
    assert out.stopped == "completed" and len(after.cases) == 12


def test_retry_errors_reruns_only_the_cases_that_errored(tmp_path):
    w = build_world()
    real, broken = w.chain.rpc, {"on": True}

    def flaky(method, params):
        if broken["on"] and method == "eth_getTransactionByHash" and params[0] == fake_hash(4):
            raise RpcError("HTTP 503 from https://node.example", code=503, transport=True)
        return real(method, params)

    _out1, r1, _ = run(w, tmp_path, raw=flaky, max_retries=0)
    assert rec_for(r1, rw.TIGHT_ORDINARY)["status"] == "error"
    assert rec_for(r1, rw.TIGHT_ORDINARY)["reason_code"] == "rpc_error"
    broken["on"] = False
    out2, _r2, _ = run(w, tmp_path, raw=flaky)
    assert out2.processed == 0  # the error is final unless asked
    out3, r3, _ = run(w, tmp_path, raw=flaky, retry_errors=True)
    assert out3.processed == 3  # case 4 plus the two cases that were never going to be found
    assert rec_for(r3, rw.TIGHT_ORDINARY)["status"] == "analysed"
    lines = [json.loads(x) for x in out3.out_path.read_text().splitlines()]
    assert sum(x.get("tx_hash") == fake_hash(4) for x in lines) == 2  # history is kept


# --------------------------------------------------------------------------- budget

def test_call_budget_stops_cleanly_before_it_is_exceeded(tmp_path):
    w = build_world()
    out, results, _ = run(w, tmp_path, budget_calls=25)
    assert out.stopped == "budget" and out.exit_code == 4
    assert len(w.chain.log) <= 25 and out.calls <= 25
    assert 0 < len(results.cases) < 12
    assert "Raise the budget" in out.message and "cases left" in out.message
    lines = [json.loads(x) for x in out.out_path.read_text().splitlines()]
    assert lines[-1]["type"] == "run" and lines[-1]["stopped"] == "budget"


def test_a_stopped_run_resumes_and_the_cache_pays_for_the_half_done_case(tmp_path):
    w = build_world()
    first, _, _ = run(w, tmp_path, budget_calls=25)
    cold = build_world()
    cold_out, _, _ = run(cold, tmp_path / "cold")
    second, results, _ = run(w, tmp_path)
    assert second.stopped == "completed" and len(results.cases) == 12
    assert first.calls + second.calls < cold_out.calls + 3 + 3  # no case was paid for twice
    assert second.cache_hits >= 1


def test_unit_budget_is_enforced_separately(tmp_path):
    w = build_world()
    r = make(w, tmp_path, budget_units=30)
    out = r.run()
    assert out.stopped == "budget" and out.units <= 30 and "unit budget" in out.message


def test_budget_too_small_for_the_endpoint_check_stops_before_any_case(tmp_path):
    out, results, _ = run(build_world(), tmp_path, budget_calls=2)
    assert out.stopped == "budget" and results is None and out.processed == 0
    assert "before the endpoint check" in out.message


def test_budget_exceeded_is_never_recorded_as_a_case_outcome(tmp_path):
    for budget in range(3, 40, 4):
        w = build_world()
        _, results, _ = run(w, tmp_path / f"b{budget}", budget_calls=budget)
        for rec in (results.cases.values() if results else []):
            assert rec["reason_code"] != "budget" if rec.get("reason_code") else True
            assert rec["status"] != "error" or rec["reason_code"] in ("tx_not_found", "pending")


# --------------------------------------------------------------------------- cache

def test_a_second_run_over_the_same_cases_costs_no_state_requests(tmp_path):
    w = build_world()
    first, r1, _ = run(w, tmp_path)
    again = tmp_path / "again"
    second_cfg = make(w, tmp_path)
    second_cfg.cfg.out_path = again / "results.jsonl"
    out = second_cfg.run()
    r2 = read_results(out.out_path)
    # only the preflight and the two lookups that are deliberately not cached (unknown and pending)
    assert out.calls == out.preflight_calls + 2
    assert out.cache_hits > 0
    for n in range(1, 13):
        assert (rec_for(r1, n)["status"], rec_for(r1, n).get("verdict")) == (
            rec_for(r2, n)["status"], rec_for(r2, n).get("verdict"))
    assert first.calls > out.calls * 3


def test_cache_disabled_means_every_run_pays(tmp_path):
    w = build_world()
    first, _, _ = run(w, tmp_path / "a", cache=False)
    second, _, _ = run(w, tmp_path / "b", cache=False)
    assert first.calls == second.calls and first.cache_hits == 0


def test_cache_is_namespaced_by_chain_and_holds_no_endpoint(tmp_path):
    run(build_world(), tmp_path)
    files = list((tmp_path / "cache").rglob("*.json"))
    assert files and {f.relative_to(tmp_path / "cache").parts[0] for f in files} == {"chain-1"}
    for f in files:
        assert set(json.loads(f.read_text())) <= {"v", "method", "params", "pin", "result",
                                                  "error"}


def test_shared_state_between_cases_in_the_same_block_is_fetched_once(tmp_path):
    w = build_world()
    run(w, tmp_path)
    codes = [p for m, p in w.chain.log if m == "eth_getCode" and p[0] == rw.ROUTER]
    assert len({json.dumps(p) for p in codes}) == len(codes)  # no duplicate requests reached the node


# --------------------------------------------------------------------------- estimate

def test_estimate_measures_three_cases_and_writes_nothing(tmp_path):
    w = build_world()
    out, results, r = run(w, tmp_path, estimate=True)
    assert out.stopped == "estimate" and out.exit_code == 0 and results is None
    assert not list(tmp_path.glob("*.jsonl"))
    assert [row.tx_hash for row in out.estimate_rows] == [fake_hash(i) for i in (1, 2, 3)]
    assert all(row.requests > 0 and row.units >= row.requests for row in out.estimate_rows)
    text = format_estimate(out, r.cfg.costs)
    assert "first 3 case(s)" in text and "projected for all 12 cases" in text
    assert "verify them in the provider console" in text and "units" in text


def test_estimate_is_the_same_on_a_warm_cache(tmp_path):
    w = build_world()
    cold, _, _ = run(w, tmp_path, estimate=True)
    warm, _, _ = run(w, tmp_path, estimate=True)
    assert [(r.requests, r.units) for r in warm.estimate_rows] == [
        (r.requests, r.units) for r in cold.estimate_rows]
    assert warm.calls == warm.preflight_calls  # but nothing was billed the second time


def test_estimate_with_fewer_cases_than_the_sample(tmp_path):
    w = build_world()
    cases = parse_cases(w.csv(), "c.csv")
    cases.cases[:] = cases.cases[:1]
    cfg = ReplayConfig(out_path=tmp_path / "r.jsonl", cache_dir=None, estimate=True, rps=1000)
    out = Replayer(cases, w.chain.rpc, cfg, PolicyConfig(), SimulatorOptions(), Redactor(),
                   clock=FakeClock()).run()
    assert len(out.estimate_rows) == 1


def test_estimate_respects_the_budget(tmp_path):
    out, _, _ = run(build_world(), tmp_path, estimate=True, budget_calls=8)
    assert out.stopped == "budget" and out.exit_code == 4


def test_estimate_text_with_no_rows():
    from txwarden.replay import ReplayOutcome
    from txwarden.replay_rpc import CostModel

    out = ReplayOutcome("budget", None, False, message="budget reached")
    text = format_estimate(out, CostModel())
    assert "first 0 case(s)" in text and "budget reached" in text and "projected" not in text


# --------------------------------------------------------------------------- failure handling

def test_rate_limit_responses_are_retried_with_backoff_and_the_case_succeeds(tmp_path):
    w, clock = build_world(), FakeClock()
    real, seen = w.chain.rpc, {"n": 0}

    def limited(method, params):
        if method == "eth_getTransactionByHash" and params[0] == fake_hash(4) and seen["n"] < 2:
            seen["n"] += 1
            raise RpcError("HTTP 429 from https://node.example", code=429, transport=True)
        return real(method, params)

    r = make(w, tmp_path, raw=limited, clock=clock)
    out = r.run()
    results = read_results(out.out_path)
    assert rec_for(results, rw.TIGHT_ORDINARY)["status"] == "analysed"
    assert 1 in clock.sleeps and 2 in clock.sleeps and r.retrying.retries == 2
    assert rec_for(results, rw.TIGHT_ORDINARY)["elapsed_s"] >= 3
    assert rec_for(results, rw.TIGHT_ORDINARY)["rpc_calls"] >= 3  # retries are counted


def test_persistent_rate_limiting_is_an_error_not_a_verdict_and_the_run_continues(tmp_path):
    w = build_world()
    real = w.chain.rpc

    def limited(method, params):
        if method == "eth_getTransactionByHash" and params[0] == fake_hash(1):
            raise RpcError("HTTP 429 from https://node.example", code=429, transport=True)
        return real(method, params)

    out, results, _ = run(w, tmp_path, raw=limited, max_retries=2)
    rec = rec_for(results, rw.LOOSE_SANDWICHED)
    assert rec["status"] == "error" and rec["reason_code"] == "rate_limited"
    assert "2 retries" in rec["reason"] and rec["verdict"] is None
    assert rec["rpc_calls"] == 3  # the first try and two retries, all counted
    assert rec_for(results, rw.MODERATE_SANDWICHED)["status"] == "analysed"
    assert out.stopped == "completed"


def test_a_failure_in_an_optional_probe_still_invalidates_the_case(tmp_path):
    """If the node fails on an account probe the engine would shrug it off; the replay must not."""
    w = build_world()
    real = w.chain.rpc

    def flaky(method, params):
        if method == "eth_getCode" and params[0] == rw.ROUTER:
            raise RpcError("HTTP 502 from https://node.example", code=502, transport=True)
        return real(method, params)

    _out, results, _ = run(w, tmp_path, raw=flaky, max_retries=0, max_consecutive_errors=0)
    swaps = [rec_for(results, n) for n in (1, 2, 3, 4, 5, 6)]
    assert {r["status"] for r in swaps} == {"error"}
    assert {r["reason_code"] for r in swaps} == {"rpc_error"}


def test_pruned_state_is_reported_as_missing_archive_access(tmp_path):
    w = build_world()
    w.chain.prune_before = 500  # nothing older than block 500 is available
    _out, results, _ = run(w, tmp_path)
    rec = rec_for(results, rw.LOOSE_SANDWICHED)
    assert rec["status"] == "error" and rec["reason_code"] == "archive_state_unavailable"
    assert "archive plan" in rec["reason"] and "missing trie node" in rec["reason"]
    assert rec_for(results, rw.NOT_A_SWAP)["status"] == "unsupported"  # needed no state


def test_repeated_rpc_failures_stop_the_run_instead_of_burning_the_budget(tmp_path):
    w = build_world()
    w.chain.prune_before = 500
    out, results, _ = run(w, tmp_path, max_consecutive_errors=3)
    assert out.stopped == "errors" and out.exit_code == 4 and len(results.cases) == 3
    assert "3 consecutive RPC failures" in out.message and "--retry-errors" in out.message


def test_consecutive_error_stop_can_be_disabled(tmp_path):
    w = build_world()
    w.chain.prune_before = 500
    out, results, _ = run(w, tmp_path, max_consecutive_errors=0)
    assert out.stopped == "completed" and len(results.cases) == 12


def test_a_case_that_needs_no_state_resets_the_failure_streak(tmp_path):
    """With old state pruned, cases 1-6 fail in a row, 7 (an approval) needs no state, 9 and 12
    fail alone. Six in a row stops the run; seven does not."""
    stops = build_world()
    stops.chain.prune_before = 500
    out, results, _ = run(stops, tmp_path / "six", max_consecutive_errors=6)
    assert out.stopped == "errors" and len(results.cases) == 6
    passes = build_world()
    passes.chain.prune_before = 500
    out, results, _ = run(passes, tmp_path / "seven", max_consecutive_errors=7)
    assert out.stopped == "completed" and len(results.cases) == 12


def test_unsupported_optional_methods_degrade_and_are_asked_for_only_once(tmp_path):
    w = build_world()
    for state in w.chain.states.values():
        state.supports_trace = False
        state.supports_simulate = False
    out, results, _ = run(w, tmp_path)
    assert len(results.cases) == 12 and out.counts["analysed"] == 6
    assert len([m for m, _ in w.chain.log if m == "debug_traceCall"]) == 1
    assert len([m for m, _ in w.chain.log if m == "eth_simulateV1"]) == 1
    assert "call_trace" in rec_for(results, rw.LOOSE_SANDWICHED)["degraded"]


def test_an_unexpected_exception_in_one_case_is_recorded_and_the_run_goes_on(tmp_path, monkeypatch):
    real = replay_module.AnvilSimulator

    class Exploding(real):
        def simulate(self, tx):
            if f"{20 * rw.E:064x}" in tx.data:  # the 20 WETH swap, case 1
                raise ZeroDivisionError("kaboom")
            return super().simulate(tx)

    monkeypatch.setattr(replay_module, "AnvilSimulator", Exploding)
    out, results, _ = run(build_world(), tmp_path)
    errors = [r for r in results.cases.values() if r.get("reason_code") == "internal_error"]
    assert [r["tx_hash"] for r in errors] == [fake_hash(1)]
    assert "ZeroDivisionError: kaboom" in errors[0]["reason"]
    assert out.stopped == "completed" and len(results.cases) == 12


def test_budget_exceeded_is_not_converted_into_an_internal_error(tmp_path):
    out, results, _ = run(build_world(), tmp_path, budget_calls=10)
    assert out.stopped == "budget"
    assert all(r.get("reason_code") != "internal_error" for r in (results.cases if results else {}).values())


def test_engine_errors_are_errors_not_verdicts(tmp_path, monkeypatch):
    from txwarden.models import Finding, Severity, Verdict

    def broken(tx, sim, policy):
        return Verdict.BLOCK, [Finding("ENGINE_ERROR", Severity.CRITICAL, "boom")]

    monkeypatch.setattr(replay_module, "assess", broken)
    _, results, _ = run(build_world(), tmp_path)
    assert rec_for(results, rw.LOOSE_SANDWICHED)["reason_code"] == "engine_error"
    assert rec_for(results, rw.LOOSE_SANDWICHED)["verdict"] is None


def test_the_policy_in_force_is_the_one_passed_in(tmp_path):
    lenient = PolicyConfig(disabled_rules={"SLIPPAGE_TOLERANCE_EXTREME", "SANDWICH_EXPOSURE_SEVERE",
                                           "SANDWICH_EXPOSURE", "SLIPPAGE_TOLERANCE_LOOSE"})
    _, results, _ = run(build_world(), tmp_path, policy=lenient)
    assert rec_for(results, rw.LOOSE_SANDWICHED)["verdict"] == "ALLOW"
    assert rec_for(results, rw.MODERATE_SANDWICHED)["verdict"] == "ALLOW"


def test_a_transaction_on_another_chain_id_is_judged_by_the_engine(tmp_path):
    w = build_world()
    w.chain.txs[fake_hash(4)]["chainId"] = hex(5)
    _, results, _ = run(w, tmp_path)
    rec = rec_for(results, rw.TIGHT_ORDINARY)
    assert rec["status"] == "analysed" and "CHAIN_ID_MISMATCH" in rec["alerting_rules"]
    assert rec["verdict"] == "BLOCK"


def test_malformed_transaction_objects_are_errors(tmp_path):
    w = build_world()
    w.chain.txs[fake_hash(4)]["from"] = "not-an-address"
    w.chain.txs[fake_hash(5)].pop("from")
    _, results, _ = run(w, tmp_path)
    for n in (4, 5):
        assert rec_for(results, n)["reason_code"] == "bad_response"


def test_non_object_transaction_response(tmp_path):
    w = build_world()
    real = w.chain.rpc

    def odd(method, params):
        if method == "eth_getTransactionByHash" and params[0] == fake_hash(4):
            return "0x1234"
        return real(method, params)

    _, results, _ = run(w, tmp_path, raw=odd)
    assert rec_for(results, rw.TIGHT_ORDINARY)["reason_code"] == "bad_response"


def test_block_zero_cannot_be_pinned_before(tmp_path):
    w = build_world()
    w.chain.txs[fake_hash(4)]["blockNumber"] = "0x0"
    _, results, _ = run(w, tmp_path)
    assert rec_for(results, rw.TIGHT_ORDINARY)["status"] == "error"


def test_an_endpoint_that_does_not_answer_chain_id_is_refused(tmp_path):
    def dead(method, params):
        raise RpcError("cannot reach https://node.example: refused", transport=True)

    with pytest.raises(ReplayError, match="cannot use the endpoint"):
        make(build_world(), tmp_path, raw=dead).run()

    with pytest.raises(ReplayError, match="did not answer eth_chainId"):
        make(build_world(), tmp_path, raw=lambda m, p: None).run()


def test_keyboard_interrupt_stops_cleanly(tmp_path):
    w = build_world()
    real, n = w.chain.rpc, {"cases": 0}

    def interrupting(method, params):
        if method == "eth_getTransactionByHash":
            n["cases"] += 1
            if n["cases"] == 3:
                raise KeyboardInterrupt
        return real(method, params)

    out, results, _ = run(w, tmp_path, raw=interrupting)
    assert out.stopped == "interrupted" and out.exit_code == 4 and len(results.cases) == 2
    assert "rerun the same command" in out.message


def test_a_crash_is_recorded_as_aborted_in_the_run_summary(tmp_path, monkeypatch):
    def explode(self, todo, writer, out):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(Replayer, "_loop", explode)
    r = make(build_world(), tmp_path)
    with pytest.raises(RuntimeError, match="disk on fire"):
        r.run()
    last = json.loads((tmp_path / "results.MOCK.jsonl").read_text().splitlines()[-1])
    assert last["type"] == "run" and last["stopped"] == "aborted"


# --------------------------------------------------------------------------- results IO

def test_read_results_keeps_the_last_record_per_hash_and_reports_oddities(tmp_path):
    p = tmp_path / "r.jsonl"
    lines = [
        {"type": "header", "format": "x", "mock": False},
        {"type": "case", "tx_hash": "0xa", "status": "error"},
        {"type": "case", "tx_hash": "0xa", "status": "analysed", "verdict": "ALLOW"},
        {"type": "mystery", "x": 1}, {"type": "header", "format": "again"},
        {"type": "run", "stopped": "completed"}, [1, 2], {"type": "case", "tx_hash": 5},
    ]
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n\nnot json\n")
    r = read_results(p)
    assert r.cases["0xa"]["status"] == "analysed" and len(r.cases) == 1
    assert r.header["format"] == "x" and len(r.runs) == 1 and not r.mock
    assert any("second header" in x for x in r.problems) and any("not valid JSON" in x
                                                                  for x in r.problems)


def test_results_writer_appends_and_repairs_a_missing_final_newline(tmp_path):
    p = tmp_path / "out" / "r.jsonl"
    w = ResultsWriter(p)
    w.write({"a": 1})
    w.close()
    with p.open("a") as f:
        f.write('{"torn')
    w2 = ResultsWriter(p)
    w2.write({"b": 2})
    w2.close()
    assert p.read_text().splitlines() == ['{"a":1}', '{"torn', '{"b":2}']


# --------------------------------------------------------------------------- endpoint variable

def test_endpoint_from_env_returns_the_url_only_for_a_usable_value():
    url = "https://node.example/v1/sk_test_1234567890"
    assert endpoint_from_env("X_RPC", {"X_RPC": f"  {url}\n"}) == url
    assert endpoint_from_env("X_RPC", {"X_RPC": "http://127.0.0.1:8545"})


@pytest.mark.parametrize("env", [{}, {"X_RPC": ""}, {"X_RPC": "   "}])
def test_unset_or_empty_variable_is_explained(env):
    with pytest.raises(ReplayError, match="X_RPC is not set or is empty"):
        endpoint_from_env("X_RPC", env)


@pytest.mark.parametrize("value", ["no-scheme-sk_test_SECRET", "ws://node.example/sk_test_SECRET",
                                   "ftp://node.example/sk_test_SECRET",
                                   "https://node.example/sk test SECRET", "https:///sk_test_SECRET",
                                   "https://node.example/\x00sk_test_SECRET", "sk_test_SECRET"])
def test_unusable_values_are_refused_without_echoing_them(value):
    with pytest.raises(ReplayError) as e:
        endpoint_from_env("X_RPC", {"X_RPC": value})
    assert "SECRET" not in str(e.value) and "not shown" in str(e.value)


@pytest.mark.parametrize("name", ["", "1ABC", "A-B", "https://node.example/key", "A B", "a=b"])
def test_environment_variable_names_are_validated(name):
    with pytest.raises(ReplayError) as e:
        endpoint_from_env(name, {})
    assert "node.example" not in str(e.value) and "environment variable name" in str(e.value)


# --------------------------------------------------------------------------- odd nodes

def test_a_node_that_cannot_report_its_head_block_still_replays(tmp_path):
    w = build_world()
    real = w.chain.rpc

    def no_head(method, params):
        if method == "eth_blockNumber":
            raise RpcError("Method not found", -32601)
        return real(method, params)

    out, results, r = run(w, tmp_path, raw=no_head)
    assert results.header["head_block"] is None and len(results.cases) == 12
    # with the head unknown every pinned state read is priced as archive
    assert r.metered.head is None and out.units > 0


def test_a_node_that_has_no_eth_call_is_an_rpc_error_not_a_verdict(tmp_path):
    w = build_world()
    real = w.chain.rpc

    def no_call(method, params):
        if method == "eth_call":
            raise RpcError("Method not found", -32601)
        return real(method, params)

    _, results, _ = run(w, tmp_path, raw=no_call, max_consecutive_errors=0)
    rec = rec_for(results, rw.TIGHT_ORDINARY)
    assert rec["status"] == "error" and rec["reason_code"] == "rpc_error"
    assert "Method not found" in rec["reason"]


def test_an_unreadable_block_number_is_treated_as_not_mined(tmp_path):
    w = build_world()
    w.chain.txs[fake_hash(4)]["blockNumber"] = "0xzz"
    _, results, _ = run(w, tmp_path)
    assert rec_for(results, rw.TIGHT_ORDINARY)["reason_code"] == "pending"


def test_reason_codes_used_by_the_runner_are_all_registered_with_the_right_status():
    import re

    src = (Path(replay_module.__file__)).read_text()
    used = set(re.findall(r'_fail\(\s*rec,\s*"(\w+)",\s*"(\w+)"', src))
    used |= set(re.findall(r'\(rec, "(error)", "(\w+)"', src))
    assert used
    for status, code in used:
        assert replay_module.REASON_CODES[code][0] == status, code
    assert {code for _, code in used} == set(replay_module.REASON_CODES)
