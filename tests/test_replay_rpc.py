"""Rate limit, backoff, cost accounting, budget and cache, with a fake clock."""
import json

import pytest

from txwarden.replay_rpc import (
    Budget,
    BudgetExceeded,
    CachingTransport,
    CostModel,
    DiskCache,
    MeteredTransport,
    RetryingTransport,
    RetryPolicy,
    SystemClock,
    TokenBucket,
    is_fatal,
    is_retryable,
)
from txwarden.simulator import RpcError

from .fake_history import FakeClock
from .helpers import revert


def http_error(code: int, **kw) -> RpcError:
    return RpcError(f"HTTP {code} from https://node.example", code=code, transport=True, **kw)


# --------------------------------------------------------------------------- token bucket

def test_bucket_spaces_requests_evenly_with_capacity_one():
    clock = FakeClock()
    bucket = TokenBucket(10, clock=clock)
    waits = [bucket.acquire() for _ in range(5)]
    assert waits[0] == 0 and waits[1:] == pytest.approx([0.1] * 4)
    assert clock.t == pytest.approx(1_000.4)


def test_bucket_allows_a_burst_up_to_capacity_then_waits():
    clock = FakeClock()
    bucket = TokenBucket(10, capacity=3, clock=clock)
    assert [bucket.acquire() for _ in range(3)] == [0, 0, 0]
    assert bucket.acquire() == pytest.approx(0.1)


def test_bucket_refills_while_idle_but_never_beyond_capacity():
    clock = FakeClock()
    bucket = TokenBucket(10, capacity=2, clock=clock)
    bucket.acquire()
    bucket.acquire()
    clock.t += 60  # a long idle period must not bank 600 tokens
    assert [bucket.acquire() for _ in range(2)] == [0, 0]
    assert bucket.acquire() == pytest.approx(0.1)


def test_bucket_supports_fractional_rates():
    clock = FakeClock()
    bucket = TokenBucket(0.5, clock=clock)
    bucket.acquire()
    assert bucket.acquire() == pytest.approx(2.0)


def test_bucket_total_time_matches_the_rate():
    clock = FakeClock()
    bucket = TokenBucket(4, clock=clock)
    for _ in range(41):
        bucket.acquire()
    assert clock.t - 1_000 == pytest.approx(40 / 4)


@pytest.mark.parametrize("rate,cap", [(0, 1), (-1, 1), (10, 0), (10, 0.5)])
def test_bucket_rejects_nonsense(rate, cap):
    with pytest.raises(ValueError):
        TokenBucket(rate, cap)


def test_system_clock_is_monotonic_and_sleep_of_zero_is_free():
    c = SystemClock()
    a = c.now()
    c.sleep(0)
    c.sleep(-1)
    assert c.now() >= a and c.wall().startswith("20")


# --------------------------------------------------------------------------- retry policy

def test_backoff_doubles_up_to_the_cap():
    p = RetryPolicy(max_retries=9, base_delay=1.0, max_delay=60.0)
    assert [p.delay(i) for i in range(8)] == [1, 2, 4, 8, 16, 32, 60, 60]


def test_retry_after_raises_the_wait_but_is_capped():
    p = RetryPolicy()
    assert p.delay(0, 10) == 10 and p.delay(5, 3) == 32 and p.delay(0, 5000) == 60
    assert p.delay(0, None) == 1


@pytest.mark.parametrize("err,expected", [
    (http_error(429), True), (http_error(500), True), (http_error(503), True),
    (http_error(599), True), (http_error(404), False), (http_error(401), False),
    (http_error(400), False), (RpcError("cannot reach host", transport=True), False),
    (RpcError("limit exceeded", -32005), True), (RpcError("Rate limit reached", -32000), True),
    (RpcError("Too Many Requests", -32000), True), (revert("nope"), False),
    (RpcError("execution reverted", 3), False),
])
def test_which_errors_are_retried(err, expected):
    assert is_retryable(err) is expected


def test_retries_429_with_exponential_backoff_and_then_succeeds():
    clock, calls = FakeClock(), []

    def inner(method, params):
        calls.append(method)
        if len(calls) <= 2:
            raise http_error(429)
        return "0x1"

    t = RetryingTransport(inner, RetryPolicy(max_retries=5), clock)
    assert t("eth_chainId", []) == "0x1"
    assert clock.sleeps == [1, 2] and t.retries == 2 and t.slept == 3 and len(calls) == 3


def test_gives_up_after_max_retries_and_raises_the_last_error():
    clock, calls = FakeClock(), []

    def inner(method, params):
        calls.append(1)
        raise http_error(503)

    t = RetryingTransport(inner, RetryPolicy(max_retries=3), clock)
    with pytest.raises(RpcError, match="HTTP 503"):
        t("eth_call", [])
    assert clock.sleeps == [1, 2, 4] and len(calls) == 4


def test_non_retryable_errors_are_raised_at_once():
    clock = FakeClock()

    def inner(method, params):
        raise revert("EXPIRED")

    with pytest.raises(RpcError, match="EXPIRED"):
        RetryingTransport(inner, clock=clock)("eth_call", [])
    assert clock.sleeps == []


def test_retry_after_header_value_is_honoured():
    clock, n = FakeClock(), [0]

    def inner(method, params):
        n[0] += 1
        if n[0] == 1:
            raise http_error(429, retry_after=7)
        return "ok"

    assert RetryingTransport(inner, clock=clock)("m", []) == "ok"
    assert clock.sleeps == [7]


def test_zero_retries_means_no_second_attempt():
    n = [0]

    def inner(method, params):
        n[0] += 1
        raise http_error(429)

    with pytest.raises(RpcError):
        RetryingTransport(inner, RetryPolicy(max_retries=0), FakeClock())("m", [])
    assert n[0] == 1


# --------------------------------------------------------------------------- costs

HEAD = 1_000


@pytest.mark.parametrize("method,params,expected", [
    ("eth_call", [{}, "latest"], 1),
    ("eth_call", [{}, hex(100)], 2),            # 900 blocks behind the head: archive
    ("eth_call", [{}, hex(990)], 1),            # inside the 128-block window
    ("eth_call", [{}, hex(HEAD - 128)], 1),     # exactly at the window edge
    ("eth_call", [{}, hex(HEAD - 129)], 2),
    ("eth_getBalance", ["0xabc", hex(5)], 2),
    ("eth_getStorageAt", ["0xabc", "0x0", hex(5)], 2),
    ("eth_simulateV1", [{}, hex(5)], 2),
    ("debug_traceCall", [{}, "latest", {}], 2),
    ("debug_traceCall", [{}, hex(5), {}], 3),   # debug surcharge plus archive surcharge
    ("trace_call", [{}, ["trace"], "latest"], 2),
    ("eth_getTransactionByHash", ["0xabc"], 1),
    ("eth_getBlockByNumber", [hex(5), False], 1),
    ("eth_chainId", [], 1),
    ("eth_call", [{}], 1),                      # no block argument means latest
    ("eth_call", [{}, "pending"], 1),
])
def test_default_cost_model(method, params, expected):
    assert CostModel().units(method, params, HEAD) == expected


def test_max_combination_does_not_add_surcharges():
    assert CostModel(combine="max").units("debug_traceCall", [{}, hex(5), {}], HEAD) == 2


def test_costs_are_configurable():
    m = CostModel(per_call=3, debug_trace=5, archive=4)
    assert m.units("eth_call", [{}, "latest"], HEAD) == 3
    assert m.units("debug_traceCall", [{}, "latest", {}], HEAD) == 5
    assert m.units("eth_call", [{}, hex(1)], HEAD) == 4
    assert m.units("debug_traceCall", [{}, hex(1), {}], HEAD) == 6   # 3 + 2 + 1
    assert CostModel(per_call=3, debug_trace=5, archive=4, combine="max").units(
        "debug_traceCall", [{}, hex(1), {}], HEAD) == 5


def test_unknown_head_treats_every_pinned_read_as_archive():
    assert CostModel().units("eth_call", [{}, hex(HEAD)], None) == 2
    assert CostModel().units("eth_call", [{}, "latest"], None) == 1


def test_archive_window_is_configurable():
    assert CostModel(archive_window=2000).units("eth_call", [{}, hex(100)], HEAD) == 1


def test_garbage_block_arguments_are_not_archive():
    assert CostModel().units("eth_call", [{}, "banana"], HEAD) == 1
    assert CostModel().units("eth_call", [{}, {"blockHash": "0x1"}], HEAD) == 1


@pytest.mark.parametrize("kw", [{"combine": "avg"}, {"per_call": -1}, {"archive_window": -1}])
def test_cost_model_rejects_nonsense(kw):
    with pytest.raises(ValueError):
        CostModel(**kw)


def test_cost_model_serialises_for_the_results_header():
    assert CostModel().to_dict() == {"per_call": 1.0, "debug_trace": 2.0, "archive": 2.0,
                                     "combine": "sum", "archive_window": 128}


# --------------------------------------------------------------------------- budget

def test_call_budget_stops_before_the_request_that_would_exceed_it():
    b = Budget(max_calls=2)
    for _ in range(2):
        b.check(1)
        b.charge("eth_call", 1)
    with pytest.raises(BudgetExceeded, match="call budget of 2") as e:
        b.check(1)
    assert e.value.calls == 2 and b.calls == 2


def test_unit_budget_allows_an_exact_fit_and_refuses_the_overshoot():
    b = Budget(max_units=5)
    b.check(3)
    b.charge("m", 3)
    b.check(2)  # 3 + 2 == 5: fits
    b.charge("m", 2)
    with pytest.raises(BudgetExceeded, match="unit budget of 5"):
        b.check(1)


def test_unit_budget_refuses_a_costly_request_even_when_a_cheap_one_would_fit():
    b = Budget(max_units=4)
    b.charge("m", 3)
    b.check(1)
    with pytest.raises(BudgetExceeded):
        b.check(2)


def test_no_limits_never_raise_and_counts_by_method():
    b = Budget()
    for _ in range(1000):
        b.check(9)
        b.charge("eth_call", 9)
    b.charge("eth_getCode", 1)
    assert b.calls == 1001 and b.by_method == {"eth_call": 1000, "eth_getCode": 1}


def test_budget_exceeded_is_not_swallowed_by_the_simulators_handlers():
    """AnvilSimulator treats RuntimeError/ValueError/KeyError... from optional probes as 'not
    available'; running out of budget must not be one of them."""
    assert not issubclass(BudgetExceeded, (RuntimeError, ValueError, KeyError, TypeError,
                                            IndexError, OSError))


def test_metered_transport_charges_every_attempt_and_stops_at_the_budget():
    clock, sent = FakeClock(), []

    def inner(method, params):
        sent.append(method)
        raise http_error(429)

    budget = Budget(max_calls=3)
    metered = MeteredTransport(inner, budget, CostModel(), TokenBucket(1000, clock=clock))
    t = RetryingTransport(metered, RetryPolicy(max_retries=10), clock)
    with pytest.raises(BudgetExceeded):
        t("eth_call", [{}, "latest"])
    assert len(sent) == 3 and budget.calls == 3  # the fourth attempt was never sent


def test_metered_transport_rate_limits_and_prices_by_head():
    clock = FakeClock()
    metered = MeteredTransport(lambda m, p: "0x", Budget(), CostModel(),
                               TokenBucket(10, clock=clock))
    metered.head = HEAD
    for _ in range(3):
        metered("eth_call", [{}, hex(5)])
    assert metered.budget.units == 6 and clock.t == pytest.approx(1_000.2)


def test_failed_requests_are_still_billed():
    budget = Budget()

    def inner(method, params):
        raise revert("x")

    with pytest.raises(RpcError):
        MeteredTransport(inner, budget, CostModel())("eth_call", [{}, "latest"])
    assert budget.calls == 1 and budget.units == 1


# --------------------------------------------------------------------------- disk cache

def test_cache_key_is_stable_and_depends_on_method_params_and_pin():
    k = DiskCache.key
    assert k("eth_call", [{"a": 1, "b": 2}, "0x5"], "0x5") == k("eth_call", [{"b": 2, "a": 1}, "0x5"],
                                                                 "0x5")
    base = k("eth_call", [{"a": 1}, "0x5"], "0x5")
    assert len({base, k("eth_getCode", [{"a": 1}, "0x5"], "0x5"), k("eth_call", [{"a": 2}, "0x5"],
                                                                    "0x5"),
                k("eth_call", [{"a": 1}, "0x5"], "0x6"), k("eth_call", [{"a": 1}, "0x5"], None)}) == 5


def test_cache_roundtrip_and_layout(tmp_path):
    cache = DiskCache(tmp_path, "chain-1")
    key = cache.key("eth_getCode", ["0xabc", "0x5"], "0x5")
    assert cache.get(key) is None
    cache.put(key, "eth_getCode", ["0xabc", "0x5"], "0x5", result="0x6080")
    assert cache.get(key)["result"] == "0x6080" and cache.writes == 1
    files = list((tmp_path / "chain-1").rglob("*.json"))
    assert [f.name for f in files] == [f"{key}.json"] and files[0].parent.name == key[:2]
    assert not list(tmp_path.rglob("*.tmp"))


def test_cache_stores_errors_and_none_results_distinctly(tmp_path):
    cache = DiskCache(tmp_path, "chain-1")
    cache.put("a" * 64, "m", [], None, error={"code": 3, "message": "boom", "data": None})
    cache.put("b" * 64, "m", [], None, result=None)
    assert cache.get("a" * 64)["error"]["message"] == "boom"
    assert "result" in cache.get("b" * 64)


@pytest.mark.parametrize("content", ["", "not json", "[]", '{"v": 99, "result": 1}',
                                     '{"v": 1}', '{"v": 1, "result": 1, "error": {}}'])
def test_damaged_cache_entries_are_misses(tmp_path, content):
    cache = DiskCache(tmp_path, "chain-1")
    key = "c" * 64
    path = tmp_path / "chain-1" / key[:2] / f"{key}.json"
    path.parent.mkdir(parents=True)
    path.write_text(content)
    assert cache.get(key) is None


# --------------------------------------------------------------------------- caching layer

def make_layer(inner, tmp_path, head=HEAD):
    return CachingTransport(inner, DiskCache(tmp_path, "chain-1"), CostModel(), head)


def counting(result="0x1"):
    calls = []

    def inner(method, params):
        calls.append((method, params))
        return result

    return inner, calls


def test_second_identical_request_is_answered_from_disk(tmp_path):
    inner, calls = counting("0xabc")
    layer = make_layer(inner, tmp_path)
    layer.pin = "0x5"
    params = [{"to": "0x1"}, "0x5"]
    assert layer("eth_call", params) == layer("eth_call", params) == "0xabc"
    assert len(calls) == 1 and layer.hits == 1 and layer.hit_units == 2  # archive-priced
    again = make_layer(inner, tmp_path)  # a fresh process: the cache is on disk
    again.pin = "0x5"
    assert again("eth_call", params) == "0xabc" and len(calls) == 1


def test_a_different_pin_is_a_different_request(tmp_path):
    inner, calls = counting()
    layer = make_layer(inner, tmp_path)
    layer.pin = "0x5"
    layer("eth_call", [{}, "0x5"])
    layer.pin = "0x6"
    layer("eth_call", [{}, "0x5"])
    assert len(calls) == 2


@pytest.mark.parametrize("method,params", [
    ("eth_call", [{}, "latest"]), ("eth_getBalance", ["0x1", "pending"]),
    ("eth_getCode", ["0x1", "safe"]), ("eth_call", [{}, "finalized"]),
    ("eth_blockNumber", []), ("eth_gasPrice", []), ("web3_clientVersion", []),
])
def test_requests_about_a_moving_head_are_never_cached(method, params, tmp_path):
    inner, calls = counting()
    layer = make_layer(inner, tmp_path)
    layer(method, params)
    layer(method, params)
    assert len(calls) == 2 and not list(tmp_path.rglob("*.json"))


def test_missing_transactions_are_not_cached_but_mined_ones_are(tmp_path):
    answers = iter([None, {"hash": "0x1", "blockNumber": None}, {"hash": "0x1",
                                                                  "blockNumber": "0x10"}])
    calls = []

    def inner(method, params):
        calls.append(1)
        return next(answers)

    layer = make_layer(inner, tmp_path)
    for _ in range(3):
        layer("eth_getTransactionByHash", ["0x1"])
    assert len(calls) == 3
    layer("eth_getTransactionByHash", ["0x1"])
    assert len(calls) == 3  # the mined answer was cached


@pytest.mark.parametrize("method,cached", [
    ("eth_getTransactionByHash", False), ("eth_getTransactionReceipt", False),
    ("eth_getBlockByNumber", False), ("eth_getBlockByHash", False),
    ("debug_traceCall", True), ("eth_getCode", True),
])
def test_null_results_are_cached_unless_they_mean_not_found_yet(method, cached, tmp_path):
    inner, calls = counting(None)
    layer = make_layer(inner, tmp_path)
    layer(method, ["0x5"])
    layer(method, ["0x5"])
    assert len(calls) == (1 if cached else 2)


def test_reverts_are_cached_because_they_are_deterministic(tmp_path):
    n = [0]

    def inner(method, params):
        n[0] += 1
        raise revert("EXPIRED")

    layer = make_layer(inner, tmp_path)
    for _ in range(2):
        with pytest.raises(RpcError, match="EXPIRED") as e:
            layer("eth_call", [{}, "0x5"])
    assert n[0] == 1 and e.value.code == 3 and not layer.failures


@pytest.mark.parametrize("err", [http_error(429), http_error(500),
                                 RpcError("missing trie node 0x1", -32000),
                                 RpcError("cannot reach host", transport=True)])
def test_infrastructure_failures_are_not_cached_and_are_recorded(err, tmp_path):
    n = [0]

    def inner(method, params):
        n[0] += 1
        raise err

    layer = make_layer(inner, tmp_path)
    for _ in range(2):
        with pytest.raises(RpcError):
            layer("eth_call", [{}, "0x5"])
    assert n[0] == 2 and len(layer.failures) == 2 and is_fatal(err)
    assert not list(tmp_path.rglob("*.json"))


def test_an_unsupported_method_is_remembered_for_the_run(tmp_path):
    n = [0]

    def inner(method, params):
        n[0] += 1
        raise RpcError("the method debug_traceCall does not exist/is not available", -32601)

    layer = make_layer(inner, tmp_path)
    for _ in range(4):
        with pytest.raises(RpcError) as e:
            layer("debug_traceCall", [{}, "0x5", {}])
    assert n[0] == 1 and layer.skipped == 3 and e.value.unsupported
    assert not layer.failures  # an optional feature missing is not a failed analysis
    assert not list(tmp_path.rglob("*.json"))


def test_a_revert_that_says_does_not_exist_does_not_disable_the_method(tmp_path):
    """RpcError.unsupported matches the phrase 'does not exist'; the circuit breaker must not."""
    n = [0]

    def inner(method, params):
        n[0] += 1
        raise revert("Pair does not exist")

    layer = make_layer(inner, tmp_path)
    for i in range(3):
        with pytest.raises(RpcError, match="does not exist"):
            layer("eth_call", [{"i": i}, "0x5"])
    assert n[0] == 3 and not layer.unsupported


def test_memoised_values_cost_nothing(tmp_path):
    inner, calls = counting()
    layer = make_layer(inner, tmp_path)
    layer.memo["eth_chainId"] = "0x1"
    assert layer("eth_chainId", []) == "0x1" and calls == []


def test_without_a_cache_everything_passes_through():
    inner, calls = counting()
    layer = CachingTransport(inner, None, CostModel())
    layer("eth_call", [{}, "0x5"])
    layer("eth_call", [{}, "0x5"])
    assert len(calls) == 2 and layer.hits == 0


def test_cache_files_hold_the_request_and_nothing_else(tmp_path):
    inner, _ = counting("0x1")
    layer = make_layer(inner, tmp_path)
    layer.pin = "0x5"
    layer("eth_getCode", ["0xabc", "0x5"])
    (path,) = list(tmp_path.rglob("*.json"))
    entry = json.loads(path.read_text())
    assert set(entry) == {"v", "method", "params", "pin", "result"}
