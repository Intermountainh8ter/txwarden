"""RPC plumbing for historical replay: rate limit, retry, cost accounting, budget and cache.

Layers, outermost first (each is a ``Transport``: ``(method, params) -> result``):

    CachingTransport   answers repeats from disk, costs nothing, never touches the layers below
      RetryingTransport  exponential backoff on HTTP 429/5xx and JSON-RPC "rate limited" errors
        MeteredTransport   budget check -> token bucket -> count -> the real transport

Every attempt, including a retry, passes through ``MeteredTransport``, so a retry storm is paid
for in the accounting and stopped by the budget like any other request. ``BudgetExceeded`` is
deliberately *not* a ``RuntimeError``: the simulator swallows those from optional probes, and a
spent budget must stop the run, not silently degrade one analysis.

Cost model. Hosted providers bill per request unit. The defaults (1 unit per call, 2 for
``debug_*``/``trace_*`` calls, 2 for state reads of blocks older than the archive window) are the
figures the provider's documentation gave at the time of writing; they are configuration, not
knowledge, and must be checked against the provider's console before you rely on them.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .simulator import RpcError, Transport

# JSON-RPC methods that read state at a block, and where the block argument sits in ``params``
STATE_BLOCK_POSITION = {
    "eth_call": 1, "eth_estimateGas": 1, "eth_getBalance": 1, "eth_getCode": 1,
    "eth_getTransactionCount": 1, "eth_getStorageAt": 2, "eth_simulateV1": 1,
    "debug_traceCall": 1,
}
MOVING_TAGS = frozenset({"latest", "pending", "safe", "finalized"})
UNCACHEABLE_METHODS = frozenset({"eth_blockNumber", "eth_gasPrice", "eth_chainId",
                                 "web3_clientVersion"})
LOOKUP_METHODS = frozenset({"eth_getTransactionByHash", "eth_getTransactionReceipt",
                            "eth_getBlockByNumber", "eth_getBlockByHash"})
RATE_LIMIT_HINTS = ("rate limit", "too many requests", "limit exceeded")


class BudgetExceeded(Exception):
    """The next request would exceed the call or unit budget; nothing was sent.

    Not a ``RuntimeError`` on purpose (see the module docstring)."""

    def __init__(self, message: str, *, calls: int, units: float):
        super().__init__(message)
        self.calls, self.units = calls, units


# --------------------------------------------------------------------------- time

class Clock(Protocol):
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...
    def wall(self) -> str: ...


class SystemClock:
    """``now`` is monotonic (for durations and rate limits); ``wall`` is a UTC timestamp."""

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def wall(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TokenBucket:
    """Classic token bucket: ``rate`` tokens per second, at most ``capacity`` stored.

    ``acquire`` blocks (through the injected clock) until a token is available and returns how
    long it waited. A capacity of 1 spaces requests evenly, so no one-second window can contain
    more than ``rate`` of them.
    """

    def __init__(self, rate: float, capacity: float = 1.0, clock: Clock | None = None):
        if not rate > 0:
            raise ValueError(f"requests per second must be positive, got {rate!r}")
        if not capacity >= 1:
            raise ValueError(f"bucket capacity must be at least 1, got {capacity!r}")
        self.rate, self.capacity = float(rate), float(capacity)
        self.clock: Clock = clock or SystemClock()
        self.tokens = self.capacity
        self._last = self.clock.now()

    def _refill(self) -> None:
        now = self.clock.now()
        self.tokens = min(self.capacity, self.tokens + (now - self._last) * self.rate)
        self._last = now

    def acquire(self) -> float:
        self._refill()
        waited = 0.0
        if self.tokens < 1.0:
            waited = (1.0 - self.tokens) / self.rate
            self.clock.sleep(waited)
            self._refill()
            self.tokens = max(self.tokens, 1.0)  # absorb floating-point shortfall
        self.tokens -= 1.0
        return waited


# --------------------------------------------------------------------------- cost and budget

@dataclass(frozen=True)
class CostModel:
    """Units billed per request. See the module docstring: defaults must be verified."""

    per_call: float = 1.0
    debug_trace: float = 2.0
    archive: float = 2.0
    combine: str = "sum"  # a call that is both debug/trace and archive: "sum" surcharges or "max"
    archive_window: int = 128  # state older than head - window needs an archive node

    def __post_init__(self) -> None:
        if self.combine not in ("sum", "max"):
            raise ValueError(f"cost combine must be 'sum' or 'max', got {self.combine!r}")
        if min(self.per_call, self.debug_trace, self.archive) < 0 or self.archive_window < 0:
            raise ValueError("costs and the archive window must not be negative")

    def is_archive(self, method: str, params: list[Any], head: int | None) -> bool:
        pos = STATE_BLOCK_POSITION.get(method)
        if pos is None:
            return False
        tag = params[pos] if len(params) > pos else "latest"
        if not isinstance(tag, str) or tag in MOVING_TAGS:
            return False
        try:
            number = int(tag, 16)
        except ValueError:
            return False
        return True if head is None else head - number > self.archive_window

    def units(self, method: str, params: list[Any], head: int | None) -> float:
        debug = method.startswith(("debug_", "trace_"))
        archive = self.is_archive(method, params, head)
        if self.combine == "max":
            applicable = [self.per_call, *([self.debug_trace] if debug else []),
                          *([self.archive] if archive else [])]
            return max(applicable)
        total = self.per_call
        total += (self.debug_trace - self.per_call) if debug else 0.0
        total += (self.archive - self.per_call) if archive else 0.0
        return max(0.0, total)

    def to_dict(self) -> dict[str, Any]:
        return {"per_call": self.per_call, "debug_trace": self.debug_trace,
                "archive": self.archive, "combine": self.combine,
                "archive_window": self.archive_window}


@dataclass
class Budget:
    """Request and unit counters with optional hard limits."""

    max_calls: int | None = None
    max_units: float | None = None
    calls: int = 0
    units: float = 0.0
    by_method: Counter = field(default_factory=Counter)

    def check(self, units: float) -> None:
        if self.max_calls is not None and self.calls + 1 > self.max_calls:
            raise BudgetExceeded(
                f"call budget of {self.max_calls} would be exceeded "
                f"({self.calls} used)", calls=self.calls, units=self.units)
        if self.max_units is not None and self.units + units > self.max_units + 1e-9:
            raise BudgetExceeded(
                f"unit budget of {self.max_units:g} would be exceeded "
                f"({self.units:g} used, next request costs {units:g})",
                calls=self.calls, units=self.units)

    def charge(self, method: str, units: float) -> None:
        self.calls += 1
        self.units += units
        self.by_method[method] += 1


# --------------------------------------------------------------------------- metering

class MeteredTransport:
    """Budget check, then rate limit, then count and send. One call here is one HTTP request."""

    def __init__(self, inner: Transport, budget: Budget, costs: CostModel,
                 bucket: TokenBucket | None = None):
        self.inner, self.budget, self.costs, self.bucket = inner, budget, costs, bucket
        self.head: int | None = None  # newest block number, once known (archive classification)

    def __call__(self, method: str, params: list[Any]) -> Any:
        units = self.costs.units(method, params, self.head)
        self.budget.check(units)
        if self.bucket is not None:
            self.bucket.acquire()
        self.budget.charge(method, units)  # billed whether or not the request succeeds
        return self.inner(method, params)


def is_retryable(e: RpcError) -> bool:
    """HTTP 429 and 5xx, or a node saying it is rate limiting: worth waiting and trying again."""
    if e.transport:
        return e.code == 429 or (e.code is not None and 500 <= e.code < 600)
    m = e.message.lower()
    return e.code == -32005 or any(h in m for h in RATE_LIMIT_HINTS)


@dataclass
class RetryPolicy:
    max_retries: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0

    def delay(self, attempt: int, retry_after: float | None = None) -> float:
        """Seconds to wait before retry number ``attempt`` (0-based): 1, 2, 4, ... capped; a
        server-supplied Retry-After raises the wait but never past ``max_delay``."""
        wait = min(self.max_delay, self.base_delay * 2 ** attempt)
        if retry_after is not None and retry_after > wait:
            wait = min(self.max_delay, retry_after)
        return wait


class RetryingTransport:
    def __init__(self, inner: Transport, policy: RetryPolicy | None = None,
                 clock: Clock | None = None):
        self.inner = inner
        self.policy = policy or RetryPolicy()
        self.clock: Clock = clock or SystemClock()
        self.retries = 0
        self.slept = 0.0

    def __call__(self, method: str, params: list[Any]) -> Any:
        attempt = 0
        while True:
            try:
                return self.inner(method, params)
            except RpcError as e:  # noqa: PERF203 - the retry decision is made per attempt
                if not is_retryable(e) or attempt >= self.policy.max_retries:
                    raise
                wait = self.policy.delay(attempt, e.retry_after)
                attempt += 1
                self.retries += 1
                self.slept += wait
                self.clock.sleep(wait)


# --------------------------------------------------------------------------- cache

class DiskCache:
    """One JSON file per request under ``<dir>/<namespace>/<xx>/<sha256>.json``.

    The key is the SHA-256 of ``[method, params, pinned_block]``; the endpoint is not part of it
    (and appears nowhere in the files), so a cache stays valid when you change providers on the
    same chain and can never leak an endpoint URL. ``namespace`` should name the chain.
    """

    VERSION = 1

    def __init__(self, directory: str | Path, namespace: str):
        self.root = Path(directory) / namespace
        self.hits = 0
        self.misses = 0
        self.writes = 0

    @staticmethod
    def key(method: str, params: list[Any], pin: str | None) -> str:
        blob = json.dumps([method, params, pin], sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def _path(self, key: str) -> Path:
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        try:
            entry = json.loads(self._path(key).read_text())
        except (OSError, ValueError):
            return None  # absent or damaged: both are simply a miss
        if (not isinstance(entry, dict) or entry.get("v") != self.VERSION
                or ("result" not in entry) == ("error" not in entry)):
            return None
        return entry

    def put(self, key: str, method: str, params: list[Any], pin: str | None,
            *, result: Any = None, error: dict[str, Any] | None = None) -> None:
        entry: dict[str, Any] = {"v": self.VERSION, "method": method, "params": params,
                                 "pin": pin}
        if error is not None:
            entry["error"] = error
        else:
            entry["result"] = result
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(entry, separators=(",", ":")))
        os.replace(tmp, path)  # atomic: a crash never leaves half a file under the real name
        self.writes += 1


def _cacheable_request(method: str, params: list[Any]) -> bool:
    if method in UNCACHEABLE_METHODS:
        return False
    return not any(isinstance(p, str) and p in MOVING_TAGS for p in params)


def _cacheable_result(method: str, result: Any) -> bool:
    if result is None:  # for these lookups null means "not found yet", which can change
        return method not in LOOKUP_METHODS
    if method == "eth_getTransactionByHash":
        return isinstance(result, dict) and result.get("blockNumber") is not None
    return True


def is_fatal(e: RpcError) -> bool:
    """A failure that says nothing about the transaction: the analysis it hit is not trustworthy.
    A node saying a method is unavailable is *not* fatal; the simulator degrades gracefully."""
    return e.transport or (e.infrastructure and not e.unsupported)


class CachingTransport:
    """Disk cache, per-run memory of unsupported methods, and failure bookkeeping.

    ``pin`` is the block the current case is analysed at; it is part of every cache key.
    ``failures`` collects the fatal errors that reached this layer so the runner can refuse to
    label a case whose analysis was cut short.
    """

    def __init__(self, inner: Transport, cache: DiskCache | None, costs: CostModel,
                 head: int | None = None):
        self.inner, self.cache, self.costs, self.head = inner, cache, costs, head
        self.pin: str | None = None
        self.hits = 0
        self.hit_units = 0.0
        self.failures: list[RpcError] = []
        self.unsupported: dict[str, str] = {}  # method -> the node's message
        self.skipped = 0
        self.memo: dict[str, Any] = {}  # values fixed for the whole run (eth_chainId)

    def __call__(self, method: str, params: list[Any]) -> Any:
        if method in self.memo:
            return self.memo[method]
        if method in self.unsupported:
            self.skipped += 1
            raise RpcError(self.unsupported[method], -32601)
        key = None
        if self.cache is not None and _cacheable_request(method, params):
            key = self.cache.key(method, params, self.pin)
            entry = self.cache.get(key)
            if entry is not None:
                self.cache.hits += 1
                self.hits += 1
                self.hit_units += self.costs.units(method, params, self.head)
                if "error" in entry:
                    e = entry["error"]
                    raise RpcError(e.get("message", "error"), e.get("code"), e.get("data"))
                return entry["result"]
            self.cache.misses += 1
        try:
            result = self.inner(method, params)
        except RpcError as e:
            if not e.transport and e.code == -32601:
                self.unsupported[method] = e.message
            if is_fatal(e):
                self.failures.append(e)
            elif key is not None and not e.infrastructure and e.code != -32601:
                assert self.cache is not None
                self.cache.put(key, method, params, self.pin,
                               error={"code": e.code, "message": e.message, "data": e.data})
            raise
        if key is not None and _cacheable_result(method, result):
            assert self.cache is not None
            self.cache.put(key, method, params, self.pin, result=result)
        return result
