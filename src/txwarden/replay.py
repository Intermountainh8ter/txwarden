"""Replay labelled historical swaps through the normal simulate-and-assess pipeline.

The question this answers: on real transactions that a human or a dataset has labelled
``sandwiched`` or ``ordinary``, how often does TxWarden's verdict say WARN or BLOCK? Nothing here
changes the engine; it feeds historical transactions to ``AnvilSimulator`` pinned to the block
before the one that mined them and records what the engine says.

This module holds the case-file loader and the runner. The RPC plumbing (rate limit, backoff,
budget, cache) is in ``replay_rpc``, secret redaction in ``redact``, and the statistics and report
in ``replay_report``.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .abi import decode_call
from .effects import extract_effects
from .models import Severity, Tx
from .redact import GENERIC, Redactor, redact_url
from .replay_rpc import (
    RATE_LIMIT_HINTS,
    Budget,
    BudgetExceeded,
    CachingTransport,
    Clock,
    CostModel,
    DiskCache,
    MeteredTransport,
    RetryingTransport,
    RetryPolicy,
    SystemClock,
    TokenBucket,
)
from .risk import PolicyConfig, assess
from .simulator import AnvilSimulator, RpcError, SimulatorOptions, Transport

LABELS = ("sandwiched", "ordinary")
_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_MAX_PROBLEMS_SHOWN = 20


class CaseFileError(ValueError):
    """The case file is unusable. ``problems`` lists every issue found, one per line number."""

    def __init__(self, path: str, problems: list[str]):
        self.path, self.problems = path, list(problems)
        shown = self.problems[:_MAX_PROBLEMS_SHOWN]
        more = len(self.problems) - len(shown)
        text = "\n  ".join(shown) + (f"\n  ... and {more} more" if more > 0 else "")
        super().__init__(f"{path}: {len(self.problems)} problem(s) in the case file:\n  {text}")


@dataclass(frozen=True)
class ReplayCase:
    tx_hash: str  # lower-case 0x + 64 hex
    label: str  # one of LABELS
    source: str = ""
    notes: str = ""
    line: int = 0  # 1-based line in the file the case came from


@dataclass
class CaseSet:
    cases: list[ReplayCase]
    path: str = ""
    sha256: str = ""  # of the file's text, so a results file can say which input it came from
    counts: dict[str, int] = field(default_factory=dict)  # every label present, zero included

    def __len__(self) -> int:
        return len(self.cases)

    def summary(self) -> str:
        parts = ", ".join(f"{self.counts.get(label, 0)} {label}" for label in LABELS)
        return f"{len(self.cases)} cases: {parts}"


def _clip(value: object, n: int = 70) -> str:
    text = str(value)
    return text if len(text) <= n else text[:n] + "..."


def _detect_format(path: str, text: str, fmt: str | None) -> str:
    if fmt:
        if fmt not in ("csv", "jsonl"):
            raise ValueError(f"unknown case file format {fmt!r} (expected csv or jsonl)")
        return fmt
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix in (".jsonl", ".ndjson"):
        return "jsonl"
    return "jsonl" if text.lstrip().startswith("{") else "csv"


def _rows_csv(text: str, problems: list[str]) -> list[tuple[int, dict[str, Any]]]:
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        problems.append("line 1: the file is empty (expected a header row)")
        return []
    names = [h.strip().lower() for h in header]
    missing = [c for c in ("tx_hash", "label") if c not in names]
    if missing:
        problems.append(f"line 1: header is missing required column(s) {', '.join(missing)} "
                        f"(found: {_clip(', '.join(names))})")
        return []
    if len(set(names)) != len(names):
        problems.append("line 1: header repeats a column name")
        return []
    rows: list[tuple[int, dict[str, Any]]] = []
    try:
        for fields_ in reader:
            line = reader.line_num
            if not any(f.strip() for f in fields_):
                continue  # blank line
            if len(fields_) > len(names):
                problems.append(f"line {line}: {len(fields_)} columns but the header has "
                                f"{len(names)}")
                continue
            fields_ = [*fields_, *[""] * (len(names) - len(fields_))]
            rows.append((line, dict(zip(names, fields_))))
    except csv.Error as e:
        problems.append(f"line {reader.line_num}: unreadable CSV ({_clip(e)})")
    return rows


def _rows_jsonl(text: str, problems: list[str]) -> list[tuple[int, dict[str, Any]]]:
    rows: list[tuple[int, dict[str, Any]]] = []
    for line, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except ValueError as e:
            problems.append(f"line {line}: not valid JSON ({_clip(e)})")
            continue
        if not isinstance(obj, dict):
            problems.append(f"line {line}: expected a JSON object, got {type(obj).__name__}")
            continue
        rows.append((line, {str(k).strip().lower(): v for k, v in obj.items()}))
    return rows


def parse_cases(text: str, path: str = "<cases>", fmt: str | None = None) -> CaseSet:
    """Validate and parse case-file text. Raises ``CaseFileError`` listing every problem found."""
    text = text.lstrip("﻿")
    kind = _detect_format(path, text, fmt)
    problems: list[str] = []
    rows = (_rows_csv if kind == "csv" else _rows_jsonl)(text, problems)
    cases: list[ReplayCase] = []
    first_line: dict[str, int] = {}
    for line, row in rows:
        h, label = row.get("tx_hash"), row.get("label")
        if not isinstance(h, str) or not _HASH_RE.fullmatch(h.strip()):
            problems.append(f"line {line}: tx_hash {_clip(h)!r} is not 0x followed by 64 hex "
                            "characters")
            continue
        h = h.strip().lower()
        norm = label.strip().lower() if isinstance(label, str) else None
        if norm not in LABELS:
            problems.append(f"line {line}: label {_clip(label)!r} is not one of "
                            f"{' | '.join(LABELS)}")
            continue
        if h in first_line:
            problems.append(f"line {line}: duplicate tx_hash (first seen on line {first_line[h]})")
            continue
        first_line[h] = line
        extra = {k: ("" if row.get(k) is None else str(row.get(k)).strip())
                 for k in ("source", "notes")}
        cases.append(ReplayCase(h, norm, extra["source"], extra["notes"], line))
    if not problems and not cases:
        problems.append("no cases found (the file has a header but no rows)")
    if problems:
        raise CaseFileError(path, problems)
    counts = Counter(c.label for c in cases)
    return CaseSet(cases, path, hashlib.sha256(text.encode()).hexdigest(),
                   {label: counts.get(label, 0) for label in LABELS})


def load_cases(path: str | Path, fmt: str | None = None) -> CaseSet:
    """Load a CSV or JSONL case file (columns ``tx_hash``, ``label``, optional ``source``,
    ``notes``). Hashes must be 0x + 64 hex, labels ``sandwiched`` or ``ordinary``, and a hash may
    appear only once. Other columns are ignored. The format comes from the suffix (``.csv``,
    ``.jsonl``/``.ndjson``) or from the first character of the file."""
    p = Path(path)
    try:
        text = p.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise CaseFileError(str(path), [f"not valid UTF-8 ({e.reason})"]) from e
    return parse_cases(text, str(path), fmt)


# =========================================================================== results files

FORMAT = "txwarden-replay/1"
MOCK_CLIENT_PREFIX = "txwarden-fakechain"  # the in-repo fake node's web3_clientVersion
STATUSES = ("analysed", "unsupported", "error")
# reason codes that mean "the RPC let us down" (as opposed to a property of the transaction)
RPC_FAILURE_CODES = frozenset({"archive_state_unavailable", "rate_limited", "rpc_error"})
_ARCHIVE_HINTS = ("missing trie node", "header not found", "state not available", "historical state",
                  "pruned", "state is not available", "unknown block", "block not found",
                  "no state available")


class ReplayError(ValueError):
    """A problem with how the replay was invoked or with the endpoint; the text is already
    scrubbed of credentials."""


def mock_stamped(path: str | Path) -> Path:
    """``results.jsonl`` -> ``results.MOCK.jsonl`` (unchanged if the name already says MOCK)."""
    p = Path(path)
    if "MOCK" in p.name:
        return p
    return p.with_name(f"{p.stem}.MOCK{p.suffix}")


@dataclass
class ResultsFile:
    path: str
    header: dict[str, Any] | None = None
    cases: dict[str, dict[str, Any]] = field(default_factory=dict)  # last record per hash
    runs: list[dict[str, Any]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def mock(self) -> bool:
        return bool(self.header and self.header.get("mock"))


def read_results(path: str | Path) -> ResultsFile:
    """Parse a results JSONL. A hash that appears twice (a retried error) keeps its last record.
    Unreadable lines are reported in ``problems`` rather than aborting, because the usual cause
    is a run killed halfway through writing its last line."""
    out = ResultsFile(str(path))
    text = Path(path).read_text(encoding="utf-8")
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            out.problems.append(f"line {number}: not valid JSON (ignored)")
            continue
        kind = rec.get("type") if isinstance(rec, dict) else None
        if kind == "header":
            if out.header is not None:
                out.problems.append(f"line {number}: second header (ignored)")
            else:
                out.header = rec
        elif kind == "case" and isinstance(rec.get("tx_hash"), str):
            out.cases[rec["tx_hash"]] = rec
        elif kind == "run":
            out.runs.append(rec)
    return out


class ResultsWriter:
    """Append-only JSONL, flushed after every record so a killed run loses at most one case."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        needs_newline = False
        if self.path.exists() and self.path.stat().st_size:
            with self.path.open("rb") as f:
                f.seek(-1, os.SEEK_END)
                needs_newline = f.read(1) != b"\n"  # a torn last line: do not glue onto it
        self._f = self.path.open("a", encoding="utf-8")
        if needs_newline:
            self._f.write("\n")

    def write(self, rec: dict[str, Any]) -> None:
        self._f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        self._f.flush()
        os.fsync(self._f.fileno())

    def close(self) -> None:
        self._f.close()


# =========================================================================== the runner

@dataclass
class ReplayConfig:
    out_path: Path = Path("replay_results.jsonl")
    cache_dir: Path | None = Path(".txwarden-replay-cache")
    limit: int | None = None  # analyse at most this many cases in this run
    rps: float = 10.0
    budget_calls: int | None = None
    budget_units: float | None = None
    costs: CostModel = field(default_factory=CostModel)
    max_retries: int = 5
    retry_errors: bool = False
    max_consecutive_errors: int = 10  # RPC failures in a row before stopping (0 = never)
    mock: bool = False  # force the MOCK stamp (it is also applied to the in-repo fake node)
    endpoint_label: str = GENERIC
    estimate: bool = False
    estimate_cases: int = 3


@dataclass
class _Snapshot:
    calls: int
    units: float
    hits: int
    hit_units: float
    methods: Counter


@dataclass
class EstimateRow:
    tx_hash: str
    status: str
    requests: int  # billed requests plus cache hits (what a cold run would send)
    units: float


@dataclass
class ReplayOutcome:
    stopped: str  # completed | limit | budget | errors | interrupted | estimate
    out_path: Path | None
    mock: bool
    analysed: int = 0  # cases processed in this run, whatever their status
    skipped: int = 0  # already in the results file
    counts: Counter = field(default_factory=Counter)
    calls: int = 0
    units: float = 0.0
    cache_hits: int = 0
    message: str = ""
    estimate_rows: list[EstimateRow] = field(default_factory=list)
    preflight_calls: int = 0
    total_cases: int = 0

    @property
    def exit_code(self) -> int:
        return 0 if self.stopped in ("completed", "limit", "estimate") else 4


def _num(x: float) -> int | float:
    return int(x) if float(x).is_integer() else round(x, 3)


def _qty(value: Any) -> int | None:
    if isinstance(value, str) and value.startswith("0x") and len(value) > 2:
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


class Replayer:
    """Feeds labelled historical transactions through simulate-and-assess, one case at a time.

    ``raw`` is the bottom of the transport stack (``http_transport`` in production, a fake in
    tests); everything above it (rate limit, backoff, budget, cache) is built here.
    """

    def __init__(self, cases: CaseSet, raw: Transport, cfg: ReplayConfig, policy: PolicyConfig,
                 sim_options: SimulatorOptions, redactor: Redactor, *,
                 clock: Clock | None = None, log: Callable[[str], None] = lambda _m: None,
                 config_sha256: str = ""):
        self.cases, self.cfg, self.policy, self.sim_options = cases, cfg, policy, sim_options
        self.redactor, self.log, self.config_sha256 = redactor, log, config_sha256
        self.clock: Clock = clock or SystemClock()
        self.budget = Budget(cfg.budget_calls, cfg.budget_units)
        self.metered = MeteredTransport(raw, self.budget, cfg.costs,
                                        TokenBucket(cfg.rps, 1.0, self.clock))
        self.retrying = RetryingTransport(self.metered, RetryPolicy(cfg.max_retries), self.clock)
        self.layer: CachingTransport | None = None
        self.chain_id: int | None = None
        self.client_version: str | None = None
        self.head: int | None = None
        self.mock = cfg.mock
        self.out_path: Path = cfg.out_path

    # ---- setup
    def _scrub(self, text: object) -> str:
        return self.redactor.scrub(text)

    def preflight(self) -> None:
        """Identify the node (uncached, counted): chain id, client, head block."""
        try:
            self.chain_id = _qty(self.retrying("eth_chainId", []))
        except RpcError as e:
            raise ReplayError(f"cannot use the endpoint: {self._scrub(e.message)}") from None
        if self.chain_id is None:
            raise ReplayError("the endpoint did not answer eth_chainId with a quantity")
        try:
            version = self.retrying("web3_clientVersion", [])
            self.client_version = self._scrub(version)[:120] if isinstance(version, str) else None
        except RpcError:
            self.client_version = None
        try:
            self.head = _qty(self.retrying("eth_blockNumber", []))
        except RpcError:
            self.head = None
        self.metered.head = self.head
        if (self.client_version or "").startswith(MOCK_CLIENT_PREFIX):
            self.mock = True
        if self.mock:
            self.out_path = mock_stamped(self.cfg.out_path)
        cache = (DiskCache(self.cfg.cache_dir, f"chain-{self.chain_id}")
                 if self.cfg.cache_dir is not None else None)
        self.layer = CachingTransport(self.retrying, cache, self.cfg.costs, self.head)
        self.layer.memo["eth_chainId"] = hex(self.chain_id)

    @property
    def rpc(self) -> CachingTransport:
        assert self.layer is not None, "preflight() first"
        return self.layer

    def _snap(self) -> _Snapshot:
        return _Snapshot(self.budget.calls, self.budget.units, self.rpc.hits, self.rpc.hit_units,
                         Counter(self.budget.by_method))

    def header(self) -> dict[str, Any]:
        return {
            "type": "header", "format": FORMAT, "mock": self.mock,
            "created_utc": self.clock.wall(), "txwarden_version": __version__,
            "endpoint": self._scrub(self.cfg.endpoint_label), "client_version": self.client_version,
            "chain_id": self.chain_id, "head_block": self.head,
            "cases_file": Path(self.cases.path).name, "cases_sha256": self.cases.sha256,
            "case_counts": dict(self.cases.counts), "config_sha256": self.config_sha256,
            "rps": self.cfg.rps, "budget_calls": self.cfg.budget_calls,
            "budget_units": self.cfg.budget_units, "costs": self.cfg.costs.to_dict(),
        }

    # ---- one case
    def _fail(self, rec: dict[str, Any], status: str, code: str, reason: str) -> None:
        rec.update(status=status, reason_code=code, reason=self._scrub(reason))

    def _rpc_failure(self, rec: dict[str, Any], e: RpcError) -> None:
        low = e.message.lower()
        if any(h in low for h in _ARCHIVE_HINTS):
            self._fail(rec, "error", "archive_state_unavailable",
                       "the endpoint cannot serve state at the pinned block (historical replay "
                       f"needs an archive plan): {e.message}")
        elif e.code == 429 or any(h in low for h in RATE_LIMIT_HINTS):
            self._fail(rec, "error", "rate_limited",
                       f"rate limited and still failing after {self.cfg.max_retries} retries: "
                       f"{e.message}")
        else:
            self._fail(rec, "error", "rpc_error", f"RPC failure: {e.message}")

    def _analyse(self, case: ReplayCase, rec: dict[str, Any]) -> None:
        rpc = self.rpc
        rpc.pin = None
        try:
            obj = rpc("eth_getTransactionByHash", [case.tx_hash])
        except RpcError as e:
            return self._rpc_failure(rec, e)
        if obj is None:
            return self._fail(rec, "error", "tx_not_found",
                              "the endpoint does not know this transaction (wrong chain, or a "
                              "mistyped hash?)")
        if not isinstance(obj, dict):
            return self._fail(rec, "error", "bad_response",
                              "eth_getTransactionByHash did not return an object")
        number = _qty(obj.get("blockNumber"))
        if number is None:
            return self._fail(rec, "error", "pending", "the transaction is not mined (no block)")
        rec["block"] = number
        rec["pinned_block"] = number - 1
        if number == 0:
            return self._fail(rec, "error", "bad_response", "block 0 has no previous block to pin")
        if not obj.get("to"):
            return self._fail(rec, "unsupported", "contract_creation",
                              "contract creation, not a swap")
        try:
            chain_id = _qty(obj.get("chainId")) or self.chain_id or 1
            tx = Tx.from_dict({"sender": obj["from"], "to": obj["to"], "chain_id": chain_id,
                               "data": obj.get("input") or "0x",
                               "value": _qty(obj.get("value")) or 0})
        except (KeyError, ValueError, TypeError) as e:
            return self._fail(rec, "error", "bad_response",
                              f"unexpected transaction object ({type(e).__name__})")
        call = decode_call(tx.data)
        rec["call_kind"] = call.kind
        if not extract_effects(tx, call, self.sim_options.weth).swaps:
            return self._fail(rec, "unsupported", "not_a_swap",
                              "not a swap the decoder recognises "
                              f"(call kind {call.kind}, selector {call.selector or 'none'})")
        pin = number - 1
        rpc.pin = hex(pin)
        res = AnvilSimulator(transport=rpc, options=self.sim_options, block=pin).simulate(tx)
        if rpc.failures:
            return self._rpc_failure(rec, rpc.failures[0])
        if res.error:
            return self._fail(rec, "error", "rpc_error", f"RPC failure: {res.error}")
        if not res.success:
            return self._fail(rec, "unsupported", "reverts_at_pin",
                              f"reverts when simulated at block {pin} ({res.revert_reason}); it "
                              f"may have depended on transactions earlier in block {number}")
        verdict, findings = assess(tx, res, self.policy)
        ids = {f.rule for f in findings}
        if "ENGINE_ERROR" in ids:
            return self._fail(rec, "error", "engine_error", "the rule engine raised an error")
        if "SIMULATION_UNAVAILABLE" in ids:
            return self._fail(rec, "error", "rpc_error", "simulation unavailable")
        if "ANALYSIS_INCOMPLETE" in ids:
            missing = next((f.data.get("missing") for f in findings
                            if f.rule == "ANALYSIS_INCOMPLETE"), None)
            return self._fail(rec, "unsupported", "pool_state_unavailable",
                              f"pool state could not be read or priced: {missing}")
        rec.update(status="analysed", verdict=verdict.value, rules=sorted(ids),
                   alerting_rules=sorted(f.rule for f in findings
                                         if f.severity >= Severity.HIGH),
                   degraded=list(res.incomplete))

    def analyse(self, case: ReplayCase) -> tuple[dict[str, Any], _Snapshot, _Snapshot]:
        """Run one case; returns its result record plus the counters before and after."""
        t0 = self.clock.now()
        rpc = self.rpc
        rpc.failures.clear()
        before = self._snap()
        rec: dict[str, Any] = {"type": "case", "tx_hash": case.tx_hash, "label": case.label}
        if case.source:
            rec["source"] = self._scrub(case.source)
        try:
            self._analyse(case, rec)
        except BudgetExceeded:
            raise
        except Exception as e:  # one bad case must not end a long run
            self._fail(rec, "error", "internal_error", f"{type(e).__name__}: {e}")
        after = self._snap()
        rec.setdefault("verdict", None)
        rec["rpc_calls"] = after.calls - before.calls
        rec["cache_hits"] = after.hits - before.hits
        rec["units"] = _num(after.units - before.units)
        rec["methods"] = dict(sorted((after.methods - before.methods).items()))
        rec["elapsed_s"] = round(self.clock.now() - t0, 3)
        return rec, before, after

    # ---- whole runs
    def _existing(self) -> ResultsFile | None:
        if not self.out_path.exists() or not self.out_path.stat().st_size:
            return None
        prior = read_results(self.out_path)
        if prior.header is None:
            raise ReplayError(f"{self.out_path} exists but is not a replay results file (no "
                              "header line); choose another --out")
        if bool(prior.header.get("mock")) != self.mock:
            raise ReplayError(f"{self.out_path} was written in "
                              f"{'MOCK' if prior.header.get('mock') else 'non-MOCK'} mode but "
                              "this run is not; refusing to mix the two")
        return prior

    def run(self) -> ReplayOutcome:
        if self.layer is None:
            try:
                self.preflight()
            except BudgetExceeded as e:
                return ReplayOutcome("budget", None, self.mock, total_cases=len(self.cases),
                                     calls=self.budget.calls, units=self.budget.units,
                                     message=f"the budget was spent before the endpoint check "
                                             f"finished ({e})")
        if self.cfg.estimate:
            return self._estimate()
        prior = self._existing()
        done = set()
        if prior is not None:
            done = {h for h, r in prior.cases.items()
                    if not (self.cfg.retry_errors and r.get("status") == "error")}
        todo = [c for c in self.cases.cases if c.tx_hash not in done]
        skipped = len(self.cases) - len(todo)
        out = ReplayOutcome("completed", self.out_path, self.mock, skipped=skipped,
                            total_cases=len(self.cases), preflight_calls=self.budget.calls)
        limited = self.cfg.limit is not None and self.cfg.limit < len(todo)
        if limited:
            todo = todo[:self.cfg.limit]
        writer = ResultsWriter(self.out_path)
        started = self.clock.wall()
        try:
            if prior is None:
                writer.write(self.header())
            self._loop(todo, writer, out)
            if out.stopped == "completed" and limited:
                out.stopped = "limit"
        except BaseException:
            out.stopped = "aborted"
            raise
        finally:
            out.calls, out.units = self.budget.calls, self.budget.units
            out.cache_hits = self.rpc.hits
            writer.write({"type": "run", "started_utc": started, "finished_utc": self.clock.wall(),
                          "stopped": out.stopped, "cases": out.analysed,
                          "rpc_calls": self.budget.calls, "units": _num(self.budget.units),
                          "cache_hits": self.rpc.hits, "retries": self.retrying.retries})
            writer.close()
        return out

    def _loop(self, todo: list[ReplayCase], writer: ResultsWriter, out: ReplayOutcome) -> None:
        streak = 0
        for i, case in enumerate(todo, 1):
            try:
                rec, _before, _after = self.analyse(case)
            except BudgetExceeded as e:
                out.stopped = "budget"
                out.message = (f"stopped before exceeding the budget ({e}); {len(todo) - i + 1} "
                               "cases left. Raise the budget and rerun the same command to "
                               "continue (finished cases are skipped and the cache is reused).")
                return
            except KeyboardInterrupt:
                out.stopped = "interrupted"
                out.message = "interrupted; rerun the same command to continue"
                return
            writer.write(rec)
            out.analysed += 1
            out.counts[rec["status"]] += 1
            self.log(f"[{i}/{len(todo)}] {rec['tx_hash']} {rec['label']}: {rec['status']}"
                     + (f" {rec['verdict']}" if rec.get("verdict") else "")
                     + (f" ({rec['reason_code']})" if rec.get("reason_code") else "")
                     + f"  requests={rec['rpc_calls']} cached={rec['cache_hits']}"
                     f" units={rec['units']}  {rec['elapsed_s']}s")
            streak = streak + 1 if rec.get("reason_code") in RPC_FAILURE_CODES else 0
            if self.cfg.max_consecutive_errors and streak >= self.cfg.max_consecutive_errors:
                out.stopped = "errors"
                out.message = (f"stopped after {streak} consecutive RPC failures (last: "
                               f"{rec['reason']}). Fix the endpoint or plan, then rerun with "
                               "--retry-errors to redo the failed cases.")
                return

    def _estimate(self) -> ReplayOutcome:
        sample = self.cases.cases[:self.cfg.estimate_cases]
        out = ReplayOutcome("estimate", None, self.mock, total_cases=len(self.cases),
                            preflight_calls=self.budget.calls)
        for case in sample:
            try:
                rec, before, after = self.analyse(case)
            except BudgetExceeded as e:
                out.stopped, out.message = "budget", f"budget reached during the estimate ({e})"
                break
            out.estimate_rows.append(EstimateRow(
                case.tx_hash, rec["status"],
                (after.calls - before.calls) + (after.hits - before.hits),
                (after.units - before.units) + (after.hit_units - before.hit_units)))
        out.calls, out.units, out.cache_hits = self.budget.calls, self.budget.units, self.rpc.hits
        return out


def format_estimate(out: ReplayOutcome, costs: CostModel) -> str:
    """Human-readable estimate: measured per-case requests and a projection to the whole file."""
    rows = out.estimate_rows
    lines = [f"Estimate from the first {len(rows)} case(s); nothing was written to a results "
             "file."]
    lines.extend(f"  {r.tx_hash}  {r.status:<11} {r.requests:>3} requests  "
                 f"{_num(r.units):>5} units" for r in rows)
    lines.append(f"  endpoint preflight (once per run): {out.preflight_calls} requests")
    if rows:
        mean_req = sum(r.requests for r in rows) / len(rows)
        mean_units = sum(r.units for r in rows) / len(rows)
        hi_req, hi_units = max(r.requests for r in rows), max(r.units for r in rows)
        n = out.total_cases
        lines += [
            f"  mean per case: {mean_req:.1f} requests, {mean_units:.1f} units",
            f"  projected for all {n} cases: about {mean_req * n:,.0f} requests, "
            f"{mean_units * n:,.0f} units (plus the preflight)",
            f"  upper bound if every case cost as much as the costliest sampled: "
            f"{hi_req * n:,.0f} requests, {hi_units * n:,.0f} units",
            "  Three cases is a rough guide: transactions that are not swaps cost one request, "
            "and swaps cost the most, so the real total depends on your mix.",
        ]
    lines.append(f"Cost model: {_num(costs.per_call)} unit per request, "
                 f"{_num(costs.debug_trace)} for debug_*/trace_*, {_num(costs.archive)} for state "
                 f"older than {costs.archive_window} blocks, surcharges combined by '{costs.combine}'. "
                 "These defaults come from the provider's documentation; verify them in the "
                 "provider console.")
    if out.message:
        lines.append(out.message)
    return "\n".join(lines)


# =========================================================================== endpoint from the environment

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def valid_env_name(name: str) -> bool:
    return bool(_ENV_NAME.fullmatch(name))


def endpoint_from_env(name: str, environ: dict[str, str] | None = None) -> str:
    """The RPC URL, read from the environment variable ``name`` and nowhere else.

    The URL usually embeds an API key, so it must not appear in a file, a command line (shell
    history, process listings) or a message; the errors here never include the value.
    """
    if not valid_env_name(name):
        raise ReplayError("--rpc-env must be an environment variable name (letters, digits and "
                          "underscores)")
    value = (os.environ if environ is None else environ).get(name, "").strip()
    if not value:
        raise ReplayError(f"environment variable {name} is not set or is empty: export it with "
                          "your node endpoint URL (see docs/LIVE_REPLAY.md); replay has no "
                          "--rpc flag on purpose")
    if redact_url(value) == GENERIC or not value.lower().startswith(("http://", "https://")) \
            or any(c.isspace() or ord(c) < 32 for c in value):
        raise ReplayError(f"environment variable {name} does not hold a usable http(s) URL "
                          "(the value is not shown)")
    return value
