"""Draw a random sample of ordinary swaps from a node, for the false-positive half of a replay.

What it produces: a case file (``tx_hash,label,source,notes``) in which every row is labelled
``ordinary``. The transactions are real swaps the decoder recognises, taken from blocks chosen at
random inside a window ending a fixed distance behind the head.

What the label means, and does not mean. Nothing here knows whether a sampled swap was attacked.
"ordinary" is "nobody labelled it sandwiched", not "verified clean": some sampled swaps will have
been sandwiched, and if the engine flags one of those the replay report counts it as a false
positive. So the false-positive rate that comes out of a sample is an upper-leaning estimate whose
bias is unknown here. The sample also says nothing about detection: it contains no sandwiched
cases, and ``replay-report`` says "not measured" for that half instead of inventing a number.

Sampling is uniform over blocks, then over recognised swaps within a block (``per_block`` of
them), not uniform over swaps: swaps in busy blocks are less likely to be drawn than swaps in
quiet ones. The seed, window and head block are written into every row's ``source`` so the sample
can be reproduced against the same chain state and so the report shows where it came from.
"""
from __future__ import annotations

import csv
import io
import os
import random
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .abi import decode_call
from .effects import extract_effects
from .models import Tx
from .redact import Redactor
from .replay import MOCK_CLIENT_PREFIX, ReplayError, _qty, parse_cases
from .replay_rpc import (
    Budget,
    BudgetExceeded,
    Clock,
    CostModel,
    MeteredTransport,
    RetryingTransport,
    RetryPolicy,
    SystemClock,
    TokenBucket,
)
from .simulator import RpcError, SimulatorOptions, Transport

COLUMNS = ("tx_hash", "label", "source", "notes")
MAX_CONSECUTIVE_BLOCK_FAILURES = 5


@dataclass
class SampleConfig:
    count: int = 60  # ordinary swaps wanted
    blocks: int = 50_000  # window length in blocks (about a week on mainnet)
    end_offset: int = 256  # the window ends this many blocks behind the head
    per_block: int = 1  # at most this many swaps taken from one block
    max_blocks: int = 400  # stop after fetching this many blocks, whatever was found
    seed: int = 1
    rps: float = 10.0
    budget_calls: int | None = None
    budget_units: float | None = None
    costs: CostModel = field(default_factory=CostModel)
    max_retries: int = 5

    def validate(self) -> None:
        for name in ("count", "blocks", "per_block", "max_blocks"):
            if getattr(self, name) < 1:
                raise ReplayError(f"--{name.replace('_', '-')} must be at least 1")
        if self.end_offset < 0:
            raise ReplayError("--end-offset must not be negative")
        if not self.rps > 0:
            raise ReplayError("--rps must be positive")


@dataclass
class SampleRow:
    tx_hash: str
    block: int
    call_kind: str


@dataclass
class SampleOutcome:
    stopped: str  # completed | max_blocks | budget | errors | window_exhausted
    rows: list[SampleRow] = field(default_factory=list)
    blocks_fetched: int = 0
    swaps_seen: int = 0
    calls: int = 0
    units: float = 0.0
    chain_id: int | None = None
    head: int | None = None
    window: tuple[int, int] | None = None
    mock: bool = False
    message: str = ""

    @property
    def exit_code(self) -> int:
        return 0 if self.stopped in ("completed", "max_blocks", "window_exhausted") and \
            self.rows else 4


def source_tag(cfg: SampleConfig, out: SampleOutcome) -> str:
    """Provenance string stored in every row's ``source`` column."""
    lo, hi = out.window or (0, 0)
    tag = (f"rpc-sample seed={cfg.seed} window={lo}-{hi} head={out.head} "
           f"per_block={cfg.per_block}")
    return tag + (" MOCK-NODE" if out.mock else "")


def render_csv(cfg: SampleConfig, out: SampleOutcome) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(COLUMNS)
    tag = source_tag(cfg, out)
    for r in sorted(out.rows, key=lambda r: (r.block, r.tx_hash)):
        writer.writerow([r.tx_hash, "ordinary", tag, f"block {r.block}; {r.call_kind}"])
    return buf.getvalue()


def write_csv(path: str | Path, text: str, *, force: bool = False) -> Path:
    """Write ``text`` to ``path`` atomically; refuse to replace an existing file without force."""
    p = Path(path)
    if p.exists() and not force:
        raise ReplayError(f"{p} already exists; choose another --out or pass --force")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return p


def _swaps_in_block(block: dict[str, Any], chain_id: int, options: SimulatorOptions
                    ) -> list[SampleRow]:
    """The transactions in a full block object that the replay would treat as supported swaps."""
    number = _qty(block.get("number"))
    txs = block.get("transactions")
    if number is None or not isinstance(txs, list):
        return []
    found: list[SampleRow] = []
    for obj in txs:
        if not isinstance(obj, dict):  # a node that ignored "full transactions" returns hashes
            continue
        h, to = obj.get("hash"), obj.get("to")
        if not isinstance(h, str) or not to:
            continue
        try:
            tx = Tx.from_dict({"sender": obj["from"], "to": to,
                               "chain_id": _qty(obj.get("chainId")) or chain_id,
                               "data": obj.get("input") or "0x",
                               "value": _qty(obj.get("value")) or 0})
        except (KeyError, ValueError, TypeError):
            continue
        call = decode_call(tx.data)
        if extract_effects(tx, call, options.weth).swaps:
            found.append(SampleRow(h.lower(), number, call.kind))
    return found


def sample_ordinary(raw: Transport, cfg: SampleConfig, options: SimulatorOptions,
                    redactor: Redactor, *, clock: Clock | None = None,
                    log: Callable[[str], None] = lambda _m: None) -> SampleOutcome:
    """Fetch random blocks until ``cfg.count`` recognised swaps are collected or a limit is hit."""
    cfg.validate()
    clock = clock or SystemClock()
    budget = Budget(cfg.budget_calls, cfg.budget_units)
    metered = MeteredTransport(raw, budget, cfg.costs, TokenBucket(cfg.rps, 1.0, clock))
    rpc = RetryingTransport(metered, RetryPolicy(cfg.max_retries), clock)
    out = SampleOutcome("completed")

    def finish(stopped: str, message: str = "") -> SampleOutcome:
        out.stopped, out.calls, out.units = stopped, budget.calls, budget.units
        out.message = redactor.scrub(message) if message else ""
        return out

    try:
        out.chain_id = _qty(rpc("eth_chainId", []))
        if out.chain_id is None:
            raise ReplayError("the endpoint did not answer eth_chainId with a quantity")
        version = rpc("web3_clientVersion", [])
        out.mock = isinstance(version, str) and version.startswith(MOCK_CLIENT_PREFIX)
        out.head = _qty(rpc("eth_blockNumber", []))
        if out.head is None:
            raise ReplayError("the endpoint did not answer eth_blockNumber with a quantity")
    except RpcError as e:
        raise ReplayError(f"cannot use the endpoint: {redactor.scrub(e.message)}") from None
    except BudgetExceeded as e:
        return finish("budget", f"the budget was spent before the endpoint check finished ({e})")

    end = out.head - cfg.end_offset
    start = max(1, end - cfg.blocks + 1)
    if end < start:
        raise ReplayError(f"the window is empty: head {out.head} minus --end-offset "
                          f"{cfg.end_offset} leaves no block to sample")
    out.window = (start, end)
    order = random.Random(cfg.seed).sample(range(start, end + 1),
                                           k=min(cfg.max_blocks, end - start + 1))
    picker = random.Random(f"{cfg.seed}:pick")
    failures = 0
    for number in order:
        if len(out.rows) >= cfg.count:
            break
        try:
            block = rpc("eth_getBlockByNumber", [hex(number), True])
        except BudgetExceeded as e:
            return finish("budget", f"stopped before exceeding the budget ({e}); "
                                    f"{len(out.rows)} of {cfg.count} swaps collected")
        except RpcError as e:
            failures += 1
            log(f"block {number}: {redactor.scrub(e.message)}")
            if failures >= MAX_CONSECUTIVE_BLOCK_FAILURES:
                return finish("errors", f"{failures} block requests in a row failed; last: "
                                        f"{e.message}")
            continue
        failures = 0
        out.blocks_fetched += 1
        if not isinstance(block, dict):
            continue
        swaps = _swaps_in_block(block, out.chain_id, options)
        out.swaps_seen += len(swaps)
        take = picker.sample(swaps, k=min(cfg.per_block, len(swaps)))
        for row in take:
            if len(out.rows) < cfg.count:
                out.rows.append(row)
        log(f"block {number}: {len(swaps)} swaps seen, {len(take)} taken "
            f"({len(out.rows)}/{cfg.count})")
    if len(out.rows) >= cfg.count:
        return finish("completed")
    if out.blocks_fetched >= len(order) and len(order) == end - start + 1:
        return finish("window_exhausted", f"every block in the window was fetched and only "
                                          f"{len(out.rows)} swaps were found")
    return finish("max_blocks", f"fetched {out.blocks_fetched} blocks (--max-blocks "
                                f"{cfg.max_blocks}) and found {len(out.rows)} of {cfg.count} "
                                "swaps; raise --max-blocks or --per-block")


def check_roundtrip(text: str) -> None:
    """Self-check used by tests and the CLI: what was written must load as an all-ordinary set."""
    parse_cases(text, "<sample>", "csv")
