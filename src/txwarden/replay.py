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
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
