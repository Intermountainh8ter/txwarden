"""Turn a replay results file into headline numbers, and refuse to when they would mislead.

Everything here is computed from the results JSONL and nothing else. A case counts toward a rate
only when it was analysed (status ``analysed``, which carries a verdict). Cases the harness could
not analyse (``unsupported``, ``error``) are never counted as detected, missed, correct or wrong;
they are reported beside the rates as denominators so the reader can see how much of the file the
rates stand on.

Refusals (exit code 3 from the CLI):

* a results file written against the in-repo fake node (``mock`` in its header) unless
  ``allow_mock``: those numbers describe the fake, not Ethereum;
* fewer than ``MIN_CASES`` analysable cases for either label unless ``allow_small``, in which
  case every output is stamped SMALL SAMPLE;
* a file with no readable header, or none of this format.
"""
from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .replay import FORMAT, LABELS, ReplayError, ResultsFile, mock_stamped, read_results

MIN_CASES = 30
Z95 = 1.959963984540054
VERDICTS = ("ALLOW", "WARN", "BLOCK")


class ReportRefused(ReplayError):
    """The report will not be rendered for this file with these options."""


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float] | None:
    """Wilson score interval for ``k`` successes in ``n`` trials (95% by default); None if n=0."""
    if n <= 0:
        return None
    if not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n, got k={k}, n={n}")
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    lo, hi = max(0.0, centre - half), min(1.0, centre + half)
    # the bounds at k=0 and k=n are exactly 0 and 1; floating point lands a hair inside them
    return (0.0 if k == 0 else lo), (1.0 if k == n else hi)


@dataclass
class LabelStats:
    label: str
    expected: int | None = None  # cases of this label in the input file, from the header
    recorded: int = 0
    analysed: int = 0
    unsupported: int = 0
    error: int = 0
    invalid: int = 0
    verdicts: Counter = field(default_factory=Counter)
    reasons: Counter = field(default_factory=Counter)  # reason_code -> cases, unsupported + error
    rule_hits: Counter = field(default_factory=Counter)  # rule -> analysed cases where it fired

    @property
    def flagged(self) -> int:  # WARN or BLOCK
        return self.verdicts["WARN"] + self.verdicts["BLOCK"]

    @property
    def blocked(self) -> int:
        return self.verdicts["BLOCK"]

    @property
    def not_run(self) -> int | None:
        return None if self.expected is None else max(0, self.expected - self.recorded)

    def rate(self, k: int) -> dict[str, Any]:
        ci = wilson(k, self.analysed)
        return {"k": k, "n": self.analysed, "rate": k / self.analysed if self.analysed else None,
                "wilson95": list(ci) if ci else None}


@dataclass
class Report:
    path: str
    header: dict[str, Any]
    mock: bool
    small_sample: bool
    labels: dict[str, LabelStats]
    alerting: set[str]  # rules that decided a verdict in at least one case
    missed: list[dict[str, Any]]  # sandwiched, analysed, verdict ALLOW
    false_positives: list[dict[str, Any]]  # ordinary, analysed, WARN or BLOCK
    rpc_calls: int
    units: float
    problems: list[str]

    @property
    def title(self) -> str:
        stamps = (["MOCK"] if self.mock else []) + (["SMALL SAMPLE"] if self.small_sample else [])
        return "TxWarden replay report" + "".join(f" - {s}" for s in stamps)

    def output_path(self, path: str | Path) -> Path:
        """``--out`` with the same stamps in the file name: report.md -> report.MOCK.md."""
        p = mock_stamped(path) if self.mock else Path(path)
        if self.small_sample and "SMALL-SAMPLE" not in p.name:
            p = p.with_name(f"{p.stem}.SMALL-SAMPLE{p.suffix}")
        return p


def _case_view(rec: dict[str, Any]) -> dict[str, Any]:
    keep = ("tx_hash", "label", "block", "pinned_block", "verdict", "rules", "alerting_rules",
            "reason_code", "reason", "source")
    return {k: rec[k] for k in keep if rec.get(k) not in (None, [], "")}


def build_report(results: ResultsFile, *, allow_mock: bool = False,
                 allow_small: bool = False) -> Report:
    """Compute the report, or raise ``ReportRefused`` explaining why not."""
    header = results.header
    if header is None:
        raise ReportRefused(f"{results.path}: no header line, so it cannot be said whether this "
                            "file came from a real node or the fake one; refusing")
    if not str(header.get("format", "")).startswith("txwarden-replay/"):
        raise ReportRefused(f"{results.path}: not a {FORMAT} results file")
    mock = bool(header.get("mock"))
    if mock and not allow_mock:
        raise ReportRefused(
            f"{results.path}: these results were produced against the in-repo fake node (MOCK). "
            "They test the harness and say nothing about real transactions. Pass --allow-mock to "
            "render them anyway; the output will be stamped MOCK.")
    if not results.cases:
        raise ReportRefused(f"{results.path}: the file contains no case results")

    expected = header.get("case_counts") or {}
    stats = {label: LabelStats(label, expected.get(label)) for label in LABELS}
    alerting: set[str] = set()
    missed: list[dict[str, Any]] = []
    flagged_ordinary: list[dict[str, Any]] = []
    problems = list(results.problems)
    calls, units = 0, 0.0
    for h, rec in results.cases.items():
        s = stats.get(rec.get("label"))
        if s is None:
            problems.append(f"{h}: unknown label {str(rec.get('label'))[:20]!r}; ignored")
            continue
        s.recorded += 1
        calls += int(rec.get("rpc_calls") or 0)
        units += float(rec.get("units") or 0)
        status, verdict = rec.get("status"), rec.get("verdict")
        if status == "analysed" and verdict in VERDICTS:
            s.analysed += 1
            s.verdicts[verdict] += 1
            s.rule_hits.update(set(rec.get("rules") or []))
            alerting.update(rec.get("alerting_rules") or [])
            if s.label == "sandwiched" and verdict == "ALLOW":
                missed.append(_case_view(rec))
            elif s.label == "ordinary" and verdict != "ALLOW":
                flagged_ordinary.append(_case_view(rec))
        elif status in ("unsupported", "error") and verdict is None:
            setattr(s, status, getattr(s, status) + 1)
            s.reasons[f"{status}:{rec.get('reason_code') or 'unspecified'}"] += 1
        else:
            s.invalid += 1  # never counted either way
            problems.append(f"{h}: record is neither a valid analysis nor a reasoned "
                            "unsupported/error; excluded from every rate")
    small = any(s.analysed < MIN_CASES for s in stats.values())
    if small and not allow_small:
        counts = ", ".join(f"{label}: {s.analysed}" for label, s in stats.items())
        raise ReportRefused(
            f"{results.path}: refusing to render a headline. Each label needs at least "
            f"{MIN_CASES} analysable cases and this file has {counts}. Run more cases (cases "
            "that are unsupported or errored do not count), or pass --allow-small to render it "
            "stamped SMALL SAMPLE.")
    return Report(results.path, header, mock, small, stats, alerting, missed, flagged_ordinary,
                  calls, units, problems)


# --------------------------------------------------------------------------- rendering

def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def _rate_line(stats: LabelStats, k: int, name: str) -> str:
    r = stats.rate(k)
    if r["n"] == 0:
        return f"  {name}: n/a (no analysable cases)"
    lo, hi = r["wilson95"]
    return f"  {name}: {k}/{r['n']} = {_pct(r['rate'])}  (Wilson 95% interval {_pct(lo)} to {_pct(hi)})"


LIMITS = (
    "What these numbers do not show:",
    "  - Only transactions the decoder recognises as V2/V3-style swaps and the node could serve "
    "at the pinned block are analysed; aggregator and unrecognised routes are excluded, so "
    "the rates describe that slice, not all swaps.",
    "  - State is read at the end of block N-1 for a transaction mined in block N. A front-run "
    "inside block N is invisible and intra-block ordering is not reproduced. The report cannot "
    "tell you what a wallet would have shown, only what the rules say at that boundary.",
    "  - The labels come from whoever supplied the file. Label noise (a sandwich dataset's false "
    "positives, an unnoticed attack among the 'ordinary' cases) moves both rates, and cases "
    "chosen because they were notable are not a random sample of swaps.",
    "  - A detection is a WARN or BLOCK for any reason, not proof the rule that fired is the "
    "reason the swap was attacked; read the per-rule table and the lists of cases above.",
    "  - Confidence intervals assume independent cases drawn from one population; they do not "
    "cover label noise, selection bias or the pinned-state approximation.",
    "  - Thresholds are the author's defaults and were not tuned on these cases.",
)


def render_text(rep: Report) -> str:
    h = rep.header
    out: list[str] = [rep.title, "=" * len(rep.title), ""]
    if rep.mock:
        out += ["MOCK: produced against the in-repo fake node. This says nothing about real "
                "transactions.", ""]
    if rep.small_sample:
        out += [f"SMALL SAMPLE: fewer than {MIN_CASES} analysable cases for at least one label. "
                "Treat every rate below as an anecdote.", ""]
    out += [f"results file : {Path(rep.path).name}",
            f"created      : {h.get('created_utc')} (txwarden {h.get('txwarden_version')})",
            f"node         : {h.get('client_version') or 'unknown'}, chain id {h.get('chain_id')}, "
            f"head block {h.get('head_block')}",
            f"cases file   : {h.get('cases_file')} (sha256 {str(h.get('cases_sha256'))[:12]}...)",
            f"RPC cost     : {rep.rpc_calls} requests, {rep.units:g} units across the recorded cases",
            ""]
    s, o = rep.labels["sandwiched"], rep.labels["ordinary"]
    out += ["Headline (analysable cases only)", "--------------------------------",
            "Detection on cases labelled sandwiched",
            _rate_line(s, s.flagged, "WARN or BLOCK"), _rate_line(s, s.blocked, "BLOCK only"),
            "False positives on cases labelled ordinary",
            _rate_line(o, o.flagged, "WARN or BLOCK"), _rate_line(o, o.blocked, "BLOCK only"), ""]

    out += ["Denominators: every case in the results file", "-----------------------------------------"]
    rows = [("label", "in file", "recorded", "analysed", "unsupported", "error", "invalid")]
    rows.extend((st.label, "?" if st.expected is None else str(st.expected), str(st.recorded),
                 str(st.analysed), str(st.unsupported), str(st.error), str(st.invalid))
                for st in rep.labels.values())
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    out += [("  " + "  ".join(c.ljust(w) for c, w in zip(r, widths))).rstrip() for r in rows]
    for st in rep.labels.values():
        if st.not_run:
            out.append(f"  WARNING: {st.not_run} {st.label} case(s) in the input file have no "
                       "result yet; the run is incomplete.")
    out.append("  Unsupported and error cases are never counted as detected, missed, correct or wrong.")
    out.append("")

    out += ["Why cases were not analysed", "---------------------------"]
    any_reason = False
    for st in rep.labels.values():
        for reason, n in sorted(st.reasons.items(), key=lambda kv: (-kv[1], kv[0])):
            any_reason = True
            out.append(f"  {st.label:<10} {reason}: {n}")
    out += [] if any_reason else ["  (none)"]
    out.append("")

    out += ["Verdicts", "--------"]
    for st in rep.labels.values():
        out.append(f"  {st.label:<10} " + ", ".join(f"{v} {st.verdicts[v]}" for v in VERDICTS))
    out.append("")

    out += ["Rules fired (analysed cases; * = decided a verdict in at least one case)",
            "------------------------------------------------------------------"]
    rules = sorted(set(s.rule_hits) | set(o.rule_hits),
                   key=lambda r: (-(s.rule_hits[r] + o.rule_hits[r]), r))
    if rules:
        w = max(len(r) for r in rules) + 2
        out.append(f"  {'rule'.ljust(w)}{'sandwiched':>12}{'ordinary':>10}")
        for r in rules:
            name = r + (" *" if r in rep.alerting else "")
            out.append(f"  {name.ljust(w)}{s.rule_hits[r]:>12}{o.rule_hits[r]:>10}")
    else:
        out.append("  (no rules fired)")
    out.append("")

    out += [f"Missed: sandwiched cases the engine allowed ({len(rep.missed)})",
            "--------------------------------------------------"]
    out += [_case_line(c) for c in rep.missed] or ["  (none)"]
    out += ["", f"False positives: ordinary cases flagged WARN or BLOCK ({len(rep.false_positives)})",
            "--------------------------------------------------------"]
    out += [_case_line(c) for c in rep.false_positives] or ["  (none)"]
    out.append("")
    if rep.problems:
        out += ["Problems found while reading the file", "-------------------------------------"]
        out += [f"  {p}" for p in rep.problems[:20]]
        out.append("")
    out += list(LIMITS)
    return "\n".join(out) + "\n"


def _case_line(c: dict[str, Any]) -> str:
    fired = ", ".join(c.get("rules", [])) or "no rule fired"
    where = f"block {c['block']}, pinned {c['pinned_block']}" if "block" in c else "no block"
    reason = f"verdict {c['verdict']} ({fired})"
    return f"  {c['tx_hash']}  {where}: {reason}" + (f"  [{c['source']}]" if c.get("source") else "")


def report_dict(rep: Report) -> dict[str, Any]:
    s, o = rep.labels["sandwiched"], rep.labels["ordinary"]
    return {
        "title": rep.title, "mock": rep.mock, "small_sample": rep.small_sample,
        "min_cases": MIN_CASES, "results_file": Path(rep.path).name, "header": rep.header,
        "headline": {
            "detection_warn_or_block": s.rate(s.flagged), "detection_block_only": s.rate(s.blocked),
            "false_positive_warn_or_block": o.rate(o.flagged),
            "false_positive_block_only": o.rate(o.blocked),
        },
        "labels": {label: {
            "expected": st.expected, "recorded": st.recorded, "analysed": st.analysed,
            "unsupported": st.unsupported, "error": st.error, "invalid": st.invalid,
            "verdicts": {v: st.verdicts[v] for v in VERDICTS}, "reasons": dict(st.reasons),
            "not_run": st.not_run,
        } for label, st in rep.labels.items()},
        "rules": {r: {"sandwiched": s.rule_hits[r], "ordinary": o.rule_hits[r],
                      "decided_a_verdict": r in rep.alerting}
                  for r in sorted(set(s.rule_hits) | set(o.rule_hits))},
        "missed_sandwiched": rep.missed, "flagged_ordinary": rep.false_positives,
        "rpc_calls": rep.rpc_calls, "units": rep.units, "problems": rep.problems,
        "limits": [x.strip(" -") for x in LIMITS[1:]],
    }


def render_json(rep: Report) -> str:
    return json.dumps(report_dict(rep), indent=2) + "\n"


def report_from_file(path: str | Path, *, allow_mock: bool = False,
                     allow_small: bool = False) -> Report:
    return build_report(read_results(path), allow_mock=allow_mock, allow_small=allow_small)


# --------------------------------------------------------------------------- README status

def committed_real_results(results_dir: str | Path) -> list[Path]:
    """Non-MOCK results files in ``results_dir`` (the files the README may quote)."""
    d = Path(results_dir)
    found: list[Path] = []
    for p in sorted(d.glob("*.jsonl")) if d.is_dir() else []:
        if "MOCK" in p.name:
            continue
        try:
            r = read_results(p)
        except (OSError, UnicodeDecodeError):
            continue
        if (r.header and str(r.header.get("format", "")).startswith("txwarden-replay/")
                and not r.mock and r.cases):
            found.append(p)
    return found


def status_markdown(results_dir: str | Path) -> str:
    """The README's real-chain status, derived from what is committed under ``results/``.

    With no non-MOCK results file it says so plainly; otherwise it quotes the numbers
    ``replay-report`` computes from each file (and says SMALL SAMPLE when that applies), so the
    claim can never run ahead of the evidence."""
    files = committed_real_results(results_dir)
    if not files:
        return ("**Real-chain results: NOT YET RUN.** No non-MOCK results file is committed under "
                "`results/`. Every number elsewhere in this README comes from synthetic data or "
                "from the in-memory fake node.")
    lines = ["**Real-chain results** (computed from the committed files by `txwarden "
             "replay-report`, not typed by hand):", ""]
    for p in files:
        rep = report_from_file(p, allow_small=True)
        s, o = rep.labels["sandwiched"], rep.labels["ordinary"]

        def fmt(st: LabelStats, k: int) -> str:
            r = st.rate(k)
            if not r["n"]:
                return "n/a"
            lo, hi = r["wilson95"]
            return f"{k}/{r['n']} ({_pct(r['rate'])}, 95% interval {_pct(lo)} to {_pct(hi)})"

        lines.append(
            f"- `results/{p.name}`: sandwiched cases flagged WARN or BLOCK {fmt(s, s.flagged)}, "
            f"{s.unsupported} unsupported and {s.error} error excluded; ordinary cases flagged "
            f"WARN or BLOCK {fmt(o, o.flagged)}, {o.unsupported} unsupported and {o.error} "
            "error excluded."
            + (" **SMALL SAMPLE.**" if rep.small_sample else ""))
    return "\n".join(lines)
