"""Wilson intervals, the headline numbers and the rules for refusing to print them."""
import io
import json
import math
import random
from contextlib import redirect_stderr

import pytest

from txwarden.cli import main
from txwarden.replay import read_results
from txwarden.replay_report import (
    MIN_CASES,
    ReportRefused,
    build_report,
    committed_real_results,
    render_json,
    render_text,
    report_from_file,
    status_markdown,
    wilson,
)

from .fake_history import fake_hash
from .replay_world import build_world


def cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stderr(err):
        code = main(list(argv), out)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- Wilson interval

# Reference values: roots of (1 + z^2/n) p^2 - (2 k/n + z^2/n) p + (k/n)^2 = 0 with z = 1.959964,
# solved separately from the closed form in the code. Spot checks by hand: for k=0, n=10 the upper
# bound is z^2 / (n + z^2) = 3.841459 / 13.841459 = 0.277533, and for k=n the lower bound is
# n / (n + z^2) = 0.722467.
WILSON_REFERENCE = [
    (5, 10, 0.236593, 0.763407), (0, 10, 0.0, 0.277533), (10, 10, 0.722467, 1.0),
    (1, 10, 0.017876, 0.404150), (30, 100, 0.218949, 0.395849), (95, 100, 0.888250, 0.978456),
    (0, 30, 0.0, 0.113513), (15, 30, 0.331541, 0.668459), (29, 30, 0.833296, 0.994091),
    (1, 2, 0.094531, 0.905469), (3, 7, 0.158220, 0.749542),
]


@pytest.mark.parametrize("k,n,lo,hi", WILSON_REFERENCE)
def test_wilson_matches_hand_computed_values(k, n, lo, hi):
    got_lo, got_hi = wilson(k, n)
    assert got_lo == pytest.approx(lo, abs=5e-7) and got_hi == pytest.approx(hi, abs=5e-7)


def test_wilson_of_zero_trials_is_undefined():
    assert wilson(0, 0) is None


@pytest.mark.parametrize("k,n", [(-1, 5), (6, 5)])
def test_wilson_rejects_impossible_counts(k, n):
    with pytest.raises(ValueError):
        wilson(k, n)


def test_wilson_is_symmetric_and_bounded():
    rng = random.Random(7)
    for _ in range(300):
        n = rng.randint(1, 500)
        k = rng.randint(0, n)
        lo, hi = wilson(k, n)
        mlo, mhi = wilson(n - k, n)
        assert 0 <= lo <= k / n <= hi <= 1, (k, n)
        assert lo == pytest.approx(1 - mhi, abs=1e-12) and hi == pytest.approx(1 - mlo, abs=1e-12)


def test_wilson_narrows_with_more_data():
    widths = [wilson(n // 2, n)[1] - wilson(n // 2, n)[0] for n in (10, 40, 160, 640)]
    assert widths == sorted(widths, reverse=True)
    assert widths[-1] < 0.08


def test_wilson_agrees_with_an_independent_root_finder():
    z = 1.959963984540054
    rng = random.Random(11)
    for _ in range(200):
        n = rng.randint(1, 400)
        k = rng.randint(0, n)
        p = k / n
        a, b, c = 1 + z * z / n, -(2 * p + z * z / n), p * p
        disc = math.sqrt(max(0.0, b * b - 4 * a * c))
        lo, hi = max(0.0, (-b - disc) / (2 * a)), min(1.0, (-b + disc) / (2 * a))
        got = wilson(k, n)
        assert got[0] == pytest.approx(lo, abs=1e-9) and got[1] == pytest.approx(hi, abs=1e-9)


def test_wilson_does_not_collapse_at_the_extremes_like_the_normal_approximation():
    lo, hi = wilson(0, 20)
    assert lo == 0 and hi > 0.15
    lo, hi = wilson(20, 20)
    assert hi == 1 and lo < 0.85


# --------------------------------------------------------------------------- synthetic results

def make_rec(n, label, status="analysed", verdict="ALLOW", rules=(), alerting=(), code=None,
             **extra):
    rec = {"type": "case", "tx_hash": fake_hash(n), "label": label, "status": status,
           "verdict": verdict if status == "analysed" else None, "block": 200 + n,
           "pinned_block": 199 + n, "rpc_calls": 10, "cache_hits": 0, "units": 16,
           "elapsed_s": 0.1, "methods": {}}
    if status == "analysed":
        rec.update(rules=list(rules), alerting_rules=list(alerting), degraded=[])
    else:
        rec.update(reason_code=code or "not_a_swap", reason="why")
    rec.update(extra)
    return rec


def header(mock=False, case_counts=None, **extra):
    h = {"type": "header", "format": "txwarden-replay/1", "mock": mock,
         "created_utc": "2026-02-01T00:00:00+00:00", "txwarden_version": "0.2.0",
         "endpoint": "rpc endpoint", "client_version": "Geth/test", "chain_id": 1,
         "head_block": 5000, "cases_file": "cases.csv", "cases_sha256": "ab" * 32,
         "case_counts": case_counts}
    if case_counts is None:
        h.pop("case_counts")
    h.update(extra)
    return h


def write(tmp_path, records, hdr=None, name="results.jsonl"):
    p = tmp_path / name
    head = [] if hdr is False else [hdr or header()]
    p.write_text("\n".join(json.dumps(x) for x in head + records) + "\n")
    return p


def population(sand=(20, 8, 4), ordi=(25, 3, 2), unsupported=(6, 5), errors=(2, 1)):
    """sand/ordi = (ALLOW, WARN, BLOCK) counts; plus unsupported and error cases per label."""
    recs, n = [], 0
    for label, (allow, warn, block), unsup, err in (("sandwiched", sand, unsupported[0], errors[0]),
                                                    ("ordinary", ordi, unsupported[1], errors[1])):
        for verdict, count in (("ALLOW", allow), ("WARN", warn), ("BLOCK", block)):
            for _ in range(count):
                n += 1
                alert = ["SANDWICH_EXPOSURE"] if verdict == "WARN" else (
                    ["SLIPPAGE_TOLERANCE_EXTREME"] if verdict == "BLOCK" else [])
                recs.append(make_rec(n, label, verdict=verdict,
                                     rules=[*alert, "CHECKS_SKIPPED"], alerting=alert))
        for _ in range(unsup):
            n += 1
            recs.append(make_rec(n, label, "unsupported", code="not_a_swap"))
        for _ in range(err):
            n += 1
            recs.append(make_rec(n, label, "error", code="rate_limited"))
    return recs


# --------------------------------------------------------------------------- the numbers

def test_rates_use_only_analysable_cases(tmp_path):
    p = write(tmp_path, population())
    rep = report_from_file(p)
    s, o = rep.labels["sandwiched"], rep.labels["ordinary"]
    assert (s.analysed, s.flagged, s.blocked) == (32, 12, 4)
    assert (o.analysed, o.flagged, o.blocked) == (30, 5, 2)
    assert (s.unsupported, s.error, o.unsupported, o.error) == (6, 2, 5, 1)
    rates = json.loads(render_json(rep))["headline"]
    assert rates["detection_warn_or_block"]["k"] == 12 and rates["detection_warn_or_block"]["n"] == 32
    assert rates["detection_warn_or_block"]["rate"] == pytest.approx(12 / 32)
    assert rates["detection_block_only"]["k"] == 4
    assert rates["false_positive_warn_or_block"]["rate"] == pytest.approx(5 / 30)
    assert rates["false_positive_block_only"]["k"] == 2
    assert rates["detection_warn_or_block"]["wilson95"] == list(wilson(12, 32))
    assert rates["false_positive_warn_or_block"]["wilson95"] == list(wilson(5, 30))


def test_unanalysed_cases_never_change_a_rate(tmp_path):
    base = report_from_file(write(tmp_path, population(), name="a.jsonl"))
    more = report_from_file(write(tmp_path, population(unsupported=(500, 500), errors=(80, 80)),
                                  name="b.jsonl"))
    for label in ("sandwiched", "ordinary"):
        a, b = base.labels[label], more.labels[label]
        assert (a.analysed, a.flagged, a.blocked) == (b.analysed, b.flagged, b.blocked)
    assert more.labels["sandwiched"].unsupported == 500 and more.labels["ordinary"].error == 80


def test_text_report_shows_every_denominator_and_the_reasons(tmp_path):
    text = render_text(report_from_file(write(tmp_path, population())))
    assert "12/32 = 37.5%" in text and "5/30 = 16.7%" in text and "4/32 = 12.5%" in text
    assert "Wilson 95% interval" in text
    row = next(line for line in text.splitlines() if line.strip().startswith("sandwiched ")
               and "40" in line)
    assert row.split() == ["sandwiched", "?", "40", "32", "6", "2", "0"]
    assert "sandwiched unsupported:not_a_swap: 6" in " ".join(text.split())
    assert "ordinary error:rate_limited: 1" in " ".join(text.split())
    assert "never counted as detected, missed, correct or wrong" in text


def test_missed_sandwiched_cases_are_listed_with_hash_and_reason(tmp_path):
    recs = population()
    rep = report_from_file(write(tmp_path, recs))
    allowed = [r for r in recs if r["label"] == "sandwiched" and r["verdict"] == "ALLOW"]
    assert [m["tx_hash"] for m in rep.missed] == [r["tx_hash"] for r in allowed]
    assert all(m["verdict"] == "ALLOW" for m in rep.missed) and len(rep.missed) == 20
    text = render_text(rep)
    assert "Missed: sandwiched cases the engine allowed (20)" in text
    assert f"{allowed[0]['tx_hash']}  block 201, pinned 200: verdict ALLOW (CHECKS_SKIPPED)" in text


def test_unanalysed_sandwiched_cases_are_not_in_the_missed_list(tmp_path):
    rep = report_from_file(write(tmp_path, population()))
    assert all(m["verdict"] == "ALLOW" for m in rep.missed)
    assert not any(m.get("reason_code") for m in rep.missed)


def test_flagged_ordinary_cases_are_listed(tmp_path):
    rep = report_from_file(write(tmp_path, population()))
    assert len(rep.false_positives) == 5
    assert {f["verdict"] for f in rep.false_positives} == {"WARN", "BLOCK"}


def test_per_rule_hits_count_cases_not_occurrences(tmp_path):
    rep = report_from_file(write(tmp_path, population()))
    s, o = rep.labels["sandwiched"], rep.labels["ordinary"]
    assert s.rule_hits["SANDWICH_EXPOSURE"] == 8 and s.rule_hits["SLIPPAGE_TOLERANCE_EXTREME"] == 4
    assert o.rule_hits["SANDWICH_EXPOSURE"] == 3 and o.rule_hits["CHECKS_SKIPPED"] == 30
    assert "SANDWICH_EXPOSURE" in rep.alerting and "CHECKS_SKIPPED" not in rep.alerting
    text = render_text(rep)
    assert "SANDWICH_EXPOSURE *" in text and "CHECKS_SKIPPED *" not in text


def test_totals_of_rpc_cost_come_from_the_file(tmp_path):
    rep = report_from_file(write(tmp_path, population()))
    assert rep.rpc_calls == 10 * 76 and rep.units == 16 * 76


def test_incomplete_runs_are_called_out(tmp_path):
    p = write(tmp_path, population(), hdr=header(case_counts={"sandwiched": 100, "ordinary": 30}))
    rep = report_from_file(p)
    assert rep.labels["sandwiched"].not_run == 60 and rep.labels["ordinary"].not_run == 0
    assert "WARNING: 60 sandwiched case(s) in the input file have no result yet" in render_text(rep)


def test_records_that_are_not_valid_analyses_are_excluded_and_reported(tmp_path):
    recs = population()
    recs.append({**make_rec(900, "sandwiched"), "verdict": None})            # analysed, no verdict
    recs.append({**make_rec(901, "ordinary", "unsupported"), "verdict": "WARN"})  # reasoned but with a verdict
    recs.append({**make_rec(902, "ordinary"), "verdict": "MAYBE"})
    recs.append(make_rec(903, "weird"))
    rep = report_from_file(write(tmp_path, recs))
    assert rep.labels["sandwiched"].invalid == 1 and rep.labels["ordinary"].invalid == 2
    assert rep.labels["sandwiched"].analysed == 32 and rep.labels["ordinary"].analysed == 30
    assert any("unknown label" in p for p in rep.problems) and len(rep.problems) == 4
    assert "Problems found while reading the file" in render_text(rep)


def test_a_label_with_no_analysable_cases_has_no_rate(tmp_path):
    recs = [make_rec(i, "ordinary") for i in range(1, 40)]
    rep = report_from_file(write(tmp_path, recs), allow_small=True)
    assert rep.labels["sandwiched"].analysed == 0
    text = render_text(rep)
    assert "n/a (no analysable cases)" in text
    assert json.loads(render_json(rep))["headline"]["detection_warn_or_block"]["rate"] is None


def test_text_always_carries_the_limitations(tmp_path):
    text = render_text(report_from_file(write(tmp_path, population())))
    for needle in ("What these numbers do not show", "label noise", "not a random sample",
                   "end of block N-1", "intra-block ordering is not reproduced",
                   "recognises as V2/V3-style swaps"):
        assert needle in text, needle
    assert json.loads(render_json(report_from_file(write(tmp_path, population(), name="x.jsonl"))
                                  ))["limits"]


# --------------------------------------------------------------------------- refusals

def test_each_label_needs_thirty_analysable_cases(tmp_path):
    exactly = population(sand=(10, 10, 10), ordi=(10, 10, 10))
    assert report_from_file(write(tmp_path, exactly)).small_sample is False
    short = population(sand=(10, 10, 9), ordi=(10, 10, 10))
    with pytest.raises(ReportRefused) as e:
        report_from_file(write(tmp_path, short, name="s.jsonl"))
    assert "sandwiched: 29, ordinary: 30" in str(e.value) and "--allow-small" in str(e.value)
    assert MIN_CASES == 30


def test_the_other_label_being_short_also_refuses(tmp_path):
    with pytest.raises(ReportRefused, match="ordinary: 29"):
        report_from_file(write(tmp_path, population(sand=(30, 0, 0), ordi=(29, 0, 0))))


def test_cases_that_were_not_analysed_do_not_count_toward_the_thirty(tmp_path):
    recs = population(sand=(10, 10, 9), unsupported=(500, 0))
    with pytest.raises(ReportRefused, match="sandwiched: 29"):
        report_from_file(write(tmp_path, recs))


def test_allow_small_renders_and_stamps_everything(tmp_path):
    rep = report_from_file(write(tmp_path, population(sand=(5, 2, 1), ordi=(7, 1, 0))),
                           allow_small=True)
    assert rep.small_sample and rep.title == "TxWarden replay report - SMALL SAMPLE"
    text = render_text(rep)
    assert text.splitlines()[0] == rep.title and "SMALL SAMPLE: fewer than 30" in text
    data = json.loads(render_json(rep))
    assert data["small_sample"] is True and data["title"] == rep.title
    assert rep.output_path("out/report.md").name == "report.SMALL-SAMPLE.md"


def test_mock_results_are_refused_unless_allowed(tmp_path):
    p = write(tmp_path, population(), hdr=header(mock=True))
    with pytest.raises(ReportRefused) as e:
        report_from_file(p)
    assert "MOCK" in str(e.value) and "--allow-mock" in str(e.value)
    rep = report_from_file(p, allow_mock=True)
    assert rep.mock and rep.title == "TxWarden replay report - MOCK"
    assert render_text(rep).splitlines()[0] == rep.title and "fake node" in render_text(rep)
    assert json.loads(render_json(rep))["mock"] is True
    assert rep.output_path("out/report.md").name == "report.MOCK.md"


def test_mock_and_small_stamp_together(tmp_path):
    p = write(tmp_path, population(sand=(3, 0, 0), ordi=(3, 0, 0)), hdr=header(mock=True))
    rep = report_from_file(p, allow_mock=True, allow_small=True)
    assert rep.title == "TxWarden replay report - MOCK - SMALL SAMPLE"
    assert rep.output_path("report.json").name == "report.MOCK.SMALL-SAMPLE.json"


def test_allow_mock_alone_does_not_waive_the_sample_size(tmp_path):
    p = write(tmp_path, population(sand=(3, 0, 0), ordi=(3, 0, 0)), hdr=header(mock=True))
    with pytest.raises(ReportRefused, match="at least 30"):
        report_from_file(p, allow_mock=True)


def test_allow_small_alone_does_not_waive_mock(tmp_path):
    p = write(tmp_path, population(), hdr=header(mock=True))
    with pytest.raises(ReportRefused, match="MOCK"):
        report_from_file(p, allow_small=True)


def test_a_file_without_a_header_is_refused_because_mock_cannot_be_ruled_out(tmp_path):
    p = write(tmp_path, population(), hdr=False)
    with pytest.raises(ReportRefused, match="no header line"):
        report_from_file(p, allow_mock=True, allow_small=True)


def test_a_file_of_another_format_is_refused(tmp_path):
    p = write(tmp_path, population(), hdr={**header(), "format": "something/else"})
    with pytest.raises(ReportRefused, match="not a txwarden-replay/1 results file"):
        report_from_file(p)


def test_a_file_with_no_cases_is_refused(tmp_path):
    with pytest.raises(ReportRefused, match="no case results"):
        report_from_file(write(tmp_path, []))


def test_a_clean_real_file_has_no_stamps(tmp_path):
    rep = report_from_file(write(tmp_path, population()))
    assert not rep.mock and not rep.small_sample and rep.title == "TxWarden replay report"
    text = render_text(rep)
    assert "MOCK" not in text and "SMALL SAMPLE" not in text
    assert rep.output_path("r.md").name == "r.md"


def test_the_last_record_for_a_hash_is_the_one_counted(tmp_path):
    recs = population()
    first = dict(recs[0])
    first["status"], first["verdict"] = "error", None
    first["reason_code"], first["reason"] = "rpc_error", "was flaky"
    p = write(tmp_path, [first, *recs])
    rep = report_from_file(p)
    assert rep.labels["sandwiched"].analysed == 32 and rep.labels["sandwiched"].error == 2


# --------------------------------------------------------------------------- the CLI

def run_world(tmp_path):
    from txwarden.redact import Redactor
    from txwarden.replay import ReplayConfig, Replayer, parse_cases
    from txwarden.risk import PolicyConfig
    from txwarden.simulator import SimulatorOptions

    from .fake_history import FakeClock

    w = build_world()
    cfg = ReplayConfig(out_path=tmp_path / "results.jsonl", cache_dir=None, rps=10_000)
    return Replayer(parse_cases(w.csv(), "c.csv"), w.chain.rpc, cfg, PolicyConfig(),
                    SimulatorOptions(), Redactor(), clock=FakeClock()).run().out_path


def test_cli_refuses_results_from_the_fake_node(tmp_path):
    path = run_world(tmp_path)
    assert path.name == "results.MOCK.jsonl"
    code, out, err = cli("replay-report", str(path))
    assert code == 3 and out == "" and "MOCK" in err and "--allow-mock" in err


def test_cli_still_refuses_a_small_mock_sample_with_only_allow_mock(tmp_path):
    code, _out, err = cli("replay-report", str(run_world(tmp_path)), "--allow-mock")
    assert code == 3 and "at least 30" in err and "sandwiched: 3, ordinary: 3" in err


def test_cli_renders_a_stamped_mock_report_when_both_flags_are_given(tmp_path):
    path = run_world(tmp_path)
    code, out, _err = cli("replay-report", str(path), "--allow-mock", "--allow-small")
    assert code == 0 and out.splitlines()[0] == "TxWarden replay report - MOCK - SMALL SAMPLE"
    assert "2/3 = 66.7%" in out and "1/3 = 33.3%" in out  # detection 2 of 3; false positives 1 of 3
    assert "Missed: sandwiched cases the engine allowed (1)" in out
    assert fake_hash(3) in out


def test_cli_writes_the_stamped_file_name(tmp_path):
    path = run_world(tmp_path)
    target = tmp_path / "out" / "report.md"
    code, out, _ = cli("replay-report", str(path), "--allow-mock", "--allow-small", "--out",
                       str(target))
    written = tmp_path / "out" / "report.MOCK.SMALL-SAMPLE.md"
    assert code == 0 and written.exists() and not target.exists()
    assert f"wrote {written}" in out and written.read_text().startswith("TxWarden replay report")


def test_cli_json_output(tmp_path):
    path = run_world(tmp_path)
    code, out, _ = cli("replay-report", str(path), "--allow-mock", "--allow-small", "--json")
    data = json.loads(out)
    assert code == 0 and data["mock"] and data["small_sample"]
    assert data["labels"]["sandwiched"]["analysed"] == 3 and data["labels"]["ordinary"]["analysed"] == 3
    sand, ordi = data["labels"]["sandwiched"], data["labels"]["ordinary"]
    assert (sand["unsupported"], sand["error"], ordi["unsupported"], ordi["error"]) == (2, 1, 2, 1)


def test_cli_real_sized_file_renders_without_flags(tmp_path):
    p = write(tmp_path, population())
    code, out, err = cli("replay-report", str(p))
    assert code == 0 and err == "" and out.startswith("TxWarden replay report\n")


def test_cli_missing_file(tmp_path):
    code, _, err = cli("replay-report", str(tmp_path / "nope.jsonl"))
    assert code == 3 and "error:" in err


def test_the_report_is_computed_from_the_file_alone(tmp_path):
    """Deleting the cases file and the cache changes nothing: only the results are read."""
    path = run_world(tmp_path)
    a = render_text(build_report(read_results(path), allow_mock=True, allow_small=True))
    for f in tmp_path.iterdir():
        if f != path:
            f.unlink() if f.is_file() else None
    b = render_text(build_report(read_results(path), allow_mock=True, allow_small=True))
    assert a == b


# --------------------------------------------------------------------------- README status

def test_status_says_not_yet_run_without_a_results_directory(tmp_path):
    text = status_markdown(tmp_path / "results")
    assert text.startswith("**Real-chain results: NOT YET RUN.**") and "`results/`" in text


def test_status_ignores_mock_files_and_files_that_are_not_results(tmp_path):
    d = tmp_path / "results"
    d.mkdir()
    write(d, population(), hdr=header(mock=True), name="run.jsonl")          # MOCK in the header
    write(d, population(), hdr=header(mock=True), name="run.MOCK.jsonl")     # MOCK in the name
    (d / "other.jsonl").write_text('{"just": "some data"}\n')
    (d / "noheader.jsonl").write_text(json.dumps(population()[0]) + "\n")
    (d / "empty.jsonl").write_text("")
    (d / "binary.jsonl").write_bytes(b"\xff\xfe\x00")
    (d / "notes.md").write_text("hello")
    assert committed_real_results(d) == []
    assert "NOT YET RUN" in status_markdown(d)


def test_status_quotes_the_numbers_computed_from_a_real_file(tmp_path):
    d = tmp_path / "results"
    d.mkdir()
    write(d, population(), name="replay.jsonl")
    text = status_markdown(d)
    assert "NOT YET RUN" not in text and "`results/replay.jsonl`" in text
    assert "12/32 (37.5%, 95% interval" in text and "5/30 (16.7%, 95% interval" in text
    assert "6 unsupported and 2 error excluded" in text and "SMALL SAMPLE" not in text


def test_status_flags_a_small_real_file(tmp_path):
    d = tmp_path / "results"
    d.mkdir()
    write(d, population(sand=(3, 1, 0), ordi=(4, 0, 0)), name="replay.jsonl")
    assert "**SMALL SAMPLE.**" in status_markdown(d)


def test_status_handles_a_label_with_no_analysable_cases(tmp_path):
    d = tmp_path / "results"
    d.mkdir()
    write(d, [make_rec(i, "ordinary") for i in range(1, 5)], name="replay.jsonl")
    assert "sandwiched cases flagged WARN or BLOCK n/a" in status_markdown(d)
