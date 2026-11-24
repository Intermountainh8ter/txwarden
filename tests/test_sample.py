"""``txwarden sample-ordinary``: random ordinary swaps from a node, for the false-positive half.

Everything runs against the in-repo fake archive node (hashes, addresses and state are synthetic).
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from txwarden.cli import SUBCOMMANDS, build_parser, main
from txwarden.redact import Redactor
from txwarden.replay import ReplayError, load_cases, read_results
from txwarden.sample import (
    SampleConfig,
    render_csv,
    sample_ordinary,
    source_tag,
    write_csv,
)
from txwarden.simulator import RpcError, SimulatorOptions

from . import replay_world as rw
from .fake_history import FakeClock, fake_hash
from .fake_rpc import FakeRpcServer
from .replay_world import build_world

KEY = "sk_live_Zx81QpLm0aa93kd7"  # a fake API key; the tests assert it never comes back out

# what build_world() puts on chain: recognised swaps are in block 200 (7 of them) and block 400
# (the one that reverts at the pin); the approval, contract creation, pending tx and unknown hash
# are not swaps the decoder recognises or are not in any block
SWAPS_200 = {rw.LOOSE_SANDWICHED, rw.MODERATE_SANDWICHED, rw.TIGHT_SANDWICHED, rw.TIGHT_ORDINARY,
             rw.TIGHT_ORDINARY_2, rw.LOOSE_ORDINARY, rw.NO_POOL}
SWAPS_400 = {rw.REVERTS}
ALL_SWAPS = {fake_hash(n) for n in SWAPS_200 | SWAPS_400}
NOT_SWAPS = {fake_hash(n) for n in (rw.NOT_A_SWAP, rw.NOT_FOUND, rw.CREATION, rw.PENDING)}


def new_world():
    """The replay test world plus a state at block 1, so the node can serve every early block."""
    world = build_world()
    world.chain.set_state(1, rw.base_state())
    return world


def cfg(**kw) -> SampleConfig:
    base = {"count": 8, "blocks": 400, "end_offset": 600, "per_block": 10, "max_blocks": 400,
            "seed": 1, "rps": 10_000.0}
    base.update(kw)
    return SampleConfig(**base)


def run(world=None, **kw):
    world = world or new_world()
    out = sample_ordinary(world.chain.rpc, cfg(**kw), SimulatorOptions(), Redactor(),
                          clock=FakeClock())
    return world, out


# --------------------------------------------------------------------------- what is sampled

def test_only_recognised_swaps_in_mined_blocks_are_sampled():
    _, out = run()
    got = {r.tx_hash for r in out.rows}
    assert got == ALL_SWAPS
    assert not got & NOT_SWAPS
    assert out.stopped == "completed"
    assert out.exit_code == 0


def test_rows_record_block_and_call_kind():
    _, out = run()
    by_hash = {r.tx_hash: r for r in out.rows}
    assert by_hash[fake_hash(rw.LOOSE_ORDINARY)].block == 200
    assert by_hash[fake_hash(rw.REVERTS)].block == 400
    assert all(r.call_kind for r in out.rows)


def test_per_block_caps_how_many_come_from_one_block():
    _, out = run(per_block=2, count=50)
    blocks = [r.block for r in out.rows]
    assert blocks.count(200) == 2 and blocks.count(400) == 1
    assert out.stopped == "window_exhausted"
    assert "only 3 swaps" in out.message


def test_count_stops_the_scan_early():
    world, out = run(count=1)
    assert len(out.rows) == 1 and out.stopped == "completed"
    fetched = [p for m, p in world.chain.log if m == "eth_getBlockByNumber"]
    assert len(fetched) < 400  # it did not walk the whole window


def test_blocks_are_requested_with_full_transactions_inside_the_window_only():
    world, out = run(blocks=300, end_offset=500)  # window 201..500 (head is 1000)
    assert out.window == (201, 500)
    fetched = [(int(p[0], 16), p[1]) for m, p in world.chain.log if m == "eth_getBlockByNumber"]
    assert fetched and all(full is True for _, full in fetched)
    assert all(201 <= n <= 500 for n, _ in fetched)
    assert len({n for n, _ in fetched}) == len(fetched)  # no block twice
    assert {r.tx_hash for r in out.rows} == {fake_hash(n) for n in SWAPS_400}  # block 200 is out


def test_the_window_never_reaches_the_head():
    world, _ = run(blocks=10_000, end_offset=256, max_blocks=10_000, count=1_000)
    newest = max(int(p[0], 16) for m, p in world.chain.log if m == "eth_getBlockByNumber")
    assert newest <= rw.HEAD - 256


def test_an_empty_window_is_an_error():
    with pytest.raises(ReplayError, match="window is empty"):
        run(end_offset=rw.HEAD)


# --------------------------------------------------------------------------- reproducibility

def test_the_same_seed_gives_the_same_sample_and_csv():
    a = run(per_block=1, count=2, seed=7)[1]
    b = run(per_block=1, count=2, seed=7)[1]
    assert [r.tx_hash for r in a.rows] == [r.tx_hash for r in b.rows]
    assert render_csv(cfg(per_block=1, count=2, seed=7), a) == \
        render_csv(cfg(per_block=1, count=2, seed=7), b)


def test_different_seeds_can_choose_different_swaps():
    picks = {tuple(sorted(r.tx_hash for r in run(per_block=1, count=2, seed=s)[1].rows))
             for s in range(1, 9)}
    assert len(picks) > 1


# --------------------------------------------------------------------------- the file

def test_the_csv_loads_as_an_all_ordinary_case_set(tmp_path):
    c = cfg()
    _, out = run()
    p = write_csv(tmp_path / "cases.csv", render_csv(c, out))
    cases = load_cases(p)
    assert cases.counts == {"sandwiched": 0, "ordinary": 8}
    assert {x.tx_hash for x in cases.cases} == ALL_SWAPS
    assert all(x.label == "ordinary" for x in cases.cases)


def test_every_row_says_where_it_came_from():
    c = cfg(seed=5)
    _, out = run(seed=5)
    tag = source_tag(c, out)
    for needle in ("rpc-sample", "seed=5", "window=1-400", f"head={rw.HEAD}", "per_block=10",
                   "MOCK-NODE"):
        assert needle in tag
    rows = render_csv(c, out).splitlines()
    assert rows[0] == "tx_hash,label,source,notes"
    assert all(tag in line and ",ordinary," in line for line in rows[1:])
    assert all("block " in line for line in rows[1:])


def test_rows_are_sorted_by_block_then_hash():
    _, out = run()
    lines = render_csv(cfg(), out).splitlines()[1:]
    blocks = [int(line.split("block ")[1].split(";")[0]) for line in lines]
    assert blocks == sorted(blocks)


def test_write_csv_will_not_replace_a_file_without_force(tmp_path):
    p = tmp_path / "cases.csv"
    p.write_text("keep me")
    with pytest.raises(ReplayError, match="already exists"):
        write_csv(p, "new")
    assert p.read_text() == "keep me"
    write_csv(p, "new", force=True)
    assert p.read_text() == "new"
    assert not [f for f in tmp_path.iterdir() if f.name.endswith(".tmp")]


# --------------------------------------------------------------------------- limits and failures

def test_a_call_budget_stops_cleanly_before_it_is_exceeded():
    _, out = run(budget_calls=5)  # 3 for the node check, then 2 blocks
    assert out.stopped == "budget"
    assert out.calls == 5
    assert "budget" in out.message


def test_a_budget_spent_on_the_node_check_is_reported_not_raised():
    _, out = run(budget_calls=2)
    assert out.stopped == "budget" and not out.rows and out.exit_code == 4


def test_max_blocks_ends_the_scan_and_says_so():
    _, out = run(max_blocks=3, count=8)
    assert out.stopped == "max_blocks"
    assert out.blocks_fetched == 3
    assert "--max-blocks 3" in out.message


def test_repeated_block_failures_stop_the_run():
    world = new_world()

    def flaky(method, params):
        if method == "eth_getBlockByNumber":
            raise RpcError("boom", -32000)
        return world.chain.rpc(method, params)

    out = sample_ordinary(flaky, cfg(), SimulatorOptions(), Redactor(), clock=FakeClock())
    assert out.stopped == "errors" and not out.rows and out.exit_code == 4


def test_one_failed_block_is_skipped():
    world = new_world()
    seen = {"n": 0}

    def once(method, params):
        if method == "eth_getBlockByNumber":
            seen["n"] += 1
            if seen["n"] == 1:
                raise RpcError("boom", -32000)
        return world.chain.rpc(method, params)

    out = sample_ordinary(once, cfg(), SimulatorOptions(), Redactor(), clock=FakeClock())
    assert out.stopped == "completed" and len(out.rows) == 8


def test_a_node_that_returns_hashes_instead_of_transactions_yields_nothing():
    world = new_world()

    def hashes_only(method, params):
        res = world.chain.rpc(method, params)
        if method == "eth_getBlockByNumber" and isinstance(res, dict):
            res["transactions"] = [t["hash"] for t in res.get("transactions", [])]
        return res

    out = sample_ordinary(hashes_only, cfg(), SimulatorOptions(), Redactor(), clock=FakeClock())
    assert not out.rows


@pytest.mark.parametrize("field,value", [("count", 0), ("blocks", 0), ("per_block", 0),
                                         ("max_blocks", 0), ("end_offset", -1), ("rps", 0)])
def test_nonsense_settings_are_refused(field, value):
    with pytest.raises(ReplayError):
        run(**{field: value})


# --------------------------------------------------------------------------- through the CLI

def cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err):
        code = main(list(argv), out)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture()
def node(monkeypatch):
    world = new_world()
    with FakeRpcServer(world.chain.rpc) as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/v2/{KEY}")
        yield world, srv


def sample_args(tmp_path: Path, *extra: str) -> list[str]:
    return ["sample-ordinary", "--out", str(tmp_path / "cases.csv"), "--blocks", "400",
            "--end-offset", "600", "--per-block", "10", "--count", "8", "--rps", "10000", *extra]


def test_sample_ordinary_is_registered_and_has_no_url_flag():
    assert "sample-ordinary" in SUBCOMMANDS
    sub = next(a for a in build_parser()._actions if a.dest == "cmd").choices["sample-ordinary"]
    options = {o for a in sub._actions for o in a.option_strings}
    assert "--rpc" not in options and "--rpc-env" in options


def test_cli_writes_the_cases_and_never_prints_the_key(tmp_path, node):
    code, out, err = cli(*sample_args(tmp_path))
    assert code == 0, err
    assert KEY not in out + err
    assert "wrote 8 ordinary cases" in out
    assert "not verified clean" in out
    text = (tmp_path / "cases.csv").read_text()
    assert KEY not in text
    assert load_cases(tmp_path / "cases.csv").counts == {"sandwiched": 0, "ordinary": 8}
    assert "MOCK" in out


def test_cli_refuses_to_overwrite_and_leaves_the_file(tmp_path, node):
    p = tmp_path / "cases.csv"
    p.write_text("keep me")
    code, _, err = cli(*sample_args(tmp_path))
    assert code == 3 and "already exists" in err
    assert p.read_text() == "keep me"
    code, _, _ = cli(*sample_args(tmp_path, "--force"))
    assert code == 0 and p.read_text().startswith("tx_hash,label")


def test_cli_exits_4_and_writes_nothing_when_no_swap_was_found(tmp_path, node):
    code, out, _ = cli(*sample_args(tmp_path, "--blocks", "10", "--end-offset", "990"))
    assert code == 4
    assert not (tmp_path / "cases.csv").exists()
    assert "0 of 8 swaps" in out


def test_cli_refuses_an_rpc_url_argument_without_echoing_it(tmp_path):
    code, _, err = cli("sample-ordinary", f"https://example.invalid/{KEY}")
    assert code == 3 and KEY not in err and "environment variable" in err
    code, _, err = cli("sample-ordinary", "--rpc", KEY)
    assert code == 3 and KEY not in err


def test_cli_does_not_echo_a_mistyped_flag(tmp_path):
    with pytest.raises(SystemExit) as e:
        with contextlib.redirect_stderr(io.StringIO()) as err:
            main(["sample-ordinary", f"--cuont={KEY}"], io.StringIO())
    assert e.value.code == 2 and KEY not in err.getvalue()


def test_cli_needs_the_environment_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("TXWARDEN_LIVE_RPC", raising=False)
    code, _, err = cli(*sample_args(tmp_path))
    assert code == 3 and "TXWARDEN_LIVE_RPC" in err


def test_cli_hides_the_key_when_the_node_rejects_it(tmp_path, monkeypatch):
    with FakeRpcServer(status=401, body=b"unauthorized") as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/v2/{KEY}")
        code, out, err = cli(*sample_args(tmp_path))
    assert code == 3 and KEY not in out + err and "401" in err
    assert not (tmp_path / "cases.csv").exists()


def test_cli_a_budget_spent_on_the_node_check_writes_nothing(tmp_path, node):
    code, out, _ = cli(*sample_args(tmp_path, "--budget-calls", "3"))
    assert code == 4 and "budget" in out
    assert not (tmp_path / "cases.csv").exists()


# --------------------------------------------------------------------------- the whole path

def test_sample_then_replay_then_report_says_detection_was_not_measured(tmp_path, node):
    assert cli(*sample_args(tmp_path))[0] == 0
    results = tmp_path / "results.jsonl"
    code, out, err = cli("replay", str(tmp_path / "cases.csv"), "--out", str(results),
                         "--cache-dir", str(tmp_path / "cache"), "--rps", "10000")
    assert code == 0, err
    assert KEY not in out + err
    real = next(tmp_path.glob("results*.jsonl"))
    header = read_results(real).header
    assert header["case_counts"] == {"sandwiched": 0, "ordinary": 8}

    code, text, err = cli("replay-report", str(real), "--allow-mock", "--allow-small")
    assert code == 0, err
    assert "sandwiched NOT MEASURED" in text
    assert "NOT MEASURED: the case file has no sandwiched cases" in text
    assert "sampled from the chain" in text
    code, js, _ = cli("replay-report", str(real), "--allow-mock", "--allow-small", "--json")
    data = json.loads(js)
    assert data["not_measured"] == ["sandwiched"] and data["sampled_ordinary"] is True
    assert data["headline"]["detection_warn_or_block"] is None
    assert data["headline"]["false_positive_warn_or_block"]["n"] > 0

