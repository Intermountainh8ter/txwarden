"""``txwarden replay`` through the CLI, over real HTTP to the fake node."""
import io
import json

import pytest

from txwarden.cli import SUBCOMMANDS, build_parser, main
from txwarden.replay import read_results

from . import replay_world as rw
from .fake_rpc import FakeRpcServer
from .replay_world import build_world

KEY = "sk_live_Zx81QpLm0aa93kd7"  # a fake API key; the tests assert it never comes back out


def cli(*argv: str) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    import contextlib

    with contextlib.redirect_stderr(err):
        code = main(list(argv), out)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture()
def cases_file(tmp_path):
    p = tmp_path / "cases.csv"
    p.write_text(build_world().csv())
    return p


@pytest.fixture()
def node(monkeypatch):
    world = build_world()
    with FakeRpcServer(world.chain.rpc) as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/v2/{KEY}")
        yield world, srv


def flags(tmp_path, *extra: str) -> list[str]:
    return ["--out", str(tmp_path / "results.jsonl"), "--cache-dir", str(tmp_path / "cache"),
            "--rps", "10000", *extra]


# --------------------------------------------------------------------------- wiring

def test_replay_is_a_registered_subcommand_with_help():
    assert "replay" in SUBCOMMANDS
    with pytest.raises(SystemExit) as e:
        build_parser().parse_args(["replay", "--help"])
    assert e.value.code == 0


def test_replay_has_no_rpc_url_flag():
    sub = next(a for a in build_parser()._actions if a.dest == "cmd").choices["replay"]
    options = {o for a in sub._actions for o in a.option_strings}
    assert "--rpc" not in options and "--rpc-env" in options
    assert not any(o.startswith("--rpc") and o != "--rpc-env" for o in options)


def test_defaults_match_the_documented_ones():
    sub = next(a for a in build_parser()._actions if a.dest == "cmd").choices["replay"]
    d = {a.dest: a.default for a in sub._actions}
    assert (d["rps"], d["cost_per_call"], d["cost_debug_trace"], d["cost_archive"]) == (
        10.0, 1.0, 2.0, 2.0)
    assert d["rpc_env"] == "TXWARDEN_LIVE_RPC" and d["archive_window"] == 128
    assert d["cost_combine"] == "sum" and d["max_retries"] == 5


# --------------------------------------------------------------------------- validation only

def test_validate_only_reports_counts_per_label_without_an_endpoint(cases_file, monkeypatch):
    monkeypatch.delenv("TXWARDEN_LIVE_RPC", raising=False)
    code, out, err = cli("replay", str(cases_file), "--validate-only")
    assert code == 0 and "12 cases: 6 sandwiched, 6 ordinary" in out and err == ""


def test_a_bad_case_file_lists_every_problem(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("tx_hash,label\n0x123,ordinary\n" + rw.fake_hash(1) + ",maybe\n")
    code, _out, err = cli("replay", str(p), "--validate-only")
    assert code == 3 and "2 problem(s)" in err and "line 2" in err and "line 3" in err


def test_a_missing_case_file_is_an_input_error(tmp_path):
    code, _, err = cli("replay", str(tmp_path / "nope.csv"), "--validate-only")
    assert code == 3 and "error:" in err


# --------------------------------------------------------------------------- refusing URLs

@pytest.mark.parametrize("extra", [
    ["--rpc", f"https://node.example/{KEY}"], [f"--rpc=https://node.example/{KEY}"],
    [f"https://node.example/{KEY}"], ["--out", f"https://node.example/{KEY}"],
    ["--rpc-env", f"https://node.example/{KEY}"],
])
def test_a_url_on_the_command_line_is_refused_and_not_repeated(cases_file, extra):
    code, out, err = cli("replay", str(cases_file), *extra)
    assert code == 3 and KEY not in out + err and "node.example" not in out + err
    assert "environment variable" in err


@pytest.mark.parametrize("argv", [["--rp", KEY], ["--rpc-e", KEY], ["--bogus", KEY], [KEY]])
def test_unrecognised_arguments_are_rejected_without_being_echoed(cases_file, argv, capsys):
    with pytest.raises(SystemExit) as e:
        main(["replay", str(cases_file), *argv], io.StringIO())
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert KEY not in err and "unrecognized arguments (not shown)" in err


def test_other_commands_still_echo_unrecognised_arguments(capsys):
    with pytest.raises(SystemExit) as e:
        main(["decode", "0x", "--bogus"], io.StringIO())
    assert e.value.code == 2 and "unrecognized arguments: --bogus" in capsys.readouterr().err


def test_bad_rpc_env_name_is_an_argument_error_that_does_not_echo_it(cases_file, capsys):
    with pytest.raises(SystemExit) as e:
        main(["replay", str(cases_file), "--rpc-env", "not a name"], io.StringIO())
    assert e.value.code == 2
    assert "not a name" not in capsys.readouterr().err


def test_missing_environment_variable_is_explained(cases_file, monkeypatch):
    monkeypatch.delenv("TXWARDEN_LIVE_RPC", raising=False)
    code, _out, err = cli("replay", str(cases_file))
    assert code == 3 and "TXWARDEN_LIVE_RPC is not set" in err and "docs/LIVE_REPLAY.md" in err


def test_another_variable_can_be_chosen(cases_file, tmp_path, monkeypatch):
    world = build_world()
    monkeypatch.delenv("TXWARDEN_LIVE_RPC", raising=False)
    with FakeRpcServer(world.chain.rpc) as srv:
        monkeypatch.setenv("MY_NODE", srv.url)
        code, out, _err = cli("replay", str(cases_file), "--rpc-env", "MY_NODE", *flags(tmp_path),
                             "--limit", "2")
    assert code == 0 and "from $MY_NODE" in out


def test_a_malformed_variable_value_is_refused(cases_file, monkeypatch):
    monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"not-a-url-{KEY}")
    code, out, err = cli("replay", str(cases_file))
    assert code == 3 and KEY not in out + err and "not shown" in err


# --------------------------------------------------------------------------- running

def test_full_run_over_http(cases_file, node, tmp_path):
    _world, srv = node
    code, out, err = cli("replay", str(cases_file), *flags(tmp_path))
    assert code == 0, err
    assert "12 cases: 6 sandwiched, 6 ordinary" in out
    assert f"endpoint: {srv.url} (from $TXWARDEN_LIVE_RPC)" in out
    assert "MOCK: the endpoint is the in-repo fake node" in out
    assert "completed: 12 analysed this run (6 with a verdict, 4 unsupported, 2 error)" in out
    path = tmp_path / "results.MOCK.jsonl"
    assert f"results: {path}" in out
    results = read_results(path)
    assert len(results.cases) == 12 and results.mock
    assert KEY not in out + err + path.read_text()
    assert all(KEY not in p for p in srv.paths) is False  # the key did travel to the node, as it must


def test_resume_over_http_skips_finished_cases(cases_file, node, tmp_path):
    cli("replay", str(cases_file), *flags(tmp_path), "--limit", "3")
    code, out, _ = cli("replay", str(cases_file), *flags(tmp_path))
    assert code == 0 and "9 analysed this run" in out and "3 already done" in out


def test_budget_stop_exits_4_and_says_how_to_continue(cases_file, node, tmp_path):
    code, out, _ = cli("replay", str(cases_file), *flags(tmp_path), "--budget-calls", "20")
    assert code == 4 and out.startswith("12 cases") and "budget:" in out
    assert "Raise the budget and rerun the same command" in out
    code, out, _ = cli("replay", str(cases_file), *flags(tmp_path))
    assert code == 0 and "completed" in out


def test_estimate_prints_projection_and_writes_no_results(cases_file, node, tmp_path):
    code, out, _ = cli("replay", str(cases_file), *flags(tmp_path), "--estimate")
    assert code == 0 and "projected for all 12 cases" in out and "Cost model: 1 unit per request" in out
    assert not list(tmp_path.glob("*.jsonl"))


def test_cost_flags_change_the_estimate(cases_file, node, tmp_path):
    _, base, _ = cli("replay", str(cases_file), *flags(tmp_path), "--estimate")
    _, dear, _ = cli("replay", str(cases_file), *flags(tmp_path), "--estimate",
                     "--cost-per-call", "5", "--cost-archive", "9", "--cost-debug-trace", "9")
    assert "Cost model: 5 unit per request, 9 for debug_*/trace_*" in dear and base != dear


def test_no_cache_flag(cases_file, node, tmp_path):
    cli("replay", str(cases_file), *flags(tmp_path), "--no-cache", "--limit", "2")
    assert not (tmp_path / "cache").exists()


def test_config_file_policy_is_applied(cases_file, node, tmp_path):
    cfg = tmp_path / "lenient.toml"
    cfg.write_text('[policy]\ndisabled_rules = ["SLIPPAGE_TOLERANCE_EXTREME", '
                   '"SANDWICH_EXPOSURE_SEVERE", "SANDWICH_EXPOSURE", "SLIPPAGE_TOLERANCE_LOOSE"]\n')
    cli("replay", str(cases_file), *flags(tmp_path), "--config", str(cfg), "--limit", "1")
    rec = next(iter(read_results(tmp_path / "results.MOCK.jsonl").cases.values()))
    assert rec["verdict"] == "ALLOW"
    header = read_results(tmp_path / "results.MOCK.jsonl").header
    assert len(header["config_sha256"]) == 64


def test_a_config_rpc_url_is_ignored(cases_file, node, tmp_path):
    _world, _srv = node
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'rpc_url = "http://127.0.0.1:9/{KEY}"\n')
    code, out, err = cli("replay", str(cases_file), *flags(tmp_path), "--config", str(cfg),
                         "--limit", "1")
    assert code == 0 and KEY not in out + err


@pytest.mark.parametrize("bad", [["--limit", "-1"], ["--budget-calls", "-5"], ["--rps", "0"],
                                 ["--rps", "-3"], ["--max-retries", "-1"]])
def test_nonsense_numbers_are_input_errors(cases_file, node, tmp_path, bad):
    code, _, err = cli("replay", str(cases_file), *flags(tmp_path), *bad)
    assert code == 3 and "must" in err


def test_json_output_files_are_valid_jsonl(cases_file, node, tmp_path):
    cli("replay", str(cases_file), *flags(tmp_path))
    for line in (tmp_path / "results.MOCK.jsonl").read_text().splitlines():
        assert json.loads(line)["type"] in ("header", "case", "run")


def test_progress_lines_are_printed_per_case(cases_file, node, tmp_path):
    _, out, _ = cli("replay", str(cases_file), *flags(tmp_path), "--limit", "2")
    assert "[1/2]" in out and "[2/2]" in out and "requests=" in out
