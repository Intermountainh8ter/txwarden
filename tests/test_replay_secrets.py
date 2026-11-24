"""The RPC URL carries an API key. It must not reach stdout, stderr, result files, cache files,
cache file names or exception text, whatever goes wrong. KEY is a made-up key."""
import io
import os
import subprocess
import sys
import traceback
from contextlib import redirect_stderr
from pathlib import Path

import pytest

import txwarden.replay as replay_module
from txwarden.cli import main
from txwarden.redact import Redactor
from txwarden.replay import ReplayConfig, Replayer, parse_cases, read_results
from txwarden.risk import PolicyConfig
from txwarden.simulator import AnvilSimulator, RpcError, SimulatorOptions, http_transport

from . import replay_world as rw
from .fake_history import FakeClock, fake_hash
from .fake_rpc import FakeRpcServer
from .helpers import U
from .replay_world import build_world

KEY = "sk_live_Zx81QpLm0aa93kd7"
ROOT = Path(__file__).resolve().parents[1]


def everything_under(path: Path) -> str:
    """All file names and contents below ``path``."""
    chunks = []
    for p in sorted(path.rglob("*")):
        chunks.append(str(p.relative_to(path)))
        if p.is_file():
            chunks.append(p.read_text(errors="replace"))
    return "\n".join(chunks)


def exception_text(e: BaseException) -> str:
    return "\n".join([str(e), repr(e), repr(e.args), "".join(traceback.format_exception(e))])


def cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stderr(err):
        code = main(list(argv), out)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture()
def cases_file(tmp_path):
    p = tmp_path / "cases.csv"
    p.write_text(build_world().csv())
    return p


def run_flags(tmp_path, *extra):
    return ["--out", str(tmp_path / "results.jsonl"), "--cache-dir", str(tmp_path / "cache"),
            "--rps", "10000", "--max-retries", "0", *extra]


URL_SHAPES = [
    "{base}/v2/" + KEY,
    "{base}/" + KEY,
    "{base}/?apikey=" + KEY,
    "{base}/rpc?x=1&token=" + KEY + "&y=2",
    "{base}/v1/" + KEY + "/eth/mainnet",
]


# --------------------------------------------------------------------------- http_transport

@pytest.mark.parametrize("shape", URL_SHAPES)
def test_connection_refused_names_the_host_and_never_the_key(shape):
    url = shape.format(base="http://127.0.0.1:1")
    with pytest.raises(RpcError) as e:
        http_transport(url, timeout=1)("eth_chainId", [])
    assert e.value.transport and "cannot reach http://127.0.0.1:1:" in e.value.message
    assert KEY not in exception_text(e.value)


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_http_errors_name_the_host_and_never_the_key(status):
    with FakeRpcServer(lambda m, p: "0x", status=status, body=b"{}") as srv:
        with pytest.raises(RpcError) as e:
            http_transport(f"{srv.url}/v2/{KEY}")("eth_chainId", [])
    assert e.value.code == status and f"HTTP {status} from {srv.url}" in e.value.message
    assert KEY not in exception_text(e.value)


def test_non_json_reply_does_not_quote_the_url_or_the_body():
    with FakeRpcServer(lambda m, p: "0x", body=f"<html>{KEY}</html>".encode(),
                       content_type="text/html") as srv:
        with pytest.raises(RpcError) as e:
            http_transport(f"{srv.url}/{KEY}")("eth_chainId", [])
    assert "did not return JSON" in e.value.message and KEY not in exception_text(e.value)


@pytest.mark.parametrize("url", [
    KEY, f"{KEY}/more", f"no-scheme.example/{KEY}", f"ftp://node.example/{KEY}",
    f"http://node.example/{KEY}\x7f", f"http://node.example/ {KEY}",
    f"http://user:{KEY}@127.0.0.1:1/rpc", f"http://127.0.0.1:{KEY}/rpc",
    f"http://127.0.0.1:1/é{KEY}", f"http://[::1/{KEY}",
])
def test_malformed_urls_fail_without_echoing_them(url):
    with pytest.raises(RpcError) as e:
        http_transport(url, timeout=1)("eth_chainId", [])
    assert e.value.transport
    assert KEY not in exception_text(e.value)
    assert e.value.__cause__ is None or KEY not in repr(e.value.__cause__)


def test_retry_after_header_is_parsed_from_the_response():
    with FakeRpcServer(lambda m, p: "0x", faults=[429], fault_headers={"Retry-After": "3"}) as srv:
        with pytest.raises(RpcError) as e:
            http_transport(srv.url)("eth_chainId", [])
    assert e.value.code == 429 and e.value.retry_after == 3.0


@pytest.mark.parametrize("header", ["soon", "-5", "99999999", "Wed, 21 Oct 2026 07:28:00 GMT", ""])
def test_unusable_retry_after_values_are_ignored(header):
    with FakeRpcServer(lambda m, p: "0x", faults=[429], fault_headers={"Retry-After": header}) as srv:
        with pytest.raises(RpcError) as e:
            http_transport(srv.url)("eth_chainId", [])
    assert e.value.retry_after is None


def test_a_response_without_retry_after_has_none():
    with FakeRpcServer(lambda m, p: "0x", faults=[503]) as srv:
        with pytest.raises(RpcError) as e:
            http_transport(srv.url)("eth_chainId", [])
    assert e.value.retry_after is None


def test_existing_behaviour_with_a_plain_url_is_unchanged():
    """No path, no key: the message is exactly what it always was."""
    with FakeRpcServer(lambda m, p: "0x", status=500, body=b"{}") as srv:
        with pytest.raises(RpcError, match=f"^HTTP 500 from {srv.url}$"):
            http_transport(srv.url)("eth_chainId", [])


# --------------------------------------------------------------------------- the CLI

@pytest.mark.parametrize("shape", URL_SHAPES)
def test_refused_connection_at_startup_leaks_nothing(cases_file, tmp_path, monkeypatch, shape):
    monkeypatch.setenv("TXWARDEN_LIVE_RPC", shape.format(base="http://127.0.0.1:1"))
    code, out, err = cli("replay", str(cases_file), *run_flags(tmp_path))
    assert code == 3 and "cannot use the endpoint" in err and "http://127.0.0.1:1" in err
    assert KEY not in out + err + everything_under(tmp_path)


def test_rate_limiting_at_startup_leaks_nothing(cases_file, tmp_path, monkeypatch):
    with FakeRpcServer(lambda m, p: "0x", faults=[429] * 50) as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/v2/{KEY}")
        code, out, err = cli("replay", str(cases_file), *run_flags(tmp_path))
    assert code == 3 and "HTTP 429" in err
    assert KEY not in out + err + everything_under(tmp_path)


def test_a_node_that_echoes_the_request_path_in_its_errors_leaks_nothing(cases_file, tmp_path,
                                                                        monkeypatch):
    world = build_world()
    real = world.chain.rpc

    def nosy(method, params):
        if method == "eth_getTransactionByHash":
            raise RpcError(f"invalid api key in https://node.example{srv.last_path}: {KEY}", -32000)
        return real(method, params)

    with FakeRpcServer(nosy) as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/v2/{KEY}")
        code, out, err = cli("replay", str(cases_file), *run_flags(tmp_path),
                             "--max-consecutive-errors", "0", "--limit", "4")
    assert code == 0
    results = read_results(tmp_path / "results.MOCK.jsonl")
    assert len(results.cases) == 4
    assert all(r["status"] == "error" for r in results.cases.values())
    assert any("[redacted]" in r["reason"] for r in results.cases.values())
    assert KEY not in out + err + everything_under(tmp_path)


def test_a_node_error_inside_a_case_leaks_nothing_in_the_progress_or_stop_message(
        cases_file, tmp_path, monkeypatch):
    world = build_world()
    real = world.chain.rpc

    def nosy(method, params):
        if method == "eth_getTransactionByHash":
            raise RpcError(f"HTTP 502 for {srv.last_path}", 502, transport=True)
        return real(method, params)

    with FakeRpcServer(nosy, faults=[]) as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/{KEY}")
        code, out, err = cli("replay", str(cases_file), *run_flags(tmp_path),
                             "--max-consecutive-errors", "2")
    # a JSON-RPC error object is not an HTTP 502, but the stop message must be clean either way
    assert KEY not in out + err + everything_under(tmp_path)
    assert code in (0, 4)


def test_a_full_successful_run_leaves_the_key_nowhere_on_disk_or_in_output(cases_file, tmp_path,
                                                                          monkeypatch):
    world = build_world()
    with FakeRpcServer(world.chain.rpc) as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/v2/{KEY}?apikey={KEY}")
        code, out, err = cli("replay", str(cases_file), *run_flags(tmp_path))
        cli("replay", str(cases_file), *run_flags(tmp_path), "--estimate")
    assert code == 0
    disk = everything_under(tmp_path)
    assert KEY not in out + err + disk
    assert "127.0.0.1" not in disk  # nor the host: files hold no endpoint detail at all
    assert srv.url.split(":")[-1] not in read_results(
        tmp_path / "results.MOCK.jsonl").header["endpoint"]
    assert any(KEY in p for p in srv.paths)  # the key did go to the node, as it must


def test_cache_file_names_and_contents_hold_no_endpoint(cases_file, tmp_path, monkeypatch):
    world = build_world()
    with FakeRpcServer(world.chain.rpc) as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/{KEY}")
        cli("replay", str(cases_file), *run_flags(tmp_path))
    cache = everything_under(tmp_path / "cache")
    assert cache and KEY not in cache and "127.0.0.1" not in cache and "http" not in cache.lower()


def test_endpoint_label_is_scrubbed_if_the_user_puts_the_url_in_it(cases_file, tmp_path,
                                                                  monkeypatch):
    world = build_world()
    with FakeRpcServer(world.chain.rpc) as srv:
        url = f"{srv.url}/v2/{KEY}"
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", url)
        cli("replay", str(cases_file), *run_flags(tmp_path), "--endpoint-label", url, "--limit", "1")
    assert KEY not in everything_under(tmp_path)


def test_an_unexpected_crash_prints_a_scrubbed_one_line_not_a_traceback(cases_file, tmp_path,
                                                                       monkeypatch):
    world = build_world()

    def crash(self):
        raise ValueError(f"cannot parse https://node.example/v2/{KEY} ({KEY})")

    monkeypatch.setattr(Replayer, "run", crash)
    with FakeRpcServer(world.chain.rpc) as srv:
        monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"{srv.url}/v2/{KEY}")
        code, out, err = cli("replay", str(cases_file), *run_flags(tmp_path))
    assert code == 1 and "ValueError" in err and "Traceback" not in err
    assert KEY not in out + err and "[redacted]" in err


def test_a_crash_with_the_url_in_a_chained_exception_is_still_clean(cases_file, tmp_path,
                                                                   monkeypatch):
    def crash(self):
        try:
            raise OSError(f"https://node.example/{KEY}")
        except OSError as e:
            raise RuntimeError("wrapper") from e

    monkeypatch.setattr(Replayer, "run", crash)
    monkeypatch.setenv("TXWARDEN_LIVE_RPC", f"https://node.example/{KEY}")
    code, out, err = cli("replay", str(cases_file), *run_flags(tmp_path))
    assert code == 1 and KEY not in out + err


def test_subprocess_run_against_a_dead_endpoint_prints_no_key_and_no_traceback(cases_file,
                                                                              tmp_path):
    env = {**os.environ, "TXWARDEN_LIVE_RPC": f"http://127.0.0.1:1/v2/{KEY}?apikey={KEY}"}
    proc = subprocess.run([sys.executable, "-m", "txwarden", "replay", str(cases_file),
                           *run_flags(tmp_path)], cwd=ROOT, env=env, capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 3
    assert KEY not in proc.stdout + proc.stderr and "Traceback" not in proc.stderr
    assert "cannot use the endpoint" in proc.stderr


def test_subprocess_run_with_the_url_as_an_argument_is_refused_without_echo(cases_file):
    proc = subprocess.run([sys.executable, "-m", "txwarden", "replay", str(cases_file), "--rpc",
                           f"https://node.example/{KEY}"], cwd=ROOT, capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 3 and KEY not in proc.stdout + proc.stderr


# --------------------------------------------------------------------------- the library

def replayer_over_http(url, tmp_path, world, clock=None, **cfg):
    cases = parse_cases(world.csv(), "cases.csv")
    config = ReplayConfig(out_path=tmp_path / "r.jsonl", cache_dir=tmp_path / "cache", rps=10_000,
                          **cfg)
    return Replayer(cases, http_transport(url), config, PolicyConfig(), SimulatorOptions(),
                    Redactor(url), clock=clock or FakeClock())


def test_retry_storm_over_http_with_a_fake_clock_leaks_nothing(tmp_path):
    world = build_world()
    state = {"fail": 0}
    real = world.chain.rpc

    def handler(method, params):
        return real(method, params)

    with FakeRpcServer(handler) as srv:
        # three 429s are consumed by the first three requests the run makes
        srv.faults = [429, 429, 503]
        clock = FakeClock()
        r = replayer_over_http(f"{srv.url}/v2/{KEY}", tmp_path, world, clock, limit=3)
        out = r.run()
    assert out.stopped == "limit" and clock.sleeps[:3] == [1, 2, 4]
    assert KEY not in everything_under(tmp_path) and state["fail"] == 0


def test_exhausted_retries_over_http_become_an_error_record_without_the_key(tmp_path):
    world = build_world()
    real = world.chain.rpc
    with FakeRpcServer(real) as srv:
        r = replayer_over_http(f"{srv.url}/v2/{KEY}", tmp_path, world, max_retries=2,
                               max_consecutive_errors=0, limit=1)
        r.preflight()  # let the endpoint check pass, then rate-limit the case itself
        srv.faults = [429] * 20
        out = r.run()
    rec = next(iter(read_results(out.out_path).cases.values()))
    assert rec["reason_code"] == "rate_limited" and srv.url in rec["reason"]
    assert KEY not in everything_under(tmp_path) and KEY not in exception_text(RuntimeError(rec["reason"]))


def test_a_failing_simulator_cannot_smuggle_the_url_into_a_result(tmp_path, monkeypatch):
    world = build_world()
    url = f"https://node.example/v2/{KEY}"

    class Leaky(AnvilSimulator):
        def simulate(self, tx):
            raise RuntimeError(f"upstream said: {url} is down")

    monkeypatch.setattr(replay_module, "AnvilSimulator", Leaky)
    cases = parse_cases(world.csv(), "cases.csv")
    cfg = ReplayConfig(out_path=tmp_path / "r.jsonl", cache_dir=tmp_path / "cache", rps=10_000,
                       limit=2)
    out = Replayer(cases, world.chain.rpc, cfg, PolicyConfig(), SimulatorOptions(), Redactor(url),
                   clock=FakeClock()).run()
    recs = list(read_results(out.out_path).cases.values())
    assert any(r["reason_code"] == "internal_error" for r in recs)
    assert KEY not in everything_under(tmp_path)


def test_case_source_text_is_scrubbed_too(tmp_path):
    world = build_world()
    url = f"https://node.example/{KEY}"
    text = world.csv().replace("EXAMPLE", f"pasted-from-{KEY}")
    cfg = ReplayConfig(out_path=tmp_path / "r.jsonl", cache_dir=None, rps=10_000, limit=1)
    out = Replayer(parse_cases(text, "c.csv"), world.chain.rpc, cfg, PolicyConfig(),
                   SimulatorOptions(), Redactor(url), clock=FakeClock()).run()
    assert KEY not in everything_under(tmp_path) and "[redacted]" in out.out_path.read_text()


def test_user_visible_exceptions_from_the_library_never_carry_the_value(monkeypatch):
    from txwarden.replay import ReplayError, endpoint_from_env

    for value in (KEY, f"ws://x/{KEY}", f"https://x/{KEY} {KEY}"):
        with pytest.raises(ReplayError) as e:
            endpoint_from_env("TXWARDEN_LIVE_RPC", {"TXWARDEN_LIVE_RPC": value})
        assert KEY not in exception_text(e.value)


def test_the_world_fixture_is_not_accidentally_using_the_key():
    assert KEY not in build_world().csv() and fake_hash(1) not in KEY and U not in KEY
    assert rw.HEAD > 0
