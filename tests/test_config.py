import json

import pytest

from txwarden import config as cfgmod
from txwarden.config import (
    AppConfig,
    ConfigError,
    config_from_dict,
    load_config,
    parse_toml,
    parse_toml_subset,
)

from .helpers import EVIL, FRIEND, OTHER, ROUTER

SAMPLE = f'''
# top-level keys
rpc_url = "http://127.0.0.1:8545"   # trailing comment
trust_well_known = true
model = "my-model"

[policy]
trusted_spenders = ["{ROUTER}"]
trusted_recipients = [
    "{FRIEND}",   # multi-line array with a comment
    "{OTHER}",
]
slippage_block = 0.03
sandwich_warn_bps = 25
expected_chain_id = 1
flag_fresh_recipients = false
disabled_rules = ["GAS_ABNORMAL"]
denylist = ["{EVIL}"]

[policy.address_book]
"0x1111111111111111111111111111111111111111" = "cold wallet # not a comment"

[simulator]
honeypot = false
max_ticks = 8
probe_value_wei = 10_000_000_000_000_000
'''


def test_subset_parser_agrees_with_tomllib_on_the_documented_subset():
    assert parse_toml_subset(SAMPLE) == parse_toml(SAMPLE)


def test_subset_parser_scalars_arrays_and_tables():
    got = parse_toml_subset('''
a = 1
b = -2.5
c = 'single # quoted'
d = "tab\\there"
e = true
f = [1, 2.5, "x", [3, 4]]
g = 0x10
[t.u]
v = "w"
['quoted.key']
z = 1
''')
    assert got["a"] == 1 and got["b"] == -2.5 and got["c"] == "single # quoted"
    assert got["d"] == "tab\there" and got["e"] is True and got["g"] == 16
    assert got["f"] == [1, 2.5, "x", [3, 4]]
    assert got["t"]["u"]["v"] == "w" and got["quoted.key"]["z"] == 1


@pytest.mark.parametrize("bad", ["x = ", "x = hello", "= 1", "[unterminated", "x y z", "x = {a=1}"])
def test_subset_parser_rejects_garbage(bad):
    with pytest.raises(ConfigError):
        parse_toml_subset(bad)


def test_subset_parser_rejects_table_over_scalar():
    with pytest.raises(ConfigError, match="not a table"):
        parse_toml_subset("a = 1\n[a.b]\n")


def test_parse_toml_wraps_decode_errors_and_falls_back_without_tomllib(monkeypatch):
    with pytest.raises(ConfigError):
        parse_toml("this is = = not toml")
    monkeypatch.setattr(cfgmod, "_tomllib", None)
    assert parse_toml(SAMPLE) == parse_toml_subset(SAMPLE)


def test_config_from_dict_builds_policy_simulator_and_book():
    cfg = config_from_dict(parse_toml(SAMPLE))
    assert cfg.rpc_url == "http://127.0.0.1:8545" and cfg.model == "my-model"
    assert cfg.policy.trusted_spenders == {ROUTER} and cfg.policy.trusted_recipients == {
        FRIEND, OTHER}
    assert cfg.policy.slippage_block == 0.03 and cfg.policy.expected_chain_id == 1
    assert cfg.policy.disabled_rules == {"GAS_ABNORMAL"} and cfg.policy.denylist == {EVIL}
    assert cfg.policy.flag_fresh_recipients is False
    assert cfg.simulator.honeypot is False and cfg.simulator.max_ticks == 8
    assert cfg.simulator.probe_value_wei == 10**16
    assert len(cfg.address_book) >= 25


def test_effective_policy_merges_labels_and_optionally_trusts_well_known():
    cfg = config_from_dict(parse_toml(SAMPLE))
    pol = cfg.effective_policy()
    assert pol.address_book[ROUTER] == "Uniswap V2 Router02"
    assert pol.address_book["0x1111111111111111111111111111111111111111"] == (
        "cold wallet # not a comment")
    permit2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
    assert permit2 in pol.trusted_spenders  # trust_well_known = true in SAMPLE
    assert "0x1e0049783f008a0085193e00003d00cd54003c71" in pol.trusted_operators
    cfg.trust_well_known = False
    assert permit2 not in cfg.effective_policy().trusted_spenders
    assert cfg.policy.trusted_spenders == {ROUTER}  # effective_policy does not mutate the config


def test_user_labels_override_builtin_labels():
    cfg = config_from_dict({"policy": {"address_book": {ROUTER: "my router"}}})
    assert cfg.effective_policy().address_book[ROUTER] == "my router"


def test_defaults_and_builtin_book_switch():
    cfg = AppConfig()
    assert cfg.rpc_url is None and not cfg.trust_well_known and len(cfg.address_book) >= 25
    assert len(config_from_dict({"builtin_address_book": False}).address_book) == 0


@pytest.mark.parametrize("raw,fragment", [
    ({"policy": {"sandwich_warm_bps": 1}}, "unknown policy keys"),
    ({"simulator": {"honeypott": True}}, "unknown keys"),
    ({"policy": {"trusted_spenders": 5}}, "policy"),
])
def test_config_errors_name_the_problem(raw, fragment):
    with pytest.raises(ConfigError, match=fragment):
        config_from_dict(raw)


def test_load_config_resolves_relative_address_book_next_to_the_file(tmp_path):
    (tmp_path / "book.json").write_text(json.dumps({"labels": {OTHER: "friend"}}))
    (tmp_path / "txwarden.toml").write_text('address_book = "book.json"\nrpc_url = "http://x"\n')
    cfg = load_config(tmp_path / "txwarden.toml")
    assert cfg.address_book.name(OTHER) == "friend" and cfg.rpc_url == "http://x"
    (tmp_path / "bad.toml").write_text("rpc_url = \n")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "bad.toml")
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.toml")
