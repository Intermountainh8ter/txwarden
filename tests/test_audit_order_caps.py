"""The order-caps audit script: determinism, labelling and rule semantics."""
import importlib.util
import json
import sys
from pathlib import Path

EVALS = Path(__file__).resolve().parents[1] / "evals"
spec = importlib.util.spec_from_file_location("audit_order_caps", EVALS / "audit_order_caps.py")
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def test_deterministic_for_seed():
    assert audit.run(7, 10) == audit.run(7, 10)


def test_rule_semantics():
    split = [900] * 7
    assert not audit.per_order_rule(split)
    assert audit.aggregate_rule(split)
    assert audit.per_order_rule([audit.PER_ORDER_CAP + 1])
    assert not audit.aggregate_rule([100, 200])


def test_cases_labelled_and_split_is_split():
    cases = audit.build(7, 10)
    assert sum(c["malicious"] for c in cases) == 20
    for c in cases:
        if c["class"] == "aggregate_exposure_split":
            assert max(c["orders"]) <= audit.PER_ORDER_CAP
            assert sum(c["orders"]) > audit.AGGREGATE_CAP


def test_result_shape_and_label():
    res = audit.run(7, 10)
    assert "SIMULATED" in res["set_label"]
    assert res["miss_rate"]["aggregate_exposure_split"] == 1.0
    assert res["miss_rate"]["aggregate_exposure_split_with_aggregate"] == 0.0


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "r.json"
    assert audit.main(["--seed", "7", "--out", str(out)]) == 0
    assert "started_at" in json.loads(out.read_text())["provenance"]
