"""The 7702/Permit2 audit script: determinism, labelling and metric shape."""
import importlib.util
import json
import sys
from pathlib import Path

EVALS = Path(__file__).resolve().parents[1] / "evals"
spec = importlib.util.spec_from_file_location("audit_7702", EVALS / "audit_7702_permit2.py")
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def test_deterministic_for_seed():
    assert audit.run(7) == audit.run(7)


def test_cases_labelled_and_balanced():
    cases = audit.build(7, 5)
    assert {c["class"] for c in cases} == {"eip7702", "permit2", "benign"}
    assert sum(c["malicious"] for c in cases) == 30


def test_result_shape_and_label():
    res = audit.run(7)
    assert "SIMULATED" in res["set_label"]
    fn = res["false_negative_rate"]
    assert 0.0 <= fn["overall"] <= 1.0
    lo, hi = fn["eip7702"]["wilson95"]
    assert 0.0 <= lo <= hi <= 1.0


def test_wilson_edges():
    assert audit.wilson(0, 0) == [0.0, 1.0]
    lo, hi = audit.wilson(10, 10)
    assert hi == 1.0 and lo > 0.5


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "r.json"
    assert audit.main(["--seed", "7", "--out", str(out)]) == 0
    assert "started_at" in json.loads(out.read_text())["provenance"]
