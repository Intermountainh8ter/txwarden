"""The batch-depth audit script: determinism, labelling and metric shape."""
import importlib.util
import json
import sys
from pathlib import Path

EVALS = Path(__file__).resolve().parents[1] / "evals"
spec = importlib.util.spec_from_file_location("audit_batch_depth", EVALS / "audit_batch_depth.py")
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def test_deterministic_for_seed():
    assert audit.run(7, 3) == audit.run(7, 3)


def test_cases_balanced_per_depth():
    cases = audit.build(7, 3)
    for d in audit.DEPTHS:
        assert sum(c["depth"] == d and c["malicious"] for c in cases) == 3
        assert sum(c["depth"] == d and not c["malicious"] for c in cases) == 3


def test_result_shape_and_label():
    res = audit.run(7, 3)
    assert "SIMULATED" in res["set_label"]
    assert set(res["batch"]["miss_rate"]) == {f"depth_{d}" for d in audit.DEPTHS}
    assert all(0.0 <= v <= 1.0 for v in res["batch"]["miss_rate"].values())


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "r.json"
    assert audit.main(["--seed", "7", "--n", "3", "--out", str(out)]) == 0
    assert "started_at" in json.loads(out.read_text())["provenance"]
