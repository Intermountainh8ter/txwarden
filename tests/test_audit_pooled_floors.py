"""The pooled-floors audit script: determinism, floors and metric shape."""
import importlib.util
import sys
from pathlib import Path

EVALS = Path(__file__).resolve().parents[1] / "evals"
spec = importlib.util.spec_from_file_location("audit_pooled", EVALS / "audit_pooled_floors.py")
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def test_deterministic_for_seed():
    assert audit.run(7, 3) == audit.run(7, 3)


def test_floors_score_zero():
    res = audit.run(7, 3)
    assert res["floors"]["allow_all"]["youden_j"] == 0
    assert res["floors"]["deny_all"]["youden_j"] == 0


def test_shape_and_label():
    res = audit.run(7, 3)
    assert "SIMULATED" in res["set_label"]
    assert -1.0 <= res["engine"]["youden_j"] <= 1.0
    assert set(res["engine"]["by_source"]) == set(audit.SOURCES)
    assert res["n_cases"] == res["n_malicious"] + res["n_benign"]
