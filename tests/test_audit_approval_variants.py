"""The approval-variant audit script: determinism, labelling and metric shape."""
import importlib.util
import json
import sys
from pathlib import Path

EVALS = Path(__file__).resolve().parents[1] / "evals"
spec = importlib.util.spec_from_file_location("audit_variants", EVALS / "audit_approval_variants.py")
audit = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit
spec.loader.exec_module(audit)


def test_deterministic_for_seed():
    assert audit.run(7, 5) == audit.run(7, 5)


def test_cases_labelled_and_balanced():
    cases = audit.build(7, 5)
    assert {c["variant"] for c in cases} == {
        "increaseAllowance", "setApprovalForAll", "dai_permit",
        "permit2_batch_permit", "permit2_approve"}
    assert sum(c["malicious"] for c in cases) == 25
    assert sum(not c["malicious"] for c in cases) == 25


def test_result_shape_and_label():
    res = audit.run(7, 5)
    assert "SIMULATED" in res["set_label"]
    assert 0.0 <= res["false_negative_rate"]["overall"] <= 1.0
    assert set(res["false_negative_rate"]["by_variant"]) == set(res["false_positive_rate"]["by_variant"])


def test_main_writes_provenance(tmp_path):
    out = tmp_path / "r.json"
    assert audit.main(["--seed", "7", "--out", str(out)]) == 0
    assert "started_at" in json.loads(out.read_text())["provenance"]
