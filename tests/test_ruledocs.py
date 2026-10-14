from txwarden.risk import RULES, PolicyConfig
from txwarden.ruledocs import (
    CATEGORY_TITLES,
    explain_dict,
    explain_text,
    fmt_default,
    knob_defaults,
    markdown_summary_table,
    rules_by_category,
    rules_markdown,
    rules_table,
)


def test_every_rule_is_documented():
    for spec in RULES.values():
        assert len(spec.description) > 20, spec.id
        assert len(spec.docs) > 10, f"{spec.id} has no operator docs"
        assert spec.category in CATEGORY_TITLES, spec.id


def test_every_policy_knob_named_by_a_rule_exists_and_every_rule_knob_is_used_somewhere():
    defaults = knob_defaults()
    used = {k for spec in RULES.values() for k in spec.config}
    assert used <= set(defaults)
    # knobs that intentionally affect no single rule: trust plumbing and the rule switch itself
    unused = set(defaults) - used
    assert unused <= {"disabled_rules", "trusted_operators", "trusted_recipients"} | {
        k for k in unused if k.startswith("trusted_")}, sorted(unused)


def test_markdown_covers_every_rule_with_anchor_and_defaults():
    md = rules_markdown()
    for spec in RULES.values():
        assert f"### {spec.id}" in md and f"(#{spec.id.lower()})" in md
    assert f"ships **{len(RULES)} rules**" in md
    assert "`sandwich_warn_bps` (default 30)" in md and "`permit_deadline_warn_s` (default 2592000)" in md
    assert md.endswith("\n") and "\n\n\n" not in md


def test_tables_and_text_render_consistently():
    assert markdown_summary_table().count("\n") == len(RULES) + 1
    assert len(rules_table().splitlines()) == len(RULES)
    cats = rules_by_category()
    assert sum(len(v) for v in cats.values()) == len(RULES)
    for specs in cats.values():  # most severe first within a category
        assert [int(r.severity) for r in specs] == sorted((int(r.severity) for r in specs), reverse=True)
    text = explain_text(RULES["GAS_ABNORMAL"])
    assert "gas_abnormal_multiple = 5" in text and "[HIGH -> WARN]" in text
    d = explain_dict(RULES["GAS_ABNORMAL"])
    assert d["config_defaults"] == {"gas_abnormal_multiple": 5.0}


def test_fmt_default():
    assert fmt_default([]) == "empty" and fmt_default(0.0075) == "0.0075" and fmt_default(True) == "True"
    assert fmt_default(PolicyConfig().expected_chain_id) == "None"
