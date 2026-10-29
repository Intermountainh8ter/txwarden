"""The replay case-file loader: validation, duplicates, labels, counts. Hashes are synthetic."""
import json

import pytest

from txwarden.replay import LABELS, CaseFileError, load_cases, parse_cases

from .fake_history import fake_hash

H1, H2, H3 = fake_hash(1), fake_hash(2), fake_hash(3)


def csv_text(*rows: str, header: str = "tx_hash,label,source,notes") -> str:
    return "\n".join([header, *rows]) + "\n"


# --------------------------------------------------------------------------- happy paths

def test_csv_with_all_columns():
    cs = parse_cases(csv_text(f"{H1},sandwiched,EXAMPLE,a note", f"{H2},ordinary,EXAMPLE,"),
                     "cases.csv")
    assert [c.tx_hash for c in cs.cases] == [H1, H2]
    assert [c.label for c in cs.cases] == ["sandwiched", "ordinary"]
    assert cs.cases[0].source == "EXAMPLE" and cs.cases[0].notes == "a note"
    assert cs.cases[1].notes == "" and [c.line for c in cs.cases] == [2, 3]
    assert cs.counts == {"sandwiched": 1, "ordinary": 1} and len(cs) == 2


def test_csv_with_only_required_columns():
    cs = parse_cases(csv_text(f"{H1},sandwiched", header="tx_hash,label"), "c.csv")
    assert cs.cases[0].source == "" and cs.cases[0].notes == ""


def test_jsonl_with_optional_fields_missing():
    text = "\n".join([json.dumps({"tx_hash": H1, "label": "ordinary"}),
                      json.dumps({"tx_hash": H2, "label": "sandwiched", "source": "EXAMPLE",
                                  "notes": "n"})])
    cs = parse_cases(text, "cases.jsonl")
    assert cs.counts == {"sandwiched": 1, "ordinary": 1}
    assert cs.cases[1].source == "EXAMPLE" and cs.cases[0].source == ""


def test_counts_include_labels_with_zero_cases():
    cs = parse_cases(csv_text(f"{H1},ordinary", header="tx_hash,label"), "c.csv")
    assert cs.counts == {"sandwiched": 0, "ordinary": 1}
    assert set(cs.counts) == set(LABELS)
    assert cs.summary() == "1 cases: 0 sandwiched, 1 ordinary"


def test_hash_and_label_are_normalised_but_not_reinterpreted():
    upper = "0x" + "AB" * 32
    cs = parse_cases(csv_text(f" {upper} , Sandwiched ", header="tx_hash,label"), "c.csv")
    assert cs.cases[0].tx_hash == "0x" + "ab" * 32 and cs.cases[0].label == "sandwiched"


def test_blank_lines_and_column_order_and_header_case_do_not_matter():
    text = f"\n\nLabel,TX_Hash\n\nordinary,{H1}\n\nsandwiched,{H2}\n\n"
    cs = parse_cases(text.lstrip("\n"), "c.csv")
    assert [c.tx_hash for c in cs.cases] == [H1, H2]


def test_extra_columns_are_ignored():
    cs = parse_cases(csv_text(f"{H1},ordinary,whatever", header="tx_hash,label,block_number"),
                     "c.csv")
    assert len(cs) == 1


def test_quoted_csv_fields_with_commas_and_newlines():
    text = 'tx_hash,label,notes\n' + f'{H1},ordinary,"a, b\nsecond line"\n{H2},sandwiched,x\n'
    cs = parse_cases(text, "c.csv")
    assert cs.cases[0].notes == "a, b\nsecond line" and len(cs) == 2


def test_utf8_bom_is_accepted(tmp_path):
    p = tmp_path / "c.csv"
    p.write_bytes(b"\xef\xbb\xbf" + csv_text(f"{H1},ordinary", header="tx_hash,label").encode())
    assert len(load_cases(p)) == 1


def test_format_detection_by_suffix_and_by_content(tmp_path):
    jsonl = json.dumps({"tx_hash": H1, "label": "ordinary"}) + "\n"
    csv = csv_text(f"{H1},ordinary", header="tx_hash,label")
    for name, text in (("a.jsonl", jsonl), ("a.ndjson", jsonl), ("a.csv", csv),
                       ("a.txt", jsonl), ("a.dat", csv)):
        p = tmp_path / name
        p.write_text(text)
        assert len(load_cases(p)) == 1, name


def test_explicit_format_overrides_the_suffix(tmp_path):
    p = tmp_path / "cases.txt"
    p.write_text(csv_text(f"{H1},ordinary", header="tx_hash,label"))
    assert len(load_cases(p, fmt="csv")) == 1
    with pytest.raises(ValueError, match="unknown case file format"):
        load_cases(p, fmt="xml")


def test_sha256_identifies_the_input():
    a = parse_cases(csv_text(f"{H1},ordinary", header="tx_hash,label"), "c.csv")
    b = parse_cases(csv_text(f"{H1},sandwiched", header="tx_hash,label"), "c.csv")
    assert len(a.sha256) == 64 and a.sha256 != b.sha256


# --------------------------------------------------------------------------- rejections

@pytest.mark.parametrize("bad", [
    "0x" + "1" * 63, "0x" + "1" * 65, "1" * 64, "0X" + "1" * 64, "0x" + "g" * 64,
    "", "0x", "0x" + "1" * 40, " ", "0x" + "11 " * 21 + "1",
])
def test_malformed_hashes_are_rejected_with_the_line_number(bad):
    with pytest.raises(CaseFileError) as e:
        parse_cases(csv_text(f"{H1},ordinary", f'"{bad}",ordinary', header="tx_hash,label"),
                    "c.csv")
    assert any(p.startswith("line 3:") and "64 hex" in p for p in e.value.problems)
    assert len(e.value.problems) == 1  # the good row is not reported


@pytest.mark.parametrize("label", ["", "benign", "mev", "sandwich", "sandwiched,x", "true", "1"])
def test_other_labels_are_rejected(label):
    with pytest.raises(CaseFileError) as e:
        parse_cases(csv_text(f'{H1},"{label}"', header="tx_hash,label"), "c.csv")
    assert "not one of sandwiched | ordinary" in e.value.problems[0]


def test_duplicate_hashes_are_rejected_even_with_the_same_label():
    text = csv_text(f"{H1},ordinary", f"{H2},ordinary", f"{H1},ordinary", header="tx_hash,label")
    with pytest.raises(CaseFileError) as e:
        parse_cases(text, "c.csv")
    assert e.value.problems == ["line 4: duplicate tx_hash (first seen on line 2)"]


def test_duplicate_hashes_are_found_across_letter_case_and_labels():
    lower = "0x" + "ab" * 32
    upper = "0x" + "AB" * 32
    with pytest.raises(CaseFileError) as e:
        parse_cases(csv_text(f"{lower},ordinary", f"{upper},sandwiched", header="tx_hash,label"),
                    "c.csv")
    assert e.value.problems == ["line 3: duplicate tx_hash (first seen on line 2)"]


def test_all_problems_are_reported_in_one_pass():
    text = csv_text("0xabc,ordinary", f"{H1},nope", f"{H2},ordinary", f"{H2},sandwiched",
                    header="tx_hash,label")
    with pytest.raises(CaseFileError) as e:
        parse_cases(text, "c.csv")
    assert [p.split(":")[0] for p in e.value.problems] == ["line 2", "line 3", "line 5"]
    assert "3 problem(s)" in str(e.value)


def test_error_text_is_truncated_after_twenty_problems():
    rows = [f"0x{i},ordinary" for i in range(30)]
    with pytest.raises(CaseFileError) as e:
        parse_cases(csv_text(*rows, header="tx_hash,label"), "c.csv")
    assert len(e.value.problems) == 30 and "... and 10 more" in str(e.value)


def test_long_garbage_values_are_clipped_in_messages():
    with pytest.raises(CaseFileError) as e:
        parse_cases(csv_text(f"{'z' * 5000},ordinary", header="tx_hash,label"), "c.csv")
    assert len(str(e.value)) < 500


@pytest.mark.parametrize("header", ["hash,label", "tx_hash", "label,notes", "x,y,z"])
def test_missing_required_columns(header):
    with pytest.raises(CaseFileError) as e:
        parse_cases(f"{header}\n{H1},ordinary\n", "c.csv")
    assert "missing required column" in e.value.problems[0]


def test_repeated_header_column_is_rejected():
    with pytest.raises(CaseFileError, match="repeats a column"):
        parse_cases(f"tx_hash,label,label\n{H1},ordinary,ordinary\n", "c.csv")


def test_too_many_columns_in_a_row():
    with pytest.raises(CaseFileError, match="3 columns but the header has 2"):
        parse_cases(f"tx_hash,label\n{H1},ordinary,extra\n", "c.csv")


def test_short_rows_are_treated_as_missing_values():
    with pytest.raises(CaseFileError, match="not one of"):
        parse_cases(f"tx_hash,label\n{H1}\n", "c.csv")


def test_empty_file_and_header_only_file():
    with pytest.raises(CaseFileError, match="empty"):
        parse_cases("", "c.csv")
    with pytest.raises(CaseFileError, match="no cases found"):
        parse_cases("tx_hash,label\n", "c.csv")
    with pytest.raises(CaseFileError, match="no cases found"):
        parse_cases("\n\n", "c.jsonl")


def test_jsonl_problems():
    text = "\n".join(["not json", "[1, 2]", json.dumps({"tx_hash": 5, "label": "ordinary"}),
                      json.dumps({"tx_hash": H1}), json.dumps({"tx_hash": H1, "label": 7})])
    with pytest.raises(CaseFileError) as e:
        parse_cases(text, "c.jsonl")
    msgs = e.value.problems
    assert "not valid JSON" in msgs[0] and "expected a JSON object, got list" in msgs[1]
    assert "tx_hash '5'" in msgs[2] and "label 'None'" in msgs[3] and "label '7'" in msgs[4]


def test_csv_with_unreadable_content_is_a_problem_not_a_crash():
    import csv as csv_module

    huge = "x" * (csv_module.field_size_limit() + 10)
    with pytest.raises(CaseFileError, match="unreadable CSV"):
        parse_cases(f"tx_hash,label\n{huge},ordinary\n", "c.csv")


def test_non_utf8_file(tmp_path):
    p = tmp_path / "c.csv"
    p.write_bytes(b"tx_hash,label\n\xff\xfe\n")
    with pytest.raises(CaseFileError, match="not valid UTF-8"):
        load_cases(p)


def test_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_cases(tmp_path / "nope.csv")


# --------------------------------------------------------------------------- no real hashes

def test_no_real_looking_transaction_hashes_are_checked_in():
    """Docs and data files may only contain obviously synthetic 32-byte values (0x000...0n or one
    repeated byte). Calldata words in evals/ and tests/fixtures/ are test data, not hashes, and
    results/ is where the author commits real results, which is the one place real hashes belong."""
    import re
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    listing = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True)
    files = listing.stdout.split() if listing.returncode == 0 else [
        str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
    synthetic = re.compile(r"0x(?:0{48,}[0-9a-fA-F]*|([0-9a-fA-F]{2})\1{31})", re.I)
    checked = 0
    for name in files:
        p = root / name
        if (p.suffix not in {".md", ".csv", ".jsonl"}
                or name.startswith(("evals/", "tests/", "results/")) or not p.is_file()):
            continue
        checked += 1
        for m in re.finditer(r"0x[0-9a-fA-F]{64}(?![0-9a-fA-F])", p.read_text()):
            assert synthetic.fullmatch(m.group(0)), f"{name}: {m.group(0)[:14]}... looks real"
    assert checked >= 5
