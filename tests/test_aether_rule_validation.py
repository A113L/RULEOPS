from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aether_validation import validate_rule_lines, validate_rule_file, write_validation_artifacts


def _result(rule: str) -> dict:
    return validate_rule_lines([rule])["results"][0]


def test_supported_single_operation_rules_are_benchmarkable() -> None:
    rules = [
        ":", "l", "u", "c", "C", "t", "r", "d", "f", "q", "k", "K", "E",
        "T1", "D1", "+1", "-1", "y1", "Y1", "'1", "x11", "O11", "*01",
        "$#", "^!", "@a", "sXY", "i2A", "o0a", "3AB", "v1A", "v2-", "B1X",
        "h", "H", "S",
    ]
    report = validate_rule_lines(rules)
    assert report["summary"]["benchmarkable_rules"] == len(rules)
    assert report["summary"]["invalid_rules"] == 0
    assert report["summary"]["unsupported_rules"] == 0


def test_literal_hash_and_space_operands_are_preserved() -> None:
    report = validate_rule_lines(["$#\n", "$ \n", "^ \n"])
    assert [item["rule"] for item in report["benchmark_rules"]] == ["$#", "$ ", "^ "]
    assert report["summary"]["benchmarkable_rules"] == 3


def test_supported_hashcat_chains_are_benchmarkable() -> None:
    for rule in ("l$1", "cS", "h$1", "v2-$1", "B1Xh", "uT0$!"):
        assert _result(rule)["status"] == "valid", rule


def test_hashcat_8_operations_not_implemented_by_aether_are_separated() -> None:
    for rule in ("N1eo", "~s?dX"):
        result = _result(rule)
        assert result["status"] == "unsupported", (rule, result)


def test_cli_only_rules_are_separated_from_rule_file_syntax() -> None:
    for rule in ("M", "4", "6", "Q", "<8", ">8", "_8", "!a", "/a", "(a", ")a", "=0a", "%2a", "X123", "~!?d"):
        assert _result(rule)["status"] == "cli_only", rule


def test_malformed_rules_are_rejected_with_reason() -> None:
    for rule in ("$", "sA", "T", "x1", "~", "~s?xA", "Z", "?l"):
        result = _result(rule)
        assert result["status"] == "invalid", (rule, result)
        assert result["reason"]


def test_utf8_bom_is_removed_on_python38_compatible_path() -> None:
    report = validate_rule_lines(["\ufeffl\n", "u\n"])
    assert [item["rule"] for item in report["benchmark_rules"]] == ["l", "u"]
    assert report["summary"]["benchmarkable_rules"] == 2
    source = (ROOT / "aether_validation.py").read_text(encoding="utf-8")
    assert "line.removeprefix(" not in source


def test_comments_and_blank_lines_keep_source_line_numbers(tmp_path: Path) -> None:
    rule_file = tmp_path / "sample.rule"
    rule_file.write_text("# comment\n\n$#\nl$1\n$\n", encoding="utf-8")
    report = validate_rule_file(rule_file)
    assert report["summary"] == {
        "total_lines": 5,
        "active_rules": 3,
        "benchmarkable_rules": 2,
        "invalid_rules": 1,
        "cli_only_rules": 0,
        "unsupported_rules": 0,
        "comment_lines": 1,
        "blank_lines": 1,
    }
    assert [item["line_number"] for item in report["benchmark_rules"]] == [3, 4]
    assert [item["line_number"] for item in report["issues"]] == [5]


def test_validation_artifacts_include_exact_lines_and_reasons(tmp_path: Path) -> None:
    report = validate_rule_lines(["$#\n", "l$1\n", "M\n", "$\n"])
    paths = write_validation_artifacts(report, tmp_path, "sample")
    assert {Path(path).name for path in paths} == {
        "sample_validation_report.json",
        "sample_cli_only_rules.txt",
        "sample_invalid_rules.txt",
    }
    data = json.loads((tmp_path / "sample_validation_report.json").read_text(encoding="utf-8"))
    assert data["summary"]["benchmarkable_rules"] == 2
    assert "line 3" in (tmp_path / "sample_cli_only_rules.txt").read_text(encoding="utf-8")
    assert "line 4" in (tmp_path / "sample_invalid_rules.txt").read_text(encoding="utf-8")


def test_unicode_and_escaped_operands_are_valid_but_not_benchmarked() -> None:
    assert _result("$é")["status"] == "unsupported"
    assert _result(r"$\x41")["status"] == "unsupported"


def test_hashcat_operation_limit_is_enforced() -> None:
    assert _result("l" * 31)["status"] == "valid"
    invalid = _result("l" * 32)
    assert invalid["status"] == "invalid"
    assert "31" in invalid["reason"]


def test_invalid_source_bytes_can_be_written_to_reports(tmp_path: Path) -> None:
    rule_file = tmp_path / "raw.rule"
    rule_file.write_bytes(b"$\xff\n")
    report = validate_rule_file(rule_file)
    paths = write_validation_artifacts(report, tmp_path / "out", "raw")
    assert paths
    text = (tmp_path / "out" / "raw_unsupported_rules.txt").read_text(encoding="utf-8")
    assert r"\xff" in text


def test_aether_kernel_executes_chains_and_has_room_for_hashcat_rule_lines() -> None:
    source = (ROOT / "aether.py").read_text(encoding="utf-8")
    assert "#define MAX_RULE_LEN 256" in source
    assert "self.max_rule_len = 256" in source
    assert "apply_hashcat_rule(word, word_len, rule, rule_len" in source
    assert "cmd_char == ' ' || cmd_char == '\\t'" in source


def test_space_separated_hashcat_rule_chains_validate_as_one_rule() -> None:
    report = validate_rule_lines(["c @0 vD|\n", "37r vNN $2\n", "vO[ BY( $0 @4 sI$\n"])
    assert report["summary"]["benchmarkable_rules"] == 3
    assert report["summary"]["invalid_rules"] == 0
    assert report["summary"]["unsupported_rules"] == 0


def test_rule_line_over_buffer_limit_is_reported_not_truncated() -> None:
    result = _result("l" + (" " * 255))
    assert result["status"] == "unsupported"
    assert "packed rule limit" in result["reason"]


def test_lowercase_base36_positions_match_kernel_decoder() -> None:
    assert _result("Ta")["status"] == "valid"
