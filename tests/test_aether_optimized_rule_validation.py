from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aether_validation import validate_rule_records


def test_optimized_output_validation_keeps_only_valid_aether_rules():
    records = [
        {"rule": "c @0 vD|", "gpu_kernel_time_seconds": 0.001},
        {"rule": "h", "gpu_kernel_time_seconds": 0.002},
        {"rule": "B1!", "gpu_kernel_time_seconds": 0.003},
        {"rule": "v-!", "gpu_kernel_time_seconds": 0.004},
        {"rule": "M", "gpu_kernel_time_seconds": 0.005},
        {"rule": "N0ab", "gpu_kernel_time_seconds": 0.006},
    ]

    result = validate_rule_records(records)

    assert [item["rule"] for item in result["valid_rules"]] == ["c @0 vD|", "h", "B1!"]
    assert result["summary"]["benchmarkable_rules"] == 3
    assert result["summary"]["invalid_rules"] == 1
    assert result["summary"]["cli_only_rules"] == 1
    assert result["summary"]["unsupported_rules"] == 1
    assert [item["record_number"] for item in result["issues"]] == [4, 5, 6]


def test_optimized_output_validation_rejects_multiline_and_non_string_records():
    records = [
        {"rule": "l\nu"},
        {"rule": None},
        {"rule": "u"},
    ]

    result = validate_rule_records(records)

    assert [item["rule"] for item in result["valid_rules"]] == ["u"]
    assert result["summary"]["benchmarkable_rules"] == 1
    assert result["summary"]["invalid_rules"] == 2
    assert len(result["issues"]) == 2
    assert all("exactly one rule line" in item["reason"] for item in result["issues"])


def test_aether_optimizer_revalidates_records_at_the_output_boundary():
    source = (ROOT / "aether.py").read_text(encoding="utf-8")
    assert "validation = validate_rule_records(all_rules)" in source
    assert 'all_rules = validation["valid_rules"]' in source
    assert '"rejected_rules": validation_issues' in source


def test_optimizer_writes_only_finally_validated_rules(tmp_path):
    import ast
    import json
    import os
    import time
    from types import SimpleNamespace

    source_path = ROOT / "aether.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    optimizer_node = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RuleSetOptimizer"
    )
    namespace = {
        "List": list,
        "os": os,
        "json": json,
        "time": time,
        "Colors": SimpleNamespace(RED="", GREEN="", YELLOW="", CYAN="", END=""),
        "validate_rule_records": validate_rule_records,
    }
    exec(compile(ast.Module(body=[optimizer_node], type_ignores=[]), str(source_path), "exec"), namespace)

    source_report = tmp_path / "performance.json"
    source_report.write_text(json.dumps({"rules": [
        {"rule": "u", "gpu_kernel_time_seconds": 0.001},
        {"rule": "v-!", "gpu_kernel_time_seconds": 0.002},
        {"rule": "M", "gpu_kernel_time_seconds": 0.003},
        {"rule": "N0ab", "gpu_kernel_time_seconds": 0.004},
        {"rule": "h", "gpu_kernel_time_seconds": 0.005},
    ]}), encoding="utf-8")
    optimized_path = tmp_path / "optimized_rules.rule"

    optimizer = namespace["RuleSetOptimizer"](max_rules=10, max_total_time=1.0)
    optimizer.create_optimized_set([str(source_report)], str(optimized_path))

    saved_rules = [
        line for line in optimized_path.read_text(encoding="utf-8").splitlines()
        if line and not line.lstrip().startswith("#")
    ]
    assert saved_rules == ["u", "h"]

    optimization_report = json.loads(
        (tmp_path / "optimized_rules_optimization_report.json").read_text(encoding="utf-8")
    )
    assert [item["rule"] for item in optimization_report["selected_rules"]] == ["u", "h"]
    validation = optimization_report["rule_validation"]
    assert validation["summary"]["benchmarkable_rules"] == 2
    assert len(validation["rejected_rules"]) == 3


def test_aether_python38_annotations_and_validation_failure_artifacts_are_safe():
    source = (ROOT / "aether.py").read_text(encoding="utf-8")
    assert "from __future__ import annotations" in source
    assert "if self.output_dir and self.last_validation_report:" in source
