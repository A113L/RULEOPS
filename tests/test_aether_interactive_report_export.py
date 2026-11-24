import ast
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def _visualization_harness():
    source_path = ROOT / "aether.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    original_class = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "VisualizationEngine"
    )
    methods = [
        node for node in original_class.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"_relative_tier_specs", "create_interactive_report"}
    ]
    reduced_class = ast.ClassDef(
        name="VisualizationHarness",
        bases=[],
        keywords=[],
        body=methods,
        decorator_list=[],
    )
    module = ast.Module(
        body=[
            ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
            reduced_class,
        ],
        type_ignores=[],
    )
    namespace = {
        "List": list,
        "Tuple": tuple,
        "Dict": dict,
        "Any": object,
        "np": np,
        "json": json,
        "datetime": datetime,
        "os": os,
        "Colors": SimpleNamespace(YELLOW="", GREEN="", END=""),
    }
    exec(compile(ast.fix_missing_locations(module), str(source_path), "exec"), namespace)
    return namespace["VisualizationHarness"]


def test_interactive_report_exports_configured_number_of_fastest_rules(tmp_path):
    harness = _visualization_harness()
    visualizer = harness()
    visualizer.output_dir = str(tmp_path)
    performance = [
        ("u", {"gpu_kernel_time_seconds": 0.003, "gpu_operations_per_sec": 100}),
        ("l", {"gpu_kernel_time_seconds": 0.001, "gpu_operations_per_sec": 300}),
        ("$1", {"gpu_kernel_time_seconds": 0.002, "gpu_operations_per_sec": 200}),
    ]

    visualizer.create_interactive_report(
        performance,
        "sample_rules",
        default_export_rule_count=2,
    )

    report_path = tmp_path / "sample_rules_interactive.html"
    html = report_path.read_text(encoding="utf-8")
    match = re.search(
        r'<script id="report-data" type="application/json">(.*?)</script>',
        html,
        re.DOTALL,
    )
    assert match, "HTML report must contain its embedded report data"
    payload = json.loads(match.group(1))

    assert payload["meta"]["default_export_rule_count"] == 2
    assert 'id="export-count"' in html
    assert 'id="export-fastest"' in html
    assert "rankedRules.slice(0,count)" in html
    assert "fastest_${count}_rules" in html


def test_web_command_passes_custom_export_count_even_without_optimizer(tmp_path):
    source_path = ROOT / "app.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "build_aether_command"
    )

    def int_option(options, key, default, minimum, maximum):
        value = int(options.get(key, default))
        if value < minimum or value > maximum:
            raise ValueError(key)
        return value

    namespace = {
        "Path": Path,
        "sys": sys,
        "ROOT": tmp_path,
        "UPLOADS_META": {"aether_files": []},
        "MAX_AETHER_FILES": 12,
        "_int_option": int_option,
        "_float_option": lambda options, key, default, minimum, maximum: float(options.get(key, default)),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source_path), "exec"), namespace)

    rule_path = tmp_path / "source.rule"
    rule_path.write_text("u\n", encoding="utf-8")
    namespace["UPLOADS_META"]["aether_files"] = [{"path": str(rule_path), "name": "source.rule"}]

    command, _ = namespace["build_aether_command"](
        {"max_optimize_rules": 137, "visualize": True, "optimize": False},
        tmp_path / "run",
    )

    flag_index = command.index("--max-optimize-rules")
    assert command[flag_index + 1] == "137"
    assert "--optimize" not in command


def test_web_form_always_sends_manual_export_count():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    options_start = source.index("function utilityOptions(tool)")
    options_end = source.index("if (tool === 'rulestripper')", options_start)
    aether_options = source[options_start:options_end]
    count_assignment = "max_optimize_rules: readUtilityNumber('aether-max-optimize-rules', 'Max rules to optimize')"
    assert count_assignment in aether_options
    assert aether_options.index(count_assignment) < aether_options.index("if (options.optimize)")
