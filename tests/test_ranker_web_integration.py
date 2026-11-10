import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app


def _make_inputs(tmp_path, monkeypatch):
    fields = {
        "base": None, "target": None, "seed": None,
        "ranker_wordlist": "wordlist.txt", "ranker_cracked": "cracked.txt",
        "ranker_rules": "candidate.rule", "ranker_source_csv": None,
        "ranker_source_rules": None, "ranker_analysis_csv": None,
    }
    uploads = {}
    for key, name in fields.items():
        if not name:
            uploads[key] = None
            continue
        path = tmp_path / name
        path.write_text("test\n", encoding="utf-8")
        uploads[key] = {"path": path, "name": name, "size": path.stat().st_size}
    monkeypatch.setattr(app, "UPLOADS_META", uploads)
    return uploads


def test_build_ranker_rank_command_maps_options(tmp_path, monkeypatch):
    _make_inputs(tmp_path, monkeypatch)
    command, output = app.build_ranker_command("rank", {
        "output_name": "scores.csv", "topk": 250, "preset": "medium_memory",
        "batch_size": 65536, "global_bits": 28, "cracked_bits": 24,
        "mab_exploration": 1.5, "mab_final_trials": 40,
        "mab_screening_trials": 6, "mab_sample_words": 4096,
        "device": 1, "legacy": True, "mab_zero_eliminate": False,
    }, tmp_path / "run")
    assert output == "scores.csv"
    assert command[3] == "rank"
    for token in ["--wordlist", "--rules", "--cracked", "--output", "--topk", "250",
                  "--preset", "medium_memory", "--batch-size", "65536", "--global-bits", "28",
                  "--cracked-bits", "24", "--legacy", "--device", "1"]:
        assert token in command
    assert "--mab-exploration" not in command
    assert "--mab-no-zero-eliminate" not in command


def test_build_ranker_optimize_accepts_existing_rules_or_csv(tmp_path, monkeypatch):
    uploads = _make_inputs(tmp_path, monkeypatch)
    rules = tmp_path / "existing.rule"
    rules.write_text(":\n$1\n", encoding="utf-8")
    uploads["ranker_source_rules"] = {"path": rules, "name": rules.name, "size": rules.stat().st_size}
    command, output = app.build_ranker_command("optimize", {
        "output_name": "optimized.rule", "candidates": 5000, "budget": 250,
        "budgets": "64,250", "rule_batch_size": 512, "words_batch_size": 80000,
        "max_word_len": 32, "max_rule_len": 255, "max_output_len": 512,
        "cost_alpha": 0.25, "auto_max_output_len": True,
    }, tmp_path / "run")
    assert output == "optimized.rule"
    assert command[3] == "postprocess"
    assert "--rules-file" in command and str(rules) in command
    assert "--ranking-csv" not in command
    assert ["--budgets", "64,250"] == command[command.index("--budgets"):command.index("--budgets") + 2]
    assert "--auto-max-output-len" in command

    uploads["ranker_source_rules"] = None
    csv = tmp_path / "ranking.csv"
    csv.write_text("rule,score\n", encoding="utf-8")
    uploads["ranker_source_csv"] = {"path": csv, "name": csv.name, "size": csv.stat().st_size}
    command, _ = app.build_ranker_command("optimize", {"source_type": "csv"}, tmp_path / "run2")
    assert "--ranking-csv" in command and str(csv) in command


def test_optimize_requires_exactly_one_source_and_required_inputs(tmp_path, monkeypatch):
    uploads = _make_inputs(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="exactly one"):
        app.build_ranker_command("optimize", {}, tmp_path / "run")
    rules = tmp_path / "existing.rule"
    rules.write_text(":\n", encoding="utf-8")
    uploads["ranker_source_rules"] = {"path": rules, "name": rules.name, "size": 2}
    csv = tmp_path / "rank.csv"
    csv.write_text("rule\n", encoding="utf-8")
    uploads["ranker_source_csv"] = {"path": csv, "name": csv.name, "size": 5}
    with pytest.raises(ValueError, match="exactly one"):
        app.build_ranker_command("optimize", {}, tmp_path / "run2")
    uploads["ranker_wordlist"] = None
    uploads["ranker_source_csv"] = None
    with pytest.raises(ValueError, match="base wordlist"):
        app.build_ranker_command("optimize", {}, tmp_path / "run3")


def test_build_ranker_analyze_command_respects_output_toggles(tmp_path, monkeypatch):
    uploads = _make_inputs(tmp_path, monkeypatch)
    csv = tmp_path / "analysis.csv"
    csv.write_text("rule,score\n", encoding="utf-8")
    uploads["ranker_analysis_csv"] = {"path": csv, "name": csv.name, "size": csv.stat().st_size}
    command, output = app.build_ranker_command("analyze", {
        "summary_name": "summary.txt", "rules_output_name": "clean.rule",
        "scores_output_name": "scored.csv", "top": 500, "write_rules": True,
        "write_scores": True, "no_console": True, "parallel": True,
    }, tmp_path / "run")
    assert output == "summary.txt"
    assert command[3] == "handler"
    for token in ["--input", str(csv), "--output", str(tmp_path / "run" / "summary.txt"),
                  "--rules-output", str(tmp_path / "run" / "clean.rule"),
                  "--scores-output", str(tmp_path / "run" / "scored.csv"), "--top", "500",
                  "--no-console", "--parallel"]:
        assert token in command


def test_ranker_ui_has_one_place_for_three_workflows_and_shared_logs():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    assert 'id="nav-rulest"' in html and 'data-nav-tool="ranker"' in html
    assert 'data-workflow="rank"' in html
    assert 'data-workflow="optimize"' in html
    assert 'data-workflow="analyze"' in html
    assert 'id="ranker-view"' in html and 'id="live-log"' in html
    assert "build_ranker_command" in (root / "app.py").read_text(encoding="utf-8")
    assert "function setActiveTool" in js
    assert "function startRankerRun" in js
    assert "/api/ranker/run" in js


def test_ranker_uploads_are_in_same_cleanup_registry():
    assert app.RANKER_UPLOAD_FIELDS.issubset(set(app.UPLOADS_META))
    assert "ranker_source_csv" in app.UPLOADS_META
    assert "ranker_analysis_csv" in app.UPLOADS_META


import pytest


def test_ranker_options_reject_non_finite_cost_alpha():
    with pytest.raises(ValueError, match="cost alpha"):
        app._float_option({"cost_alpha": "nan"}, "cost_alpha", 0.0, 0.0)
    with pytest.raises(ValueError, match="cost alpha"):
        app._float_option({"cost_alpha": "inf"}, "cost_alpha", 0.0, 0.0)


def test_ranker_tool_switch_respects_deep_link_and_keeps_shared_log():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    assert '<title>RULEOPS — Hashcat Rule Toolchain</title>' in html
    assert 'id="rulest-subnav"' not in html
    assert 'id="nav-rulest"' in html and 'data-nav-tool="concentrator"' in html
    assert "const initialTool = window.location.hash === '#ranker' ? 'ranker'" in js
    assert "history.pushState(null, '', href)" in js
    assert 'id="live-log"' in html


def test_optimize_command_honors_the_selected_source_type(tmp_path, monkeypatch):
    uploads = _make_inputs(tmp_path, monkeypatch)
    rules = tmp_path / "existing.rule"
    rules.write_text(":\n", encoding="utf-8")
    uploads["ranker_source_rules"] = {"path": rules, "name": rules.name, "size": rules.stat().st_size}
    with pytest.raises(ValueError, match="selected source is a ranking CSV"):
        app.build_ranker_command("optimize", {"source_type": "csv"}, tmp_path / "run")

    csv_path = tmp_path / "ranking.csv"
    csv_path.write_text("rule,score\nu,1\n", encoding="utf-8")
    uploads["ranker_source_rules"] = None
    uploads["ranker_source_csv"] = {"path": csv_path, "name": csv_path.name, "size": csv_path.stat().st_size}
    with pytest.raises(ValueError, match="selected source is a plain .rule file"):
        app.build_ranker_command("optimize", {"source_type": "rules"}, tmp_path / "run2")


def test_build_ranker_mab_command_includes_mab_tuning_but_not_legacy(tmp_path, monkeypatch):
    _make_inputs(tmp_path, monkeypatch)
    command, _ = app.build_ranker_command("rank", {
        "output_name": "mab.csv", "preset": "recommend", "legacy": False,
        "mab_exploration": 1.25, "mab_screening_trials": 4,
        "mab_final_trials": 32, "mab_sample_words": 4096,
        "mab_zero_eliminate": False,
    }, tmp_path / "run")
    assert "--legacy" not in command
    assert ["--mab-exploration", "1.25"] == command[command.index("--mab-exploration"):command.index("--mab-exploration") + 2]
    assert "--mab-no-zero-eliminate" in command
