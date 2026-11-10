from pathlib import Path

import pytest

import app


def _concentrator_upload(tmp_path, monkeypatch):
    source = tmp_path / "input rules.rule"
    source.write_text(":\nl\nu\n$1\n", encoding="utf-8")
    monkeypatch.setattr(
        app,
        "UPLOADS_META",
        {
            "base": None, "target": None, "seed": None,
            "ranker_wordlist": None, "ranker_cracked": None, "ranker_rules": None,
            "ranker_source_csv": None, "ranker_source_rules": None, "ranker_analysis_csv": None,
            "concentrator_files": [
                {"path": source, "name": source.name, "size": source.stat().st_size}
            ],
        },
    )
    return source


def test_concentrator_extract_command_preserves_core_cli_options(tmp_path, monkeypatch):
    _concentrator_upload(tmp_path, monkeypatch)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cmd, output = app.build_concentrator_command(
        "extract",
        {
            "output_base_name": "extract result", "top_rules": 125,
            "statistical_sort": True, "max_length": 44,
            "output_format": "expanded", "no_gpu": True,
            "in_memory": False, "confirm_large_memory": True,
        },
        run_dir,
    )
    assert "-e" in cmd and "-s" in cmd and "-t" in cmd and "125" in cmd
    assert "-d" in cmd and "--no-gpu" in cmd and "-y" in cmd
    assert "expanded" in cmd and "44" in cmd
    assert output == "extract result_extracted.rule"
    assert str(tmp_path / "input rules.rule") in cmd


def test_concentrator_combo_and_markov_commands_are_wired_to_original_switches(tmp_path, monkeypatch):
    _concentrator_upload(tmp_path, monkeypatch)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    combo, combo_output = app.build_concentrator_command(
        "combo", {"combo_target": 7500, "combo_min_len": 2, "combo_max_len": 4}, run_dir
    )
    assert "-g" in combo and "-n" in combo and "7500" in combo
    assert "-l" in combo and combo[combo.index("-l") + 1:combo.index("-l") + 3] == ["2", "4"]
    assert combo_output.endswith("_combo.rule")

    markov, markov_output = app.build_concentrator_command(
        "markov", {"generate_target": 9000, "markov_min_len": 1, "markov_max_len": 3,
                   "confirm_large_memory": True}, run_dir
    )
    assert "-gm" in markov and "-gt" in markov and "9000" in markov
    assert "-ml" in markov and markov[markov.index("-ml") + 1:markov.index("-ml") + 3] == ["1", "3"]
    assert "-y" in markov
    assert markov_output.endswith("_markov.rule")


def test_concentrator_process_command_maps_each_filter_and_never_prompts(tmp_path, monkeypatch):
    _concentrator_upload(tmp_path, monkeypatch)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    cmd, output = app.build_concentrator_command(
        "process",
        {
            "filter_min_occ": 3, "filter_max_rules": 500, "filter_func_redundancy": True,
            "filter_inverse": 100, "filter_hashcat_cleanup": "gpu", "confirm_large_memory": True,
        },
        run_dir,
    )
    assert "-p" in cmd
    for flag in ("--filter-min-occ", "--filter-max-rules", "--filter-func-redundancy", "--filter-inverse", "--filter-hashcat-cleanup"):
        assert flag in cmd
    assert "-y" in cmd
    assert output.endswith("_processed.rule")


def test_concentrator_command_validates_length_ranges_and_uploads(tmp_path, monkeypatch):
    _concentrator_upload(tmp_path, monkeypatch)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    with pytest.raises(ValueError, match="minimum length"):
        app.build_concentrator_command("combo", {"combo_min_len": 4, "combo_max_len": 2}, run_dir)
    with pytest.raises(ValueError, match="at least one"):
        monkeypatch.setattr(app, "UPLOADS_META", {"concentrator_files": []})
        app.build_concentrator_command("extract", {}, run_dir)


def test_ui_exposes_standalone_tools_four_concentrator_modes_and_legacy_selector():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")
    for item in ("nav-rulest", "concentrator-view"):
        assert f'id="{item}"' in html
    # RULEST is a standalone button; the former dropdown wrapper is gone.
    assert 'id="rulest-subnav"' not in html
    assert '<button class="nav-item active" id="nav-rulest"' in html
    assert 'data-nav-tool="concentrator"' in html
    for mode in ("extract", "combo", "markov", "process"):
        assert f'data-concentrator-mode="{mode}"' in html
        assert f'data-concentrator-panel="{mode}"' in html
    assert 'data-rank-mode="legacy"' in html
    assert 'data-rank-mode="mab"' in html
    assert "activeTool = ['ranker', 'concentrator', 'rulestripper', 'minimizer'].includes(tool) ? tool : 'rulest'" in js
    assert ".concentrator-mode-tab.active" in css
    assert ".rank-mode-tab.active" in css


def test_concentrator_web_mode_avoids_interactive_memory_prompts():
    source = (Path(app.__file__).resolve().parent / "concentrator.py").read_text(encoding="utf-8")
    assert "elif _web_mode():" in source
    assert "Functional minimization skipped: enable the explicit high-memory confirmation" in source
    assert "Markov model was not built (memory safety check declined or failed)." in source


def test_ruleops_ranker_legacy_selector_is_prominent_and_persistent():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")
    ranker_view = html.split('<div id="ranker-view"', 1)[1]
    card_pos = ranker_view.index('id="ranker-engine-mode-card"')
    uploads_pos = ranker_view.index('class="panel ranker-input-panel"')
    assert card_pos < uploads_pos, "Legacy/MAB selector must appear before shared uploads and tuning controls"
    selector = ranker_view[card_pos:uploads_pos]
    assert 'data-rank-mode="mab"' in selector
    assert 'data-rank-mode="legacy"' in selector
    assert 'aria-pressed="false"' in selector
    assert 'id="rank-mode-current"' in selector
    assert 'id="rank-mode-description"' in selector
    assert "sessionStorage.setItem" in js and "ruleops-ranker-mode" in js
    assert "sessionStorage.getItem" in js and "ruleops-ranker-mode" in js
    assert '#ranker-engine-mode-card[hidden]{display:none!important}' in css
