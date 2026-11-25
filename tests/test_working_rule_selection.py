from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_saved_rule_menus_include_rule_artifacts_from_work_folders():
    app_source = (ROOT / "app.py").read_text(encoding="utf-8")
    ui_source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert '"working_rules": []' in app_source
    assert 'Path(name).suffix.lower() not in {".rule", ".rules"}' in app_source
    assert 'full_run, _run_directory = get_tool_history_run(run_id)' in app_source
    assert 'for artifact in full_run.get("files", [])' in app_source
    assert 'group.label = \'Persistence Storage · working folders\'' in ui_source


def test_work_folder_rule_selection_uses_safe_resolver_and_transient_copy():
    app_source = (ROOT / "app.py").read_text(encoding="utf-8")
    ui_source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "def upload_meta_for_working_rule(run_id: str, relative_path: str)" in app_source
    assert "open_run_folder_file(run_id, relative_path)" in app_source
    assert 'data.get("source") == "run"' in app_source
    assert "source: 'run'" in ui_source
    assert "selectedOption.dataset.relativePath" in ui_source


def test_working_rule_selection_cache_key_was_bumped():
    source = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert "working-rule-load=20261125e" in source
