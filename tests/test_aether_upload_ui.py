from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_aether_uses_multi_file_upload_and_library_selection():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "aether_files: { endpointBase: '/api/aether/upload', maxFiles: 12" in source
    assert "input.addEventListener('change', (event) => uploadMultiFiles(field, Array.from(event.target.files || [])))" in source
    assert "select.addEventListener('change', () => selectLibraryAsset(select.dataset.libraryField, select.value, select))" in source


def test_aether_upload_success_is_added_to_local_selected_file_state():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "const uploadedMeta = { name: result.name || file.name" in source
    assert "uploadState[field] = [...existing, uploadedMeta]" in source
    assert "renderMultiFileState(field);" in source


def test_empty_or_stale_status_snapshot_cannot_erase_local_multi_file_selection():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "const serverFiles = Array.isArray(data.uploads[field]) ? data.uploads[field] : [];" in source
    assert "(uploadState[field] || []).forEach((file) =>" in source
    assert "uploadState[field] = Array.from(merged.values());" in source
    assert "uploadState[field] = files;" not in source


def test_aether_upload_only_counts_lines_and_does_not_run_full_preflight_validation():
    import ast

    app_source = (ROOT / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(app_source)
    count_function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "count_aether_rules"
    )
    namespace = {"Path": Path}
    exec(compile(ast.Module(body=[count_function], type_ignores=[]), "app.py", "exec"), namespace)

    rule_file = ROOT / "tests" / "_temporary_aether_count.rule"
    try:
        rule_file.write_text("# comment\n\n$#\nc @0 vD|\n", encoding="utf-8")
        assert namespace["count_aether_rules"](rule_file) == 2
    finally:
        rule_file.unlink(missing_ok=True)

    assert "summarize_aether_rules" not in app_source
    assert "meta[\"rule_count\"] = count_aether_rules(stored)" in app_source
    assert "meta[\"rule_count\"] = count_aether_rules(meta[\"path\"])" in app_source


def test_aether_upload_selection_ui_displays_active_rule_count_not_upload_preflight():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "active rules" in source
    assert "file.rule_validation" not in source
    assert "rule_validation: result.rule_validation" not in source
