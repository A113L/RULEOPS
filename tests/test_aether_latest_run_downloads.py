from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_aether_download_panel_uses_latest_saved_aether_run_only():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    assert ".filter((run) => run && run.tool === 'aether')" in source
    assert ".sort((a, b) => (Number(b.created_at || 0) - Number(a.created_at || 0))" in source
    assert "const detail = await apiGet(`/api/run-history/${encodeURIComponent(latest.run_id)}`)" in source
    assert "function renderAetherOutputFiles(run = null)" in source
    assert "const relativePath = String(file.path || file.name || '')" in source
    assert "`/api/run-history/${encodeURIComponent(runId)}/download/${encodeURIComponent(relativePath)}`" in source
    assert "`/api/run-history/${encodeURIComponent(runId)}/download.zip`" in source
    assert "aether: { count: 'aether-output-count', list: 'aether-output-list' }" not in source


def test_aether_panel_labels_latest_run_scope_and_loads_on_page_start():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    assert 'id="aether-output-run-note"' in html
    assert 'latest Aether run only' in html
    assert "loadLatestAetherOutputs();" in js


def test_aether_active_run_invalidates_stale_output_requests():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "latestAetherOutputRequestId += 1;" in source
    assert "latestAetherOutputRunId = activeRunId;" in source
    assert "loadLatestAetherOutputs();" in source


def test_aether_downloads_are_compact_and_file_list_is_collapsed_by_default():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "const details = document.createElement('details')" in source
    assert "details.className = 'aether-output-files-details'" in source
    assert "summary.textContent = `Show individual files (${files.length.toLocaleString()})`" in source
    assert "list.className = 'aether-output-files-list'" in source
    assert "root.append(bundle)" in source
    assert "details.append(summary, list)" in source


def test_aether_panel_is_not_overwritten_by_current_other_tool_outputs():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "aether: { count: 'aether-output-count', list: 'aether-output-list' }" not in source
    assert "loadLatestAetherOutputs();" in source


def test_latest_aether_loader_serializes_poll_requests():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "let latestAetherOutputLoading = false;" in source
    assert "if (latestAetherOutputLoading) return;" in source
    assert "latestAetherOutputLoading = true;" in source
    assert "latestAetherOutputLoading = false;" in source
