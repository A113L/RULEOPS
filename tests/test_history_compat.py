from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_legacy_load_history_callback_uses_shared_run_history_loader():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "function loadHistory(showToast = false)" in source
    assert "return loadToolRunHistory(showToast);" in source


def test_removed_aether_only_history_loader_is_not_referenced():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "loadAetherHistory" not in source
    assert "lastAetherHistoryRefresh" not in source
    assert "loadToolRunHistory();" in source


def test_app_script_cache_key_changes_for_history_compatibility_fix():
    source = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert "history-compat=20261124a" in source
