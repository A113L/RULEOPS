from pathlib import Path

import pytest

import app


def _isolated_run_storage(tmp_path, monkeypatch, status="idle"):
    data = tmp_path / "runs"
    uploads = data / "uploads"
    uploads.mkdir(parents=True)
    monkeypatch.setattr(app, "DATA", data)
    monkeypatch.setattr(app, "UPLOADS", uploads)
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    state = dict(app.STATE)
    state.update({"status": status, "run_dir": None, "outputs": []})
    monkeypatch.setattr(app, "STATE", state)
    return data, uploads, state


def test_run_storage_summary_counts_only_run_directories(tmp_path, monkeypatch):
    data, uploads, _ = _isolated_run_storage(tmp_path, monkeypatch)
    run_a = data / "abc123"
    run_b = data / "def456"
    run_a.mkdir()
    run_b.mkdir()
    (run_a / "engine.log").write_text("hello", encoding="utf-8")
    (run_a / "rules.rule").write_text("$1\n$2\n", encoding="utf-8")
    (run_b / "partial.txt").write_text("partial", encoding="utf-8")
    (uploads / "input.txt").write_text("upload", encoding="utf-8")

    summary = app.run_storage_summary()

    assert summary["run_directories"] == 2
    assert summary["files"] == 3
    assert summary["bytes"] == len(b"hello") + len(b"$1\n$2\n") + len(b"partial")
    assert summary["uploads_preserved"] is True


def test_clear_run_directories_preserves_uploads_and_authentication(tmp_path, monkeypatch):
    data, uploads, state = _isolated_run_storage(tmp_path, monkeypatch)
    run_dir = data / "abc123"
    run_dir.mkdir()
    (run_dir / "engine.log").write_text("history", encoding="utf-8")
    (uploads / "input.txt").write_text("temporary input", encoding="utf-8")
    auth_file = tmp_path / "auth.json"
    auth_file.write_text('{"password_hash":"not-empty"}', encoding="utf-8")
    state["run_dir"] = str(run_dir)
    state["outputs"] = [{"name": "engine.log", "size": 7}]

    result = app.clear_run_directories()

    assert result["deleted_directories"] == 1
    assert result["run_directories"] == 0
    assert not run_dir.exists()
    assert (uploads / "input.txt").read_text(encoding="utf-8") == "temporary input"
    assert auth_file.is_file()
    assert state["run_dir"] is None
    assert state["outputs"] == []


def test_clear_run_directories_refuses_while_job_is_active(tmp_path, monkeypatch):
    data, _, _ = _isolated_run_storage(tmp_path, monkeypatch, status="running")
    run_dir = data / "abc123"
    run_dir.mkdir()
    (run_dir / "engine.log").write_text("history", encoding="utf-8")

    with pytest.raises(RuntimeError, match="while a job is running"):
        app.clear_run_directories()

    assert run_dir.is_dir()
    assert (run_dir / "engine.log").is_file()


def test_clear_run_directories_refuses_during_upload(tmp_path, monkeypatch):
    data, _, _ = _isolated_run_storage(tmp_path, monkeypatch)
    run_dir = data / "abc123"
    run_dir.mkdir()
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", {"base"})

    with pytest.raises(RuntimeError, match="active uploads"):
        app.clear_run_directories()

    assert run_dir.is_dir()


def test_storage_ui_is_available_and_global_cleanup_is_confirmed():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    assert 'href="#run-storage"' in html
    assert 'id="run-storage"' in html  # navigation target must match the sidebar hash
    assert 'class="page-heading storage-page-heading"' in html
    assert 'class="storage-heading-copy"' in html
    assert 'storage-panel-heading-copy' in html
    assert 'v=ruleops-2.4.6-security-hardening' in html
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")
    assert ".storage-page-heading" in css
    assert ".storage-panel-heading-copy" in css
    assert ".storage-metrics .metric-value" in css
    assert 'id="system-view"' in html
    assert 'id="delete-run-directories"' in html
    assert "/api/run-storage/summary" in js
    assert "/api/run-storage/clear" in js
    assert "window.confirm(confirmation)" in js
    assert "id=\"local-engine-status\"" in html
    assert "updateLocalEngineBadge(data)" in js


def test_storage_http_endpoints_require_auth_and_csrf_and_clear_all_runs(tmp_path, monkeypatch):
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.cookies import SimpleCookie

    monkeypatch.setattr(app, "AUTH_FILE", tmp_path / "auth.json")
    data = tmp_path / "runs"
    uploads = data / "uploads"
    run_dir = data / "http-run-1"
    uploads.mkdir(parents=True)
    run_dir.mkdir()
    (run_dir / "rules.rule").write_text("$1\n", encoding="utf-8")
    (uploads / "input.txt").write_text("input", encoding="utf-8")
    monkeypatch.setattr(app, "DATA", data)
    monkeypatch.setattr(app, "UPLOADS", uploads)
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    state = dict(app.STATE)
    state.update({"status": "idle", "run_dir": str(run_dir), "outputs": [{"name": "rules.rule", "size": 3}]})
    monkeypatch.setattr(app, "STATE", state)
    monkeypatch.setattr(app, "SESSIONS", {})
    server = app.RulestHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def request_json(path, payload=None, cookie=None, csrf=None):
        headers = {}
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        if body is not None:
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(base + path, data=body, headers=headers)
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        return response, json.loads(response.read().decode("utf-8"))

    try:
        response, summary = request_json("/api/run-storage/summary")
        assert response.code == 401
        response, intelligence = request_json("/api/run-storage/intelligence")
        assert response.code == 401
        response, setup = request_json("/api/auth/setup", {"password": "run-storage-secure-password"})
        assert response.code == 200
        cookie = "rulest_session=" + SimpleCookie(response.headers["Set-Cookie"])["rulest_session"].value
        csrf = setup["csrf_token"]

        response, status = request_json("/api/status", cookie=cookie)
        assert status["engine_badge"] == {"label": "READY", "state": "ready"}
        state["status"] = "running"
        response, status = request_json("/api/status", cookie=cookie)
        assert status["engine_badge"] == {"label": "RUNNING", "state": "running"}
        state["status"] = "idle"

        response, summary = request_json("/api/run-storage/summary", cookie=cookie)
        assert response.code == 200 and summary["run_directories"] == 1
        response, intelligence = request_json("/api/run-storage/intelligence", cookie=cookie)
        assert response.code == 200
        assert intelligence["total_files"] == 2
        assert intelligence["largest_files"][0]["name"] == "rules.rule"
        assert intelligence["buckets"][0]["key"] == "runs"
        response, denied = request_json("/api/run-storage/clear", {}, cookie=cookie)
        assert response.code == 403

        response, result = request_json("/api/run-storage/clear", {}, cookie=cookie, csrf=csrf)
        assert response.code == 200 and result["ok"] is True
        assert result["deleted_directories"] == 1
        assert not run_dir.exists()
        assert (uploads / "input.txt").is_file()
        assert state["run_dir"] is None and state["outputs"] == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_scan_finds_empty_and_log_only_directories_but_preserves_outputs_and_uploads(tmp_path, monkeypatch):
    data, uploads, _ = _isolated_run_storage(tmp_path, monkeypatch)
    (data / "empty-run").mkdir()
    logs = data / "logs-only"
    logs.mkdir()
    (logs / "engine.log").write_text("history\n", encoding="utf-8")
    nested = data / "nested-logs-only" / "logs"
    nested.mkdir(parents=True)
    (nested / "worker.LOG").write_text("worker history\n", encoding="utf-8")
    output_run = data / "has-output"
    output_run.mkdir()
    (output_run / "engine.log").write_text("history\n", encoding="utf-8")
    (output_run / "result.rule").write_text("$1\n", encoding="utf-8")
    (uploads / "input.txt").write_text("upload", encoding="utf-8")

    scan = app.scan_run_storage_cleanup_candidates()

    assert {item["name"] for item in scan["log_only_directories"]} == {
        "empty-run", "logs-only", "nested-logs-only"
    }
    assert scan["log_only_count"] == 3
    assert scan["duplicate_directories"] == 0
    assert (output_run / "result.rule").is_file()
    assert (uploads / "input.txt").is_file()


def test_scan_detects_exact_directory_duplicates_by_relative_path_and_sha256(tmp_path, monkeypatch):
    data, uploads, state = _isolated_run_storage(tmp_path, monkeypatch)
    first = data / "run-first"
    second = data / "run-second"
    different_layout = data / "run-other-layout"
    for folder in (first, second, different_layout):
        folder.mkdir()
    for folder in (first, second):
        (folder / "rules" ).mkdir()
        (folder / "rules" / "output.rule").write_bytes(b"$1\n$2\n")
        (folder / "engine.log").write_bytes(b"same engine log")
    (different_layout / "output.rule").write_bytes(b"$1\n$2\n")
    state["run_dir"] = str(second)

    scan = app.scan_run_storage_cleanup_candidates()

    assert scan["duplicate_group_count"] == 1
    assert scan["duplicate_directories"] == 1
    group = scan["duplicate_groups"][0]
    assert group["keep"] == "run-second"  # active STATE.run_dir is preserved
    assert group["duplicates"] == ["run-first"]
    assert group["files"] == 2
    assert group["reclaimable_bytes"] == (len(b"$1\n$2\n") + len(b"same engine log"))
    assert (data / "run-other-layout").is_dir()
    assert uploads.is_dir()


def test_delete_log_only_runs_rechecks_candidates_and_preserves_non_log_files(tmp_path, monkeypatch):
    data, uploads, state = _isolated_run_storage(tmp_path, monkeypatch)
    log_only = data / "log-only"
    log_only.mkdir()
    (log_only / "engine.log").write_text("history", encoding="utf-8")
    empty = data / "empty"
    empty.mkdir()
    keep = data / "keep-output"
    keep.mkdir()
    (keep / "engine.log").write_text("history", encoding="utf-8")
    (keep / "rules.rule").write_text("$1", encoding="utf-8")
    (uploads / "input.txt").write_text("input", encoding="utf-8")
    state["run_dir"] = str(log_only)
    state["outputs"] = [{"name": "engine.log", "size": 7}]

    result = app.delete_log_only_run_directories()

    assert result["deleted_directories"] == 2
    assert set(result["deleted_names"]) == {"log-only", "empty"}
    assert not log_only.exists() and not empty.exists()
    assert keep.is_dir() and (keep / "rules.rule").is_file()
    assert (uploads / "input.txt").is_file()
    assert state["run_dir"] is None and state["outputs"] == []


def test_delete_duplicates_keeps_one_copy_and_only_removes_exact_matches(tmp_path, monkeypatch):
    data, uploads, _ = _isolated_run_storage(tmp_path, monkeypatch)
    folders = [data / name for name in ("copy-a", "copy-b", "copy-c")]
    for folder in folders:
        folder.mkdir()
        (folder / "output.txt").write_bytes(b"identical output\n")
        (folder / "nested").mkdir()
        (folder / "nested" / "meta.bin").write_bytes(b"\x00\x01\x02")
    (folders[2] / "output.txt").write_bytes(b"different output\n")
    (uploads / "input.txt").write_text("upload", encoding="utf-8")

    scan = app.scan_run_storage_cleanup_candidates()
    assert scan["duplicate_group_count"] == 1
    assert scan["duplicate_directories"] == 1
    keep_name = scan["duplicate_groups"][0]["keep"]
    duplicate_name = scan["duplicate_groups"][0]["duplicates"][0]

    result = app.delete_duplicate_run_directories()

    assert result["deleted_directories"] == 1
    assert result["deleted_names"] == [duplicate_name]
    assert result["retained_directories"] == [keep_name]
    assert (data / keep_name).is_dir()
    assert not (data / duplicate_name).exists()
    assert (data / "copy-c").is_dir()  # differing checksum was not touched
    assert (uploads / "input.txt").is_file()


def test_scan_and_targeted_deletes_are_locked_during_jobs_and_uploads(tmp_path, monkeypatch):
    data, _, _ = _isolated_run_storage(tmp_path, monkeypatch, status="running")
    log_dir = data / "log-only"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text("log", encoding="utf-8")
    with pytest.raises(RuntimeError, match="while a job is running"):
        app.scan_run_storage_cleanup_candidates()
    with pytest.raises(RuntimeError, match="while a job is running"):
        app.delete_log_only_run_directories()
    with pytest.raises(RuntimeError, match="while a job is running"):
        app.delete_duplicate_run_directories()

    state = dict(app.STATE)
    state.update({"status": "idle", "run_dir": None, "outputs": []})
    monkeypatch.setattr(app, "STATE", state)
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", {"base"})
    with pytest.raises(RuntimeError, match="active uploads"):
        app.scan_run_storage_cleanup_candidates()
    with pytest.raises(RuntimeError, match="active uploads"):
        app.delete_log_only_run_directories()
    with pytest.raises(RuntimeError, match="active uploads"):
        app.delete_duplicate_run_directories()
    assert log_dir.is_dir()


def test_run_storage_ui_exposes_targeted_scan_and_delete_actions():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    assert 'id="scan-run-storage"' in html
    assert 'id="delete-log-only-directories"' in html
    assert 'id="delete-duplicate-directories"' in html
    assert "/api/run-storage/scan" in js
    assert "/api/run-storage/delete-log-only" in js
    assert "/api/run-storage/delete-duplicates" in js
    assert "SHA-256" in html


def test_targeted_run_storage_http_endpoints_require_authentication_and_csrf(tmp_path, monkeypatch):
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.cookies import SimpleCookie

    monkeypatch.setattr(app, "AUTH_FILE", tmp_path / "auth.json")
    data = tmp_path / "runs"
    uploads = data / "uploads"
    log_dir = data / "logs-only"
    uploads.mkdir(parents=True)
    log_dir.mkdir()
    (log_dir / "engine.log").write_text("old log", encoding="utf-8")
    monkeypatch.setattr(app, "DATA", data)
    monkeypatch.setattr(app, "UPLOADS", uploads)
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    state = dict(app.STATE)
    state.update({"status": "idle", "run_dir": None, "outputs": []})
    monkeypatch.setattr(app, "STATE", state)
    monkeypatch.setattr(app, "SESSIONS", {})
    server = app.RulestHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def request_json(path, payload=None, cookie=None, csrf=None):
        headers = {}
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        if body is not None:
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(base + path, data=body, headers=headers, method="POST")
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            response = exc
        return response, json.loads(response.read().decode("utf-8"))

    try:
        response, _ = request_json("/api/run-storage/scan", {})
        assert response.code == 401
        response, setup = request_json("/api/auth/setup", {"password": "targeted-storage-secure-password"})
        assert response.code == 200
        cookie = "rulest_session=" + SimpleCookie(response.headers["Set-Cookie"])["rulest_session"].value
        csrf = setup["csrf_token"]

        response, _ = request_json("/api/run-storage/scan", {}, cookie=cookie)
        assert response.code == 403
        response, scan = request_json("/api/run-storage/scan", {}, cookie=cookie, csrf=csrf)
        assert response.code == 200 and scan["ok"] is True and scan["log_only_count"] == 1
        response, deleted = request_json("/api/run-storage/delete-log-only", {}, cookie=cookie, csrf=csrf)
        assert response.code == 200 and deleted["deleted_directories"] == 1
        assert not log_dir.exists()

        duplicate_a = data / "duplicate-a"
        duplicate_b = data / "duplicate-b"
        duplicate_a.mkdir()
        duplicate_b.mkdir()
        (duplicate_a / "result.rule").write_bytes(b"$1\n$2\n")
        (duplicate_b / "result.rule").write_bytes(b"$1\n$2\n")
        response, scan = request_json("/api/run-storage/scan", {}, cookie=cookie, csrf=csrf)
        assert response.code == 200 and scan["duplicate_directories"] == 1
        response, duplicate_result = request_json("/api/run-storage/delete-duplicates", {}, cookie=cookie, csrf=csrf)
        assert response.code == 200 and duplicate_result["deleted_directories"] == 1
        assert sum(folder.is_dir() for folder in (duplicate_a, duplicate_b)) == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_scan_skips_symlinked_run_contents_and_storage_preflight_blocks_new_runs(tmp_path, monkeypatch):
    data, _, _ = _isolated_run_storage(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "protected.rule").write_text("$1", encoding="utf-8")
    unsafe = data / "unsafe-run"
    unsafe.mkdir()
    try:
        (unsafe / "linked-output").symlink_to(outside / "protected.rule")
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are not supported by this test environment.")

    scan = app.scan_run_storage_cleanup_candidates()
    assert scan["skipped_unsafe_directories"] == 1
    assert not scan["log_only_directories"]
    assert (outside / "protected.rule").is_file()

    with app._run_storage_maintenance():
        ok, message, _ = app.storage_preflight()
        assert not ok
        assert "being scanned or cleaned up" in message


def test_run_storage_has_library_filename_search_duplicate_selection_and_download_controls():
    html = (app.WEB / "index.html").read_text(encoding="utf-8")
    script = (app.WEB / "app.js").read_text(encoding="utf-8")
    assert 'id="library-search-query"' in html
    assert 'id="library-search-results"' in html
    assert 'id="scan-library-duplicates"' in html
    assert 'id="library-duplicate-results"' in html
    assert 'id="delete-selected-library-files"' in html
    assert "/api/library/search?q=" in script
    assert "/api/library/download?" in script
    assert "/api/library/delete-selected" in script
    assert "library-duplicate-checkbox" in script
    assert "Search files across storage" in html
    assert "completed work folders" in html
    assert "/api/run-storage/file-download?" in script
    assert "/api/run-storage/download-outputs.zip" in script
    assert "ownedOutputs.length > 3" in script
    assert "download-output-bundle" in script


def test_storage_intelligence_reports_breakdown_largest_files_and_folders(tmp_path, monkeypatch):
    data, uploads, _state = _isolated_run_storage(tmp_path, monkeypatch)
    library = data / "library"
    wordlists = library / "wordlists"
    rules = library / "rules"
    wordlists.mkdir(parents=True)
    rules.mkdir(parents=True)
    (data / "job-001").mkdir()
    (data / "job-001" / "large-output.bin").write_bytes(b"R" * 120)
    (wordlists / "wordlist.txt").write_bytes(b"W" * 70)
    (rules / "rules.rule").write_bytes(b"$1\n$2\n")
    (uploads / "temporary.txt").write_bytes(b"U" * 15)
    monkeypatch.setattr(app, "_STORAGE_INTELLIGENCE_STATE", {
        "last_run_scan": None, "last_library_scan": None, "activity": [],
    })

    summary = app.storage_intelligence_summary()

    assert summary["total_bytes"] >= 211
    assert summary["total_files"] == 4
    assert summary["run_directories"] == 1
    buckets = {item["key"]: item for item in summary["buckets"]}
    assert buckets["runs"]["bytes"] == 120
    assert buckets["library"]["bytes"] == 76
    assert buckets["uploads"]["bytes"] == 15
    assert summary["library"]["wordlist_files"] == 1
    assert summary["library"]["rule_files"] == 1
    assert summary["largest_files"][0]["name"] == "large-output.bin"
    assert summary["largest_files"][0]["source"] == "run"
    assert "file-download" in summary["largest_files"][0]["download_url"]
    assert any(item["name"] == "wordlist.txt" for item in summary["recent_library_files"])
    assert "api/library/download" in summary["recent_library_files"][0]["download_url"]
    assert any(item["name"] == "job-001" for item in summary["largest_folders"])
    assert any(item["name"] == "wordlists" for item in summary["largest_folders"])


def test_storage_intelligence_includes_recent_scan_activity_and_verified_cleanup_estimates(tmp_path, monkeypatch):
    data, _uploads, _state = _isolated_run_storage(tmp_path, monkeypatch)
    log_folder = data / "logs-only"
    log_folder.mkdir()
    (log_folder / "engine.log").write_text("log", encoding="utf-8")
    monkeypatch.setattr(app, "_STORAGE_INTELLIGENCE_STATE", {
        "last_run_scan": None, "last_library_scan": None, "activity": [],
    })

    scan = app.scan_run_storage_cleanup_candidates()
    summary = app.storage_intelligence_summary()

    assert scan["log_only_count"] == 1
    assert summary["cleanup"]["log_only_count"] == 1
    assert summary["cleanup"]["log_only_bytes"] == 3
    assert summary["cleanup"]["run_scanned_at"]
    assert summary["activity"][0]["action"] == "Run folder scan"
    assert summary["history_scope"] == "since server start"


def test_storage_intelligence_ui_has_dashboard_sections_and_refresh_route():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")
    assert 'id="storage-intelligence-title"' in html
    assert 'id="storage-intel-breakdown"' in html
    assert 'id="storage-intel-cleanup"' in html
    assert 'id="storage-intel-largest-files"' in html
    assert 'id="storage-intel-largest-folders"' in html
    assert 'id="storage-intel-activity"' in html
    assert "/api/run-storage/intelligence" in js
    assert "renderStorageIntelligence(data)" in js
    assert ".storage-workspace-grid" in css
    assert ".storage-intelligence-panel" in css
