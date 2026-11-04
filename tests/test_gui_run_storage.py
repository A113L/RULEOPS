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
