import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

import app


def _setup_server(tmp_path, monkeypatch):
    data_dir = tmp_path / "runs"
    uploads_dir = data_dir / "uploads"
    uploads_dir.mkdir(parents=True)
    monkeypatch.setattr(app, "DATA", data_dir)
    monkeypatch.setattr(app, "UPLOADS", uploads_dir)
    monkeypatch.setattr(app, "UPLOADS_META", {
        "base": None, "target": None, "seed": None,
        "ranker_wordlist": None, "ranker_cracked": None, "ranker_rules": None,
        "ranker_source_csv": None, "ranker_source_rules": None, "ranker_analysis_csv": None,
        "concentrator_files": [],
    })
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    monkeypatch.setattr(app, "UPLOAD_RESERVATIONS", {})
    monkeypatch.setattr(app, "STATE", {
        **app.STATE, "status": "idle", "run_dir": None, "outputs": [], "logs": [],
    })
    monkeypatch.setattr(app, "MAX_UPLOAD_BYTES", 1024 * 1024)
    monkeypatch.setattr(app, "MAX_TOTAL_UPLOAD_BYTES", 1024 * 1024)
    monkeypatch.setattr(app, "MAX_DATA_STORAGE_BYTES", 4 * 1024 * 1024)
    monkeypatch.setattr(app, "MIN_FREE_DISK_BYTES", 0)
    monkeypatch.setattr(app, "SESSIONS", {
        "library-test-session": {
            "csrf": "library-test-csrf", "expires": time.time() + 600, "role": "admin",
        }
    })
    server = app.RulestHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    headers = {
        "Cookie": "rulest_session=library-test-session",
        "X-CSRF-Token": "library-test-csrf",
    }
    return server, thread, base_url, headers, data_dir, uploads_dir


def _stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def _request_json(url, headers, payload=None, raw=None, method=None):
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        request_headers = {**headers, "Content-Type": "application/json"}
    else:
        body = raw
        request_headers = {**headers, "Content-Type": "application/octet-stream"}
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))
    with response:
        return response.status, json.loads(response.read().decode("utf-8"))


def test_wordlist_upload_is_moved_into_persistent_library_without_duplicate_copy(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        status, result = _request_json(
            base + "/api/upload/base?filename=large%20dictionary.txt",
            headers, raw=b"alpha\nbeta\ngamma\n", method="POST",
        )
        assert status == 200 and result["ok"] is True
        assert result["library"] is True
        assert result["category"] == "wordlists"
        asset = data_dir / "library" / "wordlists" / result["asset_id"]
        assert asset.read_bytes() == b"alpha\nbeta\ngamma\n"
        assert list(uploads_dir.iterdir()) == []
        assert app.UPLOADS_META["base"]["path"] == asset
        assert app.UPLOADS_META["base"]["library"] is True
    finally:
        _stop_server(server, thread)


def test_saved_assets_can_be_listed_selected_and_survive_run_cleanup(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        wordlist_dir = data_dir / "library" / "wordlists"
        rules_dir = data_dir / "library" / "rules"
        wordlist_dir.mkdir(parents=True)
        rules_dir.mkdir(parents=True)
        word_id = "a" * 32 + "_common_words.txt"
        rules_id = "b" * 32 + "_best_rules.rule"
        (wordlist_dir / word_id).write_bytes(b"password\nwelcome\n")
        (rules_dir / rules_id).write_bytes(b":\n$1\n")

        status, listed = _request_json(base + "/api/library", headers, method="GET")
        assert status == 200
        assert [item["id"] for item in listed["wordlists"]] == [word_id]
        assert [item["id"] for item in listed["rules"]] == [rules_id]

        status, selected = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "target", "asset_id": word_id}, method="POST",
        )
        assert status == 200 and selected["ok"] is True
        assert app.UPLOADS_META["target"]["path"] == wordlist_dir / word_id
        assert app.UPLOADS_META["target"]["name"] == "common_words.txt"

        status, selected_rules = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "seed", "asset_id": rules_id}, method="POST",
        )
        assert status == 200 and selected_rules["category"] == "rules"
        assert app.UPLOADS_META["seed"]["path"] == rules_dir / rules_id

        # Selecting a persistent asset and ending a job must only clear the
        # active references; the on-disk reusable library remains untouched.
        app.cleanup_uploaded_files(log_message=False)
        assert app.UPLOADS_META["target"] is None
        assert (wordlist_dir / word_id).is_file()
        assert (rules_dir / rules_id).is_file()

        run_dir = data_dir / "run-to-delete"
        run_dir.mkdir()
        (run_dir / "output.rule").write_text(":\n", encoding="utf-8")
        result = app.clear_run_directories()
        assert result["deleted_directories"] == 1
        assert not run_dir.exists()
        assert (wordlist_dir / word_id).is_file()
        assert (rules_dir / rules_id).is_file()
        assert result["library_preserved"] is True
    finally:
        _stop_server(server, thread)


def test_library_selection_rejects_traversal_and_wrong_input_category(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        rules_dir = data_dir / "library" / "rules"
        rules_dir.mkdir(parents=True)
        rules_id = "c" * 32 + "_only.rule"
        (rules_dir / rules_id).write_text(":\n", encoding="utf-8")

        status, result = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "base", "asset_id": rules_id}, method="POST",
        )
        assert status == 404
        assert "no longer exists" in result["error"].lower() or "invalid" in result["error"].lower()
        assert app.UPLOADS_META["base"] is None

        status, result = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "base", "asset_id": "../../etc/passwd"}, method="POST",
        )
        assert status == 404
        assert app.UPLOADS_META["base"] is None

        status, result = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "ranker_analysis_csv", "asset_id": rules_id}, method="POST",
        )
        assert status == 400
    finally:
        _stop_server(server, thread)


def test_concentrator_can_select_multiple_saved_rule_files_and_deduplicates(tmp_path, monkeypatch):
    server, thread, base, headers, data_dir, _uploads_dir = _setup_server(tmp_path, monkeypatch)
    try:
        rules_dir = data_dir / "library" / "rules"
        rules_dir.mkdir(parents=True)
        ids = [f"{letter * 32}_rule_{letter}.rule" for letter in ("d", "e")]
        for asset_id in ids:
            (rules_dir / asset_id).write_text(":\n", encoding="utf-8")

        for asset_id in ids:
            status, result = _request_json(
                base + "/api/library/select", headers,
                payload={"field": "concentrator_files", "asset_id": asset_id}, method="POST",
            )
            assert status == 200 and result["ok"] is True
        assert len(app.UPLOADS_META["concentrator_files"]) == 2

        status, duplicate = _request_json(
            base + "/api/library/select", headers,
            payload={"field": "concentrator_files", "asset_id": ids[0]}, method="POST",
        )
        assert status == 200 and duplicate["already_selected"] is True
        assert len(app.UPLOADS_META["concentrator_files"]) == 2
    finally:
        _stop_server(server, thread)
