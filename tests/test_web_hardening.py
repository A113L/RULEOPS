import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app


def _start_server(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "SECURITY_DB", tmp_path / "security.sqlite3")
    monkeypatch.setattr(app, "SESSIONS", {})
    monkeypatch.setattr(app, "LOGIN_FAILURES", {})
    server = app.RulestHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_address[1]}"


def _stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=3)


def _session_headers(monkeypatch, tmp_path):
    token = "test-session-token-123456789"
    csrf = "test-csrf-token-123456789"
    monkeypatch.setattr(app, "SESSIONS", {
        token: {"csrf": csrf, "expires": time.time() + 600}
    })
    return {"Cookie": f"rulest_session={token}", "X-CSRF-Token": csrf}


def test_security_headers_and_external_login_assets(tmp_path, monkeypatch):
    server, thread, base = _start_server(monkeypatch, tmp_path)
    try:
        with urllib.request.urlopen(base + "/", timeout=3) as response:
            page = response.read().decode("utf-8")
            csp = response.headers.get("Content-Security-Policy", "")
            assert "default-src 'self'" in csp
            assert "script-src 'self'" in csp
            assert "style-src 'self'" in csp
            assert "style-src-attr 'unsafe-inline'" in csp  # Used only for dynamic progress widths.
            assert "script-src 'self'" in csp and "script-src 'unsafe-inline'" not in csp
            assert "object-src 'none'" in csp
            assert "frame-ancestors 'none'" in csp
            assert "Permissions-Policy" in response.headers
            assert "Cross-Origin-Opener-Policy" in response.headers
            assert "Python" not in response.headers.get("Server", "")
            assert 'src="/login.js"' in page
            assert 'href="/login.css"' in page
            assert "<style" not in page and "<script>" not in page
        for asset in ("login.css", "login.js"):
            with urllib.request.urlopen(base + "/" + asset, timeout=3) as response:
                assert response.status == 200
                assert response.headers.get("Content-Security-Policy")
    finally:
        _stop_server(server, thread)


def test_login_throttle_persists_in_sqlite_across_in_memory_reset(tmp_path, monkeypatch):
    db_path = tmp_path / "security.sqlite3"
    monkeypatch.setattr(app, "SECURITY_DB", db_path)
    monkeypatch.setattr(app, "LOGIN_FAILURES", {})

    for _ in range(app.LOGIN_MAX_FAILURES):
        app.record_login_failure("192.0.2.10")

    first_lock = app.login_lock_remaining("192.0.2.10")
    assert first_lock > 0
    app.LOGIN_FAILURES.clear()  # Simulate loss of process-local memory on restart.
    assert app.login_lock_remaining("192.0.2.10") > 0
    assert db_path.exists()
    if hasattr(db_path, "stat") and sys.platform != "win32":
        assert db_path.stat().st_mode & 0o077 == 0

    app.reset_login_failures("192.0.2.10")
    assert app.login_lock_remaining("192.0.2.10") == 0


def test_repeated_login_lockouts_use_progressive_backoff(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "SECURITY_DB", tmp_path / "security.sqlite3")
    monkeypatch.setattr(app, "LOGIN_FAILURES", {})

    for _ in range(app.LOGIN_MAX_FAILURES):
        app.record_login_failure("192.0.2.11")
    first = app.login_lock_remaining("192.0.2.11")
    assert first > 0

    # Simulate expiry of the first lock without sleeping for five minutes.
    real_time = time.time
    offset = app.LOGIN_LOCK_SECONDS + 2
    monkeypatch.setattr(app.time, "time", lambda: real_time() + offset)
    assert app.login_lock_remaining("192.0.2.11") == 0
    for _ in range(app.LOGIN_MAX_FAILURES):
        app.record_login_failure("192.0.2.11")
    second = app.login_lock_remaining("192.0.2.11")
    assert second > app.LOGIN_LOCK_SECONDS


def test_connection_limit_returns_503_when_all_slots_are_in_use(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "MAX_CONCURRENT_CONNECTIONS", 1)
    server, thread, base = _start_server(monkeypatch, tmp_path)
    acquired = server._connection_slots.acquire(blocking=False)
    assert acquired
    try:
        request = urllib.request.Request(base + "/api/auth/me")
        try:
            urllib.request.urlopen(request, timeout=3)
            assert False, "Expected the bounded server to reject the excess connection."
        except urllib.error.HTTPError as exc:
            assert exc.code == 503
            assert "connection limit" in exc.read().decode("utf-8").lower()
    finally:
        server._connection_slots.release()
        _stop_server(server, thread)


def test_slow_incomplete_headers_are_closed_by_absolute_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "HEADER_TIMEOUT_SECONDS", 0.25)
    server, thread, _base = _start_server(monkeypatch, tmp_path)
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow:")
        time.sleep(0.45)
        client.settimeout(1)
        try:
            result = client.recv(1024)
        except (ConnectionResetError, OSError, socket.timeout):
            result = b""
        assert result == b""
    finally:
        client.close()
        _stop_server(server, thread)


def test_upload_per_file_and_aggregate_quotas_are_enforced_before_body_read(tmp_path, monkeypatch):
    data_dir = tmp_path / "runs"
    uploads_dir = data_dir / "uploads"
    uploads_dir.mkdir(parents=True)
    (uploads_dir / "already-there.bin").write_bytes(b"12345")
    monkeypatch.setattr(app, "DATA", data_dir)
    monkeypatch.setattr(app, "UPLOADS", uploads_dir)
    monkeypatch.setattr(app, "UPLOADS_META", {key: None for key in app.UPLOADS_META})
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    monkeypatch.setattr(app, "UPLOAD_RESERVATIONS", {})
    monkeypatch.setattr(app, "STATE", {**app.STATE, "status": "idle"})
    monkeypatch.setattr(app, "MAX_UPLOAD_BYTES", 100)
    monkeypatch.setattr(app, "MAX_TOTAL_UPLOAD_BYTES", 5)
    monkeypatch.setattr(app, "MAX_DATA_STORAGE_BYTES", 1024)
    monkeypatch.setattr(app, "MIN_FREE_DISK_BYTES", 0)
    server, thread, base = _start_server(monkeypatch, tmp_path)
    headers = _session_headers(monkeypatch, tmp_path)
    try:
        request = urllib.request.Request(
            base + "/api/upload/base?filename=base.txt",
            data=b"x",
            headers={**headers, "Content-Type": "application/octet-stream"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=3)
            assert False, "Expected aggregate upload quota rejection."
        except urllib.error.HTTPError as exc:
            assert exc.code == 413
            assert "combined temporary uploads" in exc.read().decode("utf-8").lower()
        assert not any(path.name.endswith("base.txt") for path in uploads_dir.iterdir())
    finally:
        _stop_server(server, thread)


def test_data_storage_quota_is_enforced_independently_of_upload_quota(tmp_path, monkeypatch):
    data_dir = tmp_path / "runs"
    uploads_dir = data_dir / "uploads"
    uploads_dir.mkdir(parents=True)
    (data_dir / "old-run").mkdir()
    (data_dir / "old-run" / "output.rule").write_bytes(b"123456")
    monkeypatch.setattr(app, "DATA", data_dir)
    monkeypatch.setattr(app, "UPLOADS", uploads_dir)
    monkeypatch.setattr(app, "UPLOADS_META", {key: None for key in app.UPLOADS_META})
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    monkeypatch.setattr(app, "UPLOAD_RESERVATIONS", {})
    monkeypatch.setattr(app, "STATE", {**app.STATE, "status": "idle"})
    monkeypatch.setattr(app, "MAX_UPLOAD_BYTES", 100)
    monkeypatch.setattr(app, "MAX_TOTAL_UPLOAD_BYTES", 100)
    monkeypatch.setattr(app, "MAX_DATA_STORAGE_BYTES", 6)
    monkeypatch.setattr(app, "MIN_FREE_DISK_BYTES", 0)
    server, thread, base = _start_server(monkeypatch, tmp_path)
    headers = _session_headers(monkeypatch, tmp_path)
    try:
        request = urllib.request.Request(
            base + "/api/upload/base?filename=base.txt",
            data=b"x",
            headers={**headers, "Content-Type": "application/octet-stream"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=3)
            assert False, "Expected application storage quota rejection."
        except urllib.error.HTTPError as exc:
            assert exc.code == 507
            assert "data quota" in exc.read().decode("utf-8").lower()
    finally:
        _stop_server(server, thread)


def test_slow_upload_times_out_and_releases_quota_reservation(tmp_path, monkeypatch):
    data_dir = tmp_path / "runs"
    uploads_dir = data_dir / "uploads"
    uploads_dir.mkdir(parents=True)
    monkeypatch.setattr(app, "DATA", data_dir)
    monkeypatch.setattr(app, "UPLOADS", uploads_dir)
    monkeypatch.setattr(app, "UPLOADS_META", {key: None for key in app.UPLOADS_META})
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    monkeypatch.setattr(app, "UPLOAD_RESERVATIONS", {})
    monkeypatch.setattr(app, "STATE", {**app.STATE, "status": "idle"})
    monkeypatch.setattr(app, "MAX_UPLOAD_BYTES", 1024)
    monkeypatch.setattr(app, "MAX_TOTAL_UPLOAD_BYTES", 1024)
    monkeypatch.setattr(app, "MAX_DATA_STORAGE_BYTES", 1024)
    monkeypatch.setattr(app, "MIN_FREE_DISK_BYTES", 0)
    monkeypatch.setattr(app, "UPLOAD_IDLE_TIMEOUT_SECONDS", 0.2)
    server, thread, _base = _start_server(monkeypatch, tmp_path)
    headers = _session_headers(monkeypatch, tmp_path)
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        request_headers = (
            "POST /api/upload/base?filename=slow.txt HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: 100\r\n"
            f"Cookie: {headers['Cookie']}\r\n"
            f"X-CSRF-Token: {headers['X-CSRF-Token']}\r\n"
            "\r\n"
        ).encode("ascii")
        client.sendall(request_headers + b"x")
        client.settimeout(2)
        response = b""
        while True:
            try:
                part = client.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            response += part
        assert b"408 Request Timeout" in response
        assert not list(uploads_dir.iterdir())
        assert not app.UPLOADS_ACTIVE
        assert not app.UPLOAD_RESERVATIONS
    finally:
        client.close()
        _stop_server(server, thread)


def test_upload_minimum_sustained_rate_is_enforced(tmp_path, monkeypatch):
    class FakeConnection:
        def settimeout(self, _seconds):
            pass

    class SlowReader:
        def read1(self, _size):
            time.sleep(0.12)
            return b"x"

    handler = object.__new__(app.Handler)
    handler.connection = FakeConnection()
    handler.rfile = SlowReader()
    monkeypatch.setattr(app, "UPLOAD_MIN_RATE_BYTES_PER_SECOND", 100)
    monkeypatch.setattr(app, "UPLOAD_RATE_GRACE_SECONDS", 0.1)
    monkeypatch.setattr(app, "UPLOAD_RATE_CHECK_INTERVAL_SECONDS", 0.1)
    try:
        import pytest
        with pytest.raises(TimeoutError, match="below the configured minimum"):
            handler.read_upload_to_file(tmp_path / "slow.bin", 100)
    finally:
        (tmp_path / "slow.bin").unlink(missing_ok=True)


def test_server_shutdown_closes_inflight_upload_and_cleans_partial_file(tmp_path, monkeypatch):
    data_dir = tmp_path / "runs"
    uploads_dir = data_dir / "uploads"
    uploads_dir.mkdir(parents=True)
    monkeypatch.setattr(app, "DATA", data_dir)
    monkeypatch.setattr(app, "UPLOADS", uploads_dir)
    monkeypatch.setattr(app, "UPLOADS_META", {key: None for key in app.UPLOADS_META})
    monkeypatch.setattr(app, "UPLOADS_ACTIVE", set())
    monkeypatch.setattr(app, "UPLOAD_RESERVATIONS", {})
    monkeypatch.setattr(app, "STATE", {**app.STATE, "status": "idle"})
    monkeypatch.setattr(app, "MAX_UPLOAD_BYTES", 1024)
    monkeypatch.setattr(app, "MAX_TOTAL_UPLOAD_BYTES", 1024)
    monkeypatch.setattr(app, "MAX_DATA_STORAGE_BYTES", 1024)
    monkeypatch.setattr(app, "MIN_FREE_DISK_BYTES", 0)
    monkeypatch.setattr(app, "UPLOAD_IDLE_TIMEOUT_SECONDS", 15)
    server, thread, _base = _start_server(monkeypatch, tmp_path)
    headers = _session_headers(monkeypatch, tmp_path)
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        request_headers = (
            "POST /api/upload/base?filename=shutdown.txt HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: 100\r\n"
            f"Cookie: {headers['Cookie']}\r\n"
            f"X-CSRF-Token: {headers['X-CSRF-Token']}\r\n"
            "\r\n"
        ).encode("ascii")
        client.sendall(request_headers + b"x")
        deadline = time.monotonic() + 2
        while not app.UPLOADS_ACTIVE and time.monotonic() < deadline:
            time.sleep(0.01)
        assert app.UPLOADS_ACTIVE
        start = time.monotonic()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert time.monotonic() - start < 2
        assert not thread.is_alive()
        assert not app.UPLOADS_ACTIVE
        assert not app.UPLOAD_RESERVATIONS
        assert not list(uploads_dir.iterdir())
    finally:
        client.close()
        if thread.is_alive():
            _stop_server(server, thread)


def test_run_storage_preflight_blocks_quota_and_free_space_reserve(tmp_path, monkeypatch):
    data_dir = tmp_path / "runs"
    data_dir.mkdir()
    (data_dir / "old-result.rule").write_bytes(b"123456")
    monkeypatch.setattr(app, "DATA", data_dir)
    monkeypatch.setattr(app, "MAX_DATA_STORAGE_BYTES", 5)
    monkeypatch.setattr(app, "MIN_FREE_DISK_BYTES", 0)
    ok, reason, used = app.storage_preflight()
    assert not ok and "quota" in reason.lower()
    assert used == 6

    monkeypatch.setattr(app, "MAX_DATA_STORAGE_BYTES", 100)
    monkeypatch.setattr(app, "MIN_FREE_DISK_BYTES", 10**30)
    ok, reason, _used = app.storage_preflight()
    assert not ok and "free disk" in reason.lower()


def test_duplicate_content_length_is_rejected_before_auth_dispatch(tmp_path, monkeypatch):
    server, thread, _base = _start_server(monkeypatch, tmp_path)
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        client.sendall(
            b"POST /api/auth/login HTTP/1.0\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 2\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n{}"
        )
        client.settimeout(2)
        chunks = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        response = b"".join(chunks)
        assert b"400 Bad Request" in response
        assert b"duplicate content-length" in response.lower()
    finally:
        client.close()
        _stop_server(server, thread)
