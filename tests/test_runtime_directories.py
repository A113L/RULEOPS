from pathlib import Path

import app


def test_runtime_directories_are_recreated_when_missing(tmp_path, monkeypatch):
    data = tmp_path / "runs"
    uploads = data / "uploads"
    monkeypatch.setattr(app, "DATA", data)
    monkeypatch.setattr(app, "UPLOADS", uploads)

    app.ensure_runtime_directories()

    assert data.is_dir()
    assert uploads.is_dir()


def test_runtime_directories_use_nested_missing_parent(tmp_path, monkeypatch):
    data = tmp_path / "not-created-yet" / "runs"
    uploads = data / "uploads"
    monkeypatch.setattr(app, "DATA", data)
    monkeypatch.setattr(app, "UPLOADS", uploads)

    app.ensure_runtime_directories()

    assert data.is_dir()
    assert uploads.is_dir()
