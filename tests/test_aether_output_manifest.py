import json
from pathlib import Path

import app


def _write_history_manifest(run_dir: Path, run_id: str, *, manifest_required: bool = True) -> None:
    payload = {
        "schema_version": 1,
        "run_id": run_id,
        "tool": "aether",
        "mode": "benchmark",
        "created_at": 100.0,
        "finished_at": 110.0,
        "exit_code": 0,
        "status": "completed",
        "inputs": [{"slot": 1, "name": "sample.rule", "size": 12, "output_stem": "sample"}],
        "group_names": ["sample.rule"],
        "aether_outputs_manifest_required": manifest_required,
    }
    (run_dir / app.RUN_HISTORY_MANIFEST).write_text(json.dumps(payload), encoding="utf-8")


def test_aether_history_and_zip_allowlist_excludes_leftovers_from_prior_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "DATA", tmp_path)
    run_id = "0123456789"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    _write_history_manifest(run_dir, run_id)

    (run_dir / "previous-run-1.json").write_text('{"run": 1}', encoding="utf-8")
    (run_dir / "previous-run-2.json").write_text('{"run": 2}', encoding="utf-8")
    (run_dir / "current-run.json").write_text('{"run": 3}', encoding="utf-8")

    app._write_aether_output_manifest(run_dir, run_id, [{"name": "current-run.json"}])

    # The history file collector is the shared source for both the Storage UI
    # and /download.zip; it must expose only the allowlisted current-run file.
    files = app._tool_history_files(run_dir)
    detail, resolved_dir = app.get_tool_history_run(run_id)
    assert resolved_dir == run_dir
    assert [entry["path"] for entry in files] == ["current-run.json"]
    assert [entry["path"] for entry in detail["files"]] == ["current-run.json"]
    assert (run_dir / app.AETHER_OUTPUTS_MANIFEST).is_file()


def test_invalid_aether_output_manifest_fails_closed(tmp_path):
    run_id = "abcdef1234"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    _write_history_manifest(run_dir, run_id)
    (run_dir / "output.json").write_text('{"ok": true}', encoding="utf-8")
    (run_dir / app.AETHER_OUTPUTS_MANIFEST).write_text(
        json.dumps({"schema_version": 1, "tool": "aether", "run_id": "wrong-id", "files": ["output.json"]}),
        encoding="utf-8",
    )

    assert app._tool_history_files(run_dir) == []


def test_legacy_aether_run_without_output_manifest_keeps_compatibility(tmp_path):
    run_id = "fedcba9876"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    _write_history_manifest(run_dir, run_id, manifest_required=False)
    (run_dir / "legacy-a.json").write_text("a", encoding="utf-8")
    (run_dir / "legacy-b.json").write_text("b", encoding="utf-8")

    assert {entry["path"] for entry in app._tool_history_files(run_dir)} == {"legacy-a.json", "legacy-b.json"}


def test_aether_outputs_manifest_is_not_exposed_as_an_artifact():
    source = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
    assert "AETHER_OUTPUTS_MANIFEST, AETHER_OUTPUTS_MANIFEST + \".tmp\"" in source
    assert "_write_aether_output_manifest(run_dir, run_id, outputs)" in source
    assert "aether_output_baseline.get(item.name) == signature" in source
