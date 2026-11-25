from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_run_history_persists_absolute_input_filepaths():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert 'record["filepath"] = os.path.abspath(raw_path)' in source
    assert '"filepath": str(path.resolve())' in source
    assert 'os.path.isabs(filepath)' in source


def test_run_history_artifacts_expose_absolute_paths():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert '"absolute_path": os.path.abspath(str(directory / Path(path.as_posix())))' in source


def test_run_storage_ui_displays_absolute_input_and_artifact_paths():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "Input filepath:" in source
    assert "const pathInputs = matchingInputs.length ? matchingInputs : allInputs;" in source
    assert "file.absolute_path" in source
    assert "Filepath: ${absolutePath}" in source


def test_run_storage_ui_cache_key_was_bumped():
    source = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert "storage-absolute-filepaths=20261125b" in source
