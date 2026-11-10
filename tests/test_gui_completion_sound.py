from pathlib import Path

import app


def test_completion_sound_is_opt_out_and_tracks_all_job_types():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")

    assert 'id="completion-sound" type="checkbox" checked' in html
    assert "ruleops-completion-sound" in js
    assert "AudioContext" in js and "playCompletionSound()" in js
    assert "data.status === 'completed'" in js
    assert "pendingCompletionJobIds" in js
    assert "trackStartedJob(started)" in js
    assert js.count("trackStartedJob(started)") == 4


def test_reusable_library_dropdowns_cover_wordlists_and_rules_for_all_workspaces():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    expected = (
        "base", "target", "seed", "ranker_wordlist", "ranker_cracked",
        "ranker_rules", "ranker_source_rules", "concentrator_files",
    )
    for field in expected:
        assert f'data-library-field="{field}"' in html
    assert "fetch('/api/library'" in js
    assert "apiPost('/api/library/select'" in js
    assert "runs/library/wordlists" in (root / "INPUT_LIBRARY.md").read_text(encoding="utf-8")
    assert "runs/library/rules" in (root / "INPUT_LIBRARY.md").read_text(encoding="utf-8")
