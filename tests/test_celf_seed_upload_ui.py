from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_rule_selection_exposes_direct_celf_seed_upload_and_saved_rules_picker():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert '<label class="secondary-upload" for="seed-file">＋ Upload rules file</label>' in html
    assert 'id="celf-library-seed" data-library-field="seed"' in html
    assert 'id="celf-seed-state"' in html
    assert 'aria-label="CELF custom seed rules source"' in html


def test_celf_seed_controls_share_the_existing_seed_upload_and_library_state():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    # One real file input is deliberately reused by both upload buttons.
    assert html.count('id="seed-file"') == 1
    assert html.count('data-library-field="seed"') == 2
    assert "document.querySelectorAll('[data-library-field]')" in js
    assert "select.addEventListener('change', () => selectLibraryAsset(select.dataset.libraryField, select.value, select))" in js
    assert "function setSeedFileStatus(message" in js
    assert "[$('seed-state'), $('celf-seed-state')]" in js
    assert "setSeedFileStatus(`✓ ${result.name} · ${humanSize(result.size)}`)" in js
    assert "setSeedFileStatus(`✓ ${result.name} · ${humanSize(result.size)} · saved`)" in js
