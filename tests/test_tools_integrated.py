"""Integration smoke tests for the three tools added to the RULEOPS UI."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import app as app_module

ROOT = Path(__file__).resolve().parents[1]


def _set_upload(monkeypatch, field, path):
    monkeypatch.setitem(app_module.UPLOADS_META, field, {
        "path": str(path), "name": path.name, "size": path.stat().st_size,
        "library": False,
    })


def test_rulestripper_builder_uses_shared_memory_runner_and_bounds(tmp_path, monkeypatch):
    base = tmp_path / "base.txt"
    target = tmp_path / "target.txt"
    base.write_text("password\n", encoding="utf-8")
    target.write_text("drowssap\n", encoding="utf-8")
    _set_upload(monkeypatch, "rulestripper_base", base)
    _set_upload(monkeypatch, "rulestripper_target", target)

    cmd, output = app_module.build_rulestripper_command({
        "max_depth": 6, "min_stem": 4, "leet_amb": 3,
        "workers": 0, "chunk_size": 0, "ascii_range": 3,
        "output_name": "extracted.rule",
    }, tmp_path)

    assert output == "extracted.rule"
    assert cmd[2] == str(ROOT / "run_rulestripper.py")
    assert str(base) in cmd and str(target) in cmd
    assert "--max-depth" in cmd and "6" in cmd
    assert "--no-color" in cmd


def test_minimizer_builder_forwards_probe_options(tmp_path, monkeypatch):
    rules = tmp_path / "input.rule"
    probes = tmp_path / "probe.txt"
    rules.write_text(":\nr\n", encoding="utf-8")
    probes.write_text("password\nadmin\n", encoding="utf-8")
    _set_upload(monkeypatch, "minimizer_rules", rules)
    _set_upload(monkeypatch, "minimizer_probe", probes)

    cmd, output = app_module.build_minimizer_command({
        "workers": 2, "probe_words": 64, "seed": 17,
        "extra_probes": "password admin", "multibyte": True,
        "output_name": "minimal.rule",
    }, tmp_path)

    assert output == "minimal.rule"
    assert cmd[2] == str(ROOT / "minimizer.py")
    assert "--probe-file" in cmd and str(probes) in cmd
    assert "--probe-words" in cmd and "64" in cmd
    assert "--seed" in cmd and "17" in cmd
    assert "--extra-probes" in cmd and "password" in cmd and "admin" in cmd
    assert "--multibyte" in cmd


def test_utility_upload_fields_are_reusable_library_assets():
    assert app_module.UTILITY_UPLOAD_FIELDS == {
        "rulestripper_base", "rulestripper_target", "minimizer_rules", "minimizer_probe"
    }
    assert app_module.LIBRARY_FIELD_CATEGORIES["rulestripper_base"] == "wordlists"
    assert app_module.LIBRARY_FIELD_CATEGORIES["rulestripper_target"] == "wordlists"
    assert app_module.LIBRARY_FIELD_CATEGORIES["minimizer_rules"] == "rules"
    assert app_module.LIBRARY_FIELD_CATEGORIES["minimizer_probe"] == "wordlists"


def test_email_extractor_is_local_client_side_page():
    html = (ROOT / "web" / "email-rule-extractor.html").read_text(encoding="utf-8")
    js = (ROOT / "web" / "email-rule-extractor.js").read_text(encoding="utf-8")
    assert 'src="/email-rule-extractor.js?v=2.6.1"' in html
    assert 'href="/email-rule-extractor.css?v=2.6.1"' in html
    assert 'href="/styles.css?v=2.6.1-ui-polish"' in html
    assert "hcrt.pages.dev" not in html + js
    assert not re.search(r"<script\b(?![^>]*\bsrc=)[^>]*>", html, flags=re.I)
    assert "FileReader" in js
    assert "createObjectURL" in js or "download" in js


def test_tool_cli_entry_points_show_help():
    for script in (ROOT / "run_rulestripper.py", ROOT / "minimizer.py"):
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=20,
        )
        assert result.returncode == 0, result.stderr
        assert "usage:" in result.stdout.lower()


def test_email_extractor_uses_shared_dark_theme_without_broken_css_prelude():
    html = (ROOT / "web" / "email-rule-extractor.html").read_text(encoding="utf-8")
    css = (ROOT / "web" / "email-rule-extractor.css").read_text(encoding="utf-8")

    assert html.index('/styles.css?') < html.index('/email-rule-extractor.css?')
    assert css.lstrip().startswith("/* Email Rule Extractor")
    assert ":root {" in css
    assert "--bg:" not in css  # inherit the canonical RULEOPS background token
    assert "var(--surface)" in css and "var(--accent)" in css
    assert "700;800&family=" not in css


def test_integrated_tool_panel_titles_and_descriptions_are_separate_blocks():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")

    assert html.count('class="utility-heading-copy"') == 4
    assert html.count('class="utility-monitor-heading"') == 2
    assert ".utility-heading-title h2 {" in css
    assert ".utility-heading-copy > p {" in css
    assert ".utility-monitor-heading h2 {" in css
    assert ".utility-tool-grid .stage-monitor-copy > b {" in css


def test_rulestripper_accepts_plain_text_wordlists_regardless_of_extension(tmp_path):
    # Linux-created files often have no suffix, while other sources use
    # arbitrary suffixes such as .found, .data or .backup. All are content-based.
    cases = (
        ("wordlist", b"password\nadmin\n"),
        ("targets.found", "drowssap\nhasło\n".encode("utf-8")),
        ("dump.data", b"alpha\nbeta\n"),
        ("dictionary.backup.2026", b"one\ntwo\n"),
        ("ordinary.txt", b"first\nsecond\n"),
    )
    for filename, content in cases:
        path = tmp_path / filename
        path.write_bytes(content)
        app_module._validate_rulestripper_upload("rulestripper_base", filename, path)

def test_rulestripper_rejects_binary_content_regardless_of_extension(tmp_path):
    # A misleading .txt suffix must not make a binary payload acceptable.
    binary = tmp_path / "actually-a-binary.txt"
    binary.write_bytes(b"\x00\x01\x02\x7f\x89PNG\r\n\x00")
    try:
        app_module._validate_rulestripper_upload("rulestripper_base", binary.name, binary)
    except ValueError as exc:
        assert "plain-text" in str(exc)
    else:
        raise AssertionError("binary data must not be accepted based on its filename")

def test_rulestripper_rejects_empty_wordlists(tmp_path):
    empty = tmp_path / "empty-wordlist"
    empty.write_bytes(b"")
    try:
        app_module._validate_rulestripper_upload("rulestripper_target", empty.name, empty)
    except ValueError as exc:
        assert "plain-text" in str(exc)
    else:
        raise AssertionError("empty files must not be accepted as wordlists")

def test_rulestripper_file_inputs_are_extension_agnostic_and_monitor_fields_are_separate():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
    assert '<input id="rulestripper_base-file" type="file">' in html
    assert '<input id="rulestripper_target-file" type="file">' in html
    assert html.count("Any plain-text wordlist · filename extension does not matter") == 2
    assert html.count('class="monitor-meta-item"') >= 4
    assert ".utility-tool-grid .monitor-meta-item" in css
    assert callable(getattr(app_module.Handler, "handle_upload", None))
