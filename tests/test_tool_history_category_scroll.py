from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def _css_rule(source: str, selector: str) -> str:
    match = re.search(rf"{re.escape(selector)}\s*\{{([^}}]*)\}}", source, re.S)
    assert match, f"Missing CSS rule: {selector}"
    return match.group(1)


def test_previous_runs_is_one_keyboard_accessible_scroll_region():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    assert "root.setAttribute('role', 'region')" in source
    assert "root.setAttribute('aria-label', 'Previous tool runs')" in source
    assert "root.tabIndex = 0" in source
    assert "toolContent.className = 'tool-history-tool-content'" in source
    assert "toolContent.append(groupDetails)" in source


def test_previous_runs_outer_box_owns_the_styled_scrollbar():
    source = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
    outer = _css_rule(source, ".tool-run-history-list")
    category = _css_rule(source, ".tool-history-tool-content")

    assert "height:min(590px,66vh)" in outer
    assert "overflow-y:scroll !important" in outer
    assert "overscroll-behavior-y:contain" in outer
    assert "scrollbar-width:auto" in outer
    assert "scrollbar-color:var(--history-scroll-thumb) #111923" in outer
    assert ".tool-run-history-list::-webkit-scrollbar{width:13px;height:13px;}" in source
    assert "overflow-y" not in category
    assert "max-height:none !important" in category


def test_previous_runs_scrollbar_styles_are_cache_busted():
    source = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert source.count("storage-previous-runs-scroll=20261126b") == 2

