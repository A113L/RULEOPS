from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def _css_rule(source: str, selector: str) -> str:
    match = re.search(rf"{re.escape(selector)}\s*\{{([^}}]*)\}}", source, re.S)
    assert match, f"Missing CSS rule: {selector}"
    return match.group(1)


def test_each_tool_category_uses_its_own_keyboard_accessible_scroll_region():
    source = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    assert "tool-history-tool tool-history-tool--${tool}" in source
    assert "toolContent.className = 'tool-history-tool-content'" in source
    assert "toolContent.setAttribute('role', 'region')" in source
    assert "toolContent.tabIndex = 0" in source
    assert "toolContent.append(groupDetails)" in source
    assert "toolDetails.append(toolSummary, toolContent)" in source


def test_archive_scroll_is_independent_per_tool_not_on_the_outer_list():
    source = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
    outer = _css_rule(source, ".tool-run-history-list")
    category = _css_rule(source, ".tool-history-tool-content")

    assert "overflow-y" not in outer
    assert "max-height" not in outer
    assert "max-height" in category
    assert "overflow-y:auto" in category
    assert "overscroll-behavior:contain" in category
    assert "scrollbar-width:thin" in category
    assert "scrollbar-color:var(--tool-scroll-thumb) var(--tool-scroll-track)" in category


def test_all_six_tool_categories_have_a_distinct_scrollbar_theme():
    source = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
    for tool in ("rulest", "ranker", "concentrator", "rulestripper", "minimizer", "aether"):
        rule = _css_rule(source, f".tool-history-tool--{tool}")
        assert "--tool-scroll-thumb:" in rule
        assert "--tool-scroll-thumb-hover:" in rule


def test_tool_category_scrollbar_cache_key_is_bumped():
    source = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    assert source.count("tool-category-scroll=20261125a") == 2
