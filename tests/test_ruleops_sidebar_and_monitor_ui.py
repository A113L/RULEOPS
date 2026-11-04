from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
JS = (ROOT / "web" / "app.js").read_text(encoding="utf-8")


def test_sidebar_exposes_three_programs_and_rulest_submenu():
    assert 'id="nav-rulest"' in HTML
    assert 'id="rulest-subnav"' in HTML
    assert 'data-nav-tool="ranker"' in HTML
    assert 'data-nav-tool="concentrator"' in HTML
    assert 'data-nav-section="tuning"' in HTML
    assert 'data-nav-section="gpu-diagnostic"' in HTML
    assert 'data-nav-section="run-storage"' in HTML
    assert 'id="system-view"' in HTML


def test_ranker_legacy_choice_is_visible_and_functionally_wired():
    assert 'data-rank-mode="legacy"' in HTML
    assert 'Legacy exhaustive' in HTML
    assert "selectRankingMode(button.dataset.rankMode)" in JS
    assert "legacy: activeRankingMode === 'legacy'" in JS
    assert "sessionStorage.setItem('ruleops-ranker-mode'" in JS


def test_monitor_headings_have_separate_spaced_typographic_hierarchy():
    assert 'class="panel-heading-copy"><span class="side-panel-kicker">RANKER MONITOR</span><h2>Job activity</h2>' in HTML
    assert 'class="panel-heading-copy"><span class="side-panel-kicker">CONCENTRATOR MONITOR</span><h2>Job activity</h2>' in HTML
    assert ".panel-heading-copy{display:flex" in CSS
    assert "gap:6px" in CSS
    assert "color:#cbd4de" in CSS
    assert HTML.count('class="monitor-status-main"') == 3
    assert ".monitor-status-main>p" in CSS
    assert "font:10px/1.65 var(--sans)" in CSS
    assert ".monitor-details b" in CSS
    assert "font:600 12px/1.35 var(--sans)" in CSS


def test_frontend_assets_cache_key_was_bumped():
    assert "ruleops-2.4.6-security-hardening" in HTML


def test_sidebar_hash_links_resolve_to_real_dom_targets():
    import re
    hrefs = re.findall(r'<a\b[^>]*href="#([^"]+)"', HTML)
    ids = set(re.findall(r'\bid="([^"]+)"', HTML))
    missing = sorted(set(hrefs) - ids)
    assert not missing, f"Sidebar hash links have no target element: {missing}"
