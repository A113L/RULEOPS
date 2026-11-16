from pathlib import Path

import app


def test_about_page_preserves_tool_descriptions_donations_and_support():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert 'href="#about"' in html
    assert '<b>About</b>' in html
    assert 'id="about"' in html and 'id="about-grid"' in html
    assert 'Local-first' in html
    assert 'One toolchain, six integrated tools' in html
    for tool_name in ('RULEST', 'Rule Ranker', 'Concentrator', 'Rulestripper', 'Rule Minimizer', 'Email Rule Extractor'):
        assert tool_name in html
    assert 'Donations are entirely optional' in html
    assert '0x597c06b19bc90876f6375b8d1348b34c94f223a4' in html
    assert '13jsg1BFDegtiz5q5h5AKYVQDwo8YAh8SJ' in html
    assert 'LLDEKP1L7Zs99cYHSVdxXHZPUaR5Hcpand' in html
    assert 'RHXGULWc3jcgSHB9LAEmRCGnddRemnZ6hu' in html
    assert 'TWCr67GVVWYmPhDadGFzqWu5rcWuqwD8gi' in html
    assert 'nullpointer@i2pmail.org' in html
    assert 'a_1_1_3_1' in html
    assert 'about-user-panel' in html
    assert 'applyAdminVisibility' in js
    assert 'voluntary cryptocurrency donations' in readme.lower()


def test_about_navigation_and_user_password_control_are_wired():
    root = Path(app.__file__).resolve().parent
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    assert "href === '#about'" in js
    assert "setActiveSystemView('about')" in js
    assert "wireAboutAccessControls" in js
    assert "apiPost('/api/auth/set-user-password'" in js


def test_about_page_uses_shared_card_spacing_and_stacked_tool_headings():
    root = Path(app.__file__).resolve().parent
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")
    html = (root / "web" / "index.html").read_text(encoding="utf-8")

    # The tool title and subtitle must be separate flex rows, not adjacent
    # inline text such as "RULESTRule generation engine".
    assert ".usecase-head{\n  display:flex;" in css
    assert ".usecase-head b{\n  display:block;" in css
    assert ".usecase-head small{\n  display:block;" in css
    assert "grid-template-columns:repeat(3,minmax(0,1fr))" in css
    assert ".donation-row{\n  display:grid;" in css
    assert ".contact-row{\n  display:grid;" in css
    assert "@media(max-width:650px)" in css
    assert "build=2.6.4" in html


def test_celf_comparison_fills_primary_about_column_below_tool_cards():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")

    primary_column = html.index('<div class="primary-column">')
    tool_cards = html.index('<section class="panel usecases-panel"')
    celf_guide = html.index('<section class="panel about-celf-panel" id="about-celf-comparison"')
    secondary_column = html.index('<div class="secondary-column">')

    assert primary_column < tool_cards < celf_guide < secondary_column
    assert 'id="about-celf-comparison" hidden' not in html
    assert ".about-grid .about-celf-panel" in css


def test_about_sidebar_uses_remaining_space_for_ruleops_brand_emblem():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")

    secondary_column = html.index('<div class="secondary-column">', html.index('id="about-grid"'))
    brand_panel = html.index('class="panel about-brand-emblem-panel"', secondary_column)
    donations_panel = html.index('class="panel donations-panel"', secondary_column)
    user_panel = html.index('id="about-user-panel"', secondary_column)

    assert secondary_column < brand_panel < donations_panel < user_panel
    assert 'id="about-brand-logo-title"' in html
    assert 'HASHCAT RULE TOOLCHAIN' in html
    assert '.about-grid{align-items:stretch}' in css
    assert '.about-brand-emblem-panel{' in css
    assert 'flex:1 1 280px' in css


def test_all_about_tool_cards_have_styled_navigation_links():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")

    expected = {
        'data-tool="rulest"': ('href="#workspace"', 'data-nav-tool="rulest"'),
        'data-tool="ranker"': ('href="#ranker"', 'data-nav-tool="ranker"'),
        'data-tool="concentrator"': ('href="#concentrator"', 'data-nav-tool="concentrator"'),
        'data-tool="rulestripper"': ('href="#rulestripper"', 'data-nav-tool="rulestripper"'),
        'data-tool="minimizer"': ('href="#minimizer"', 'data-nav-tool="minimizer"'),
        'data-tool="email-extractor"': ('href="/email-rule-extractor.html"',),
    }
    for card_marker, link_bits in expected.items():
        card_start = html.index(card_marker, html.index('id="about-grid"'))
        card_end = html.index('</article>', card_start)
        card = html[card_start:card_end]
        assert 'class="about-tool-link"' in card
        for bit in link_bits:
            assert bit in card

    assert '.usecase-card .about-tool-link{' in css
    assert '.usecase-card .about-tool-link:focus-visible{' in css
    assert '.usecase-card[data-tool="email-extractor"]' in css


def test_rulest_label_and_eta_icon_are_consistent():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    email_html = (root / "web" / "email-rule-extractor.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")

    assert '<h1>RULEST<span class="title-period">.</span></h1>' in html
    assert '<strong>RULEST</strong>' in html
    assert 'Run workspace' not in html
    assert 'Run workspace' not in js
    assert '⌛' not in html + email_html
    assert 'metric-icon">◴' in html + email_html


def test_storage_intelligence_scrollbar_is_narrow_and_theme_scoped():
    root = Path(app.__file__).resolve().parent
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")
    assert '.storage-intelligence-panel::-webkit-scrollbar{width:7px;height:7px;}' in css
    assert '.storage-intelligence-panel{\n  scrollbar-width:thin;' in css
