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
