from pathlib import Path

import app


def test_about_page_replaces_license_page_and_preserves_donations_and_support():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert 'href="#about"' in html
    assert '<b>About</b>' in html
    assert 'id="about"' in html and 'id="about-grid"' in html
    assert 'All application features are available without a product license' in html
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
    assert 'Offline licensing (DEMO / PROFESSIONAL / ENTERPRISE)' not in readme
    assert 'id="license-admin"' not in html
    assert 'id="nav-license-admin"' not in html


def test_about_navigation_and_user_password_control_are_wired_without_license_ui():
    root = Path(app.__file__).resolve().parent
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    assert "href === '#about'" in js
    assert "setActiveSystemView('about')" in js
    assert "wireAboutAccessControls" in js
    assert "apiPost('/api/auth/set-user-password'" in js
    assert 'refreshLicense' not in js
    assert '/api/license' not in js


def test_product_license_code_and_runtime_gates_are_removed():
    root = Path(app.__file__).resolve().parent
    source = (root / "app.py").read_text(encoding="utf-8")
    assert "from licensing.core" not in source
    assert "apply_celf_limits" not in source
    assert "can_start_full_run" not in source
    assert "record_module_run" not in source
    assert '"license":' not in source
    assert not (root / "license_admin.py").exists()
    assert not (root / "licensing").exists()
    # The repository's MIT license is retained; it is not an app activation feature.
    assert (root / "LICENSE").is_file()


def test_legacy_license_api_routes_are_gone(tmp_path, monkeypatch):
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.cookies import SimpleCookie

    monkeypatch.setattr(app, "AUTH_FILE", tmp_path / "auth.json")
    monkeypatch.setattr(app, "SECURITY_DB", tmp_path / "security.sqlite3")
    monkeypatch.setattr(app, "SESSIONS", {})
    monkeypatch.setattr(app, "LOGIN_FAILURES", {})
    server = app.RulestHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        setup_request = urllib.request.Request(
            base + "/api/auth/setup",
            data=json.dumps({"password": "about-page-test-password"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(setup_request, timeout=5) as response:
            setup = json.loads(response.read().decode("utf-8"))
            cookie = SimpleCookie(response.headers["Set-Cookie"])
            session_cookie = "rulest_session=" + cookie["rulest_session"].value

        request = urllib.request.Request(base + "/api/license", headers={"Cookie": session_cookie})
        try:
            urllib.request.urlopen(request, timeout=5)
            assert False, "The retired product-license endpoint must not exist."
        except urllib.error.HTTPError as exc:
            assert exc.code == 404

        request = urllib.request.Request(
            base + "/api/license/install",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Cookie": session_cookie,
                "X-CSRF-Token": setup["csrf_token"],
            },
        )
        try:
            urllib.request.urlopen(request, timeout=5)
            assert False, "The retired license-install endpoint must not exist."
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


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
    assert "build=2.5.0-about-layout" in html
