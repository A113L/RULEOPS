from pathlib import Path

import app


def test_license_controls_switch_to_confirmed_uninstall_when_installed():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")

    assert 'id="install-license-button"' in html
    assert 'id="license-install-hint"' in html
    assert "button.dataset.licenseAction = installed ? 'uninstall' : 'install'" in js
    assert "<span>Uninstall license</span>" in js
    assert "window.confirm(" in js
    assert "fetch('/api/license/uninstall'" in js
    assert "input.disabled = installed" in js


def test_license_uninstall_endpoint_is_admin_protected():
    source = Path(app.__file__).read_text(encoding="utf-8")
    assert 'parsed.path == "/api/license/uninstall"' in source
    assert "def handle_license_uninstall(self):" in source
    handler = source.split("def handle_license_uninstall(self):", 1)[1].split("def handle_clear_logs", 1)[0]
    assert "require_admin(self, api=True)" in handler
    assert "uninstall_license()" in handler


def test_license_activation_panel_fills_remaining_desktop_column_height():
    root = Path(app.__file__).resolve().parent
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")

    assert "@media (min-width: 981px)" in css
    assert "#license-admin-grid {\n    align-items: stretch;" in css
    assert "#license-admin-grid #license-install-panel {\n    flex: 1 1 auto;" in css
    assert "#license-admin-grid #license-install-panel .license-textarea" in css
