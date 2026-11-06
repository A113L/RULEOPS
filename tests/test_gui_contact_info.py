from pathlib import Path


def test_contact_panel_uses_discord_username_not_matrix():
    root = Path(__file__).resolve().parents[1]
    html = (root / "web" / "index.html").read_text(encoding="utf-8")

    assert '<span class="contact-label">Discord</span>' in html
    assert 'href="https://discord.com/app"' in html
    assert '>a_1_1_3_1</a>' in html
    assert "matrix.to" not in html.lower()
    assert "@a1131:matrix.org" not in html
