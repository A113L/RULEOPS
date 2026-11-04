from pathlib import Path

import app


def test_engine_badge_reflects_job_lifecycle():
    assert app.engine_badge_for_status("idle") == {"label": "READY", "state": "ready"}
    assert app.engine_badge_for_status("running") == {"label": "RUNNING", "state": "running"}
    assert app.engine_badge_for_status("running", paused=True) == {"label": "PAUSED", "state": "paused"}
    assert app.engine_badge_for_status("stopping") == {"label": "STOPPING", "state": "stopping"}
    assert app.engine_badge_for_status("completed") == {"label": "COMPLETE", "state": "complete"}
    assert app.engine_badge_for_status("stopped") == {"label": "STOPPED", "state": "stopped"}
    assert app.engine_badge_for_status("failed") == {"label": "ERROR", "state": "error"}
    assert app.engine_badge_for_status("unexpected") == {"label": "READY", "state": "ready"}
    assert app.engine_badge_for_status("offline") == {"label": "OFFLINE", "state": "offline"}


def test_sidebar_badge_is_live_and_styled_for_each_state():
    root = Path(app.__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    css = (root / "web" / "styles.css").read_text(encoding="utf-8")

    assert 'id="local-engine-card"' in html
    assert 'id="local-engine-status"' in html
    assert 'aria-live="polite"' in html
    assert "function updateLocalEngineBadge(data)" in js
    assert "updateLocalEngineBadge(data)" in js
    assert "card.dataset.engineState = badge.state" in js
    for state in ("running", "paused", "stopping", "error", "offline", "complete"):
        assert f'data-engine-state="{state}"' in css
    assert "RULEOPS 2.4.4" in css
    assert "ruleops-2.4.6-security-hardening" in html
