from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _metric_panel(source: str, tool: str) -> str:
    match = re.search(
        rf'<section\b(?=[^>]*data-tool-metrics="{re.escape(tool)}")[^>]*>(.*?)</section>',
        source,
        flags=re.DOTALL,
    )
    assert match, f"Missing metrics panel for {tool}"
    return match.group(1)


def test_every_server_tool_has_the_five_shared_metric_cards():
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    for tool in ("rulest", "ranker", "concentrator", "rulestripper", "minimizer"):
        panel = _metric_panel(html, tool)
        assert panel.count('<article class="metric-card') == 5, tool
        for metric in ("status", "note", "stage", "elapsed", "outputs", "eta", "eta-note"):
            assert f'data-metric="{metric}"' in panel, (tool, metric)
        assert 'data-metric-dot' in panel, tool


def test_server_metric_renderer_is_tool_scoped():
    js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    assert "data.tool === tool" in js
    assert "renderToolMetrics(tool, data)" in js
    assert "function estimateStageEta(data)" in js
    assert "Current stage · recalculated live" in js
    assert "renderOutputs(data.outputs || [], data.tool || 'rulest')" in js
    assert "const ownedOutputs = tool === outputTool ? outputs : [];" in js


def test_email_extractor_has_matching_cards_and_local_lifecycle():
    html = (ROOT / "web" / "email-rule-extractor.html").read_text(encoding="utf-8")
    assert html.count('<article class="metric-card') == 5
    for metric_id in (
        "email-metric-status",
        "email-metric-note",
        "email-metric-stage",
        "email-metric-elapsed",
        "email-metric-outputs",
        "email-metric-eta",
        "email-metric-eta-note",
    ):
        assert f'id="{metric_id}"' in html

    js = (ROOT / "web" / "email-rule-extractor.js").read_text(encoding="utf-8")
    assert "setEmailMetricState('running', 'Analyzing email patterns')" in js
    assert "async function processEmails(" in js
    assert "metricProgressCompleted / metricProgressTotal" in js
    assert "setEmailMetricState('completed'" in js
    assert "metricOutputFiles = 1" in js
    assert "metricOutputFiles = 0" in js
