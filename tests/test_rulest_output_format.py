from hashcat_rule_format import expand_hashcat_rule, format_hashcat_rule


def test_expanded_format_splits_compact_hashcat_operators_without_changing_order():
    compact = "$7$5$5$0 i0ai1m ^to1oi2r $1"
    assert expand_hashcat_rule(compact) == "$7 $5 $5 $0 i0a i1m ^t o1o i2r $1"


def test_expanded_format_preserves_rulest_extended_operators():
    compact = "vT~ B76 vCc BWk hHS"
    assert expand_hashcat_rule(compact) == "vT~ B76 vCc BWk h H S"


def test_expanded_format_is_idempotent_and_line_format_is_unchanged():
    compact = "$1$2 csa@"
    expanded = "$1 $2 c sa@"
    assert expand_hashcat_rule(expanded) == expanded
    assert format_hashcat_rule(compact, "line") == compact
    assert format_hashcat_rule(compact, "expanded") == expanded


def test_concentrator_and_rulest_share_the_same_expansion():
    import concentrator

    sample = "$7$5$5$0 i0ai1m ^to1oi2r $1 vT~ B76"
    assert concentrator.expand_rule(sample) == expand_hashcat_rule(sample)


def test_cli_and_ui_expose_expanded_output_format():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    cli = (root / "rulest" / "cli.py").read_text(encoding="utf-8")
    ui = (root / "web" / "index.html").read_text(encoding="utf-8")
    js = (root / "web" / "app.js").read_text(encoding="utf-8")
    app_source = (root / "app.py").read_text(encoding="utf-8")
    assert "--output-format" in cli and "'expanded'" in cli
    assert 'id="output_format"' in ui
    assert "output_format: 'line'" in js
    assert '"output_format": "--output-format"' in app_source
    assert 'Output format must be' in app_source
