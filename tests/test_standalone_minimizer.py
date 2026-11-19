"""Regression tests for the standalone Rule Minimizer's progressive engine."""
import minimizer as standalone


def _full_signature_reference(rules, probes, multibyte=False):
    """Historic all-probes-at-once semantics: retain first rule per signature."""
    first_by_signature = {}
    for index, rule in enumerate(rules):
        signature = standalone.compute_signature(rule, probes, multibyte=multibyte)
        first_by_signature.setdefault(signature, index)
    survivors = sorted(first_by_signature.values())
    kept = [rules[index] for index in survivors]
    return kept, len(kept), len(rules) - len(kept)


def test_offset_progressive_matches_full_signature_reference(monkeypatch):
    rules = ["@!", "@#", "l", "l l", "u", "Q", "M", "c", "c c", ":"]
    probes = ["abc", "!#", "Hello", "Password", "a`b", 'a"b', "a'b", "a\\b"]
    monkeypatch.setattr(standalone, "MINIMIZER_PROBE_BATCH_SIZE", 1)
    monkeypatch.setattr(standalone, "MINIMIZER_BATCH_SIZE", 3)

    expected = _full_signature_reference(rules, probes)
    actual = standalone.minimizer(rules, probes)
    assert actual == expected
    # The two reject-character rules collide on the first input probe but
    # must be separated when a later probe distinguishes their behavior.
    assert "@!" in actual[0] and "@#" in actual[0]


def test_offset_engine_matches_full_signature_reference(monkeypatch):
    rules = ["@!", "@#", "l", "l l", "u", "Q", "M", "c", "c c", ":"]
    probes = ["abc", "!#", "Hello", "Password"]
    monkeypatch.setattr(standalone, "MINIMIZER_PROBE_BATCH_SIZE", 1)
    monkeypatch.setattr(standalone, "MINIMIZER_BATCH_SIZE", 2)

    expected = _full_signature_reference(rules, probes)
    actual = standalone.minimizer(rules, probes)
    assert actual == expected


def test_first_probe_unique_rules_skip_remaining_probes(monkeypatch):
    rules = [f"s{source}{replacement}" for source in "abcdef"
             for replacement in "!@#$%^&*0123456789"]
    probes = ["abcdefghijklmnopqrstuvwxyz", "Password", "!@#$%^&*()"]
    monkeypatch.setattr(standalone, "MINIMIZER_PROBE_BATCH_SIZE", 1)
    expected = _full_signature_reference(rules, probes)

    actual = standalone.minimizer(rules, probes)
    assert actual == expected


def test_multibyte_progressive_signatures_preserve_invalid_utf8_outputs(monkeypatch):
    rules = ["r", "r r", "d", "l", "Q", "M", ":"]
    probes = ["ą", "ß", "🙂", "Password", "漢字"]
    monkeypatch.setattr(standalone, "MINIMIZER_PROBE_BATCH_SIZE", 1)

    expected = _full_signature_reference(rules, probes, multibyte=True)
    actual = standalone.minimizer(rules, probes, multibyte=True)
    assert actual == expected


def test_worker_pool_progressive_minimizer_matches_serial_reference(monkeypatch):
    rules = ["@!", "@#", "l", "l l", "u", "Q", "M", "c", "c c", ":"]
    probes = ["abc", "!#", "Hello", "Password"]
    monkeypatch.setattr(standalone, "MINIMIZER_PROBE_BATCH_SIZE", 1)
    monkeypatch.setattr(standalone, "MINIMIZER_BATCH_SIZE", 2)

    expected = _full_signature_reference(rules, probes)
    actual = standalone.minimizer(rules, probes, workers=2)
    assert actual == expected


def test_progressive_minimizer_skips_later_probes_for_early_unique_rules(monkeypatch):
    rules = [f"s{source}{replacement}" for source in "abcdef"
             for replacement in "!@#$%^&*0123456789"]
    probes = ["abcdefghijklmnopqrstuvwxyz", "Password", "!@#$%^&*()"]
    monkeypatch.setattr(standalone, "MINIMIZER_PROBE_BATCH_SIZE", 1)

    expected = _full_signature_reference(rules, probes)
    calls = [0]
    apply_single = standalone._apply_single

    def counted_apply_single(*args, **kwargs):
        calls[0] += 1
        return apply_single(*args, **kwargs)

    monkeypatch.setattr(standalone, "_apply_single", counted_apply_single)
    actual = standalone.minimizer(rules, probes)

    assert actual == expected
    assert calls[0] < len(rules) * len(probes) // 2


def test_unsupported_duplicate_text_is_deduplicated_but_distinct_rules_survive():
    rules = ["Q", "M", "Q", "u"]
    actual = standalone.minimizer(rules, ["abc", "Password"])
    assert actual == (["Q", "M", "u"], 3, 1)
