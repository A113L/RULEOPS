"""Unit tests for rulest.minimize: signature-based functional minimization."""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from rulest.minimize import compute_rule_signature_hash, minimize_by_signature


PROBES = ['abc', 'Hello', 'test123']


class TestComputeRuleSignatureHash:

    def test_deterministic_for_same_rule_and_probes(self):
        sig1 = compute_rule_signature_hash('l', PROBES)
        sig2 = compute_rule_signature_hash('l', PROBES)
        assert sig1 == sig2

    def test_functionally_equivalent_rules_share_signature(self):
        # 'u' twice in a row behaves like 'u' once on these probe words.
        sig_u = compute_rule_signature_hash('u', PROBES)
        sig_uu = compute_rule_signature_hash('u u', PROBES)
        assert sig_u == sig_uu

    def test_functionally_different_rules_have_different_signatures(self):
        sig_l = compute_rule_signature_hash('l', PROBES)
        sig_u = compute_rule_signature_hash('u', PROBES)
        assert sig_l != sig_u

    def test_unsupported_rule_returns_sentinel(self):
        sig = compute_rule_signature_hash('Q', PROBES)
        assert sig.startswith('__UNSUPPORTED__')
        assert sig == '__UNSUPPORTED__::Q'

    def test_signature_depends_on_probe_words(self):
        sig_a = compute_rule_signature_hash('c', ['abc'])
        sig_b = compute_rule_signature_hash('c', ['xyz'])
        assert sig_a != sig_b


class TestMinimizeBySignature:

    def test_empty_counter_returns_empty_counter(self):
        result = minimize_by_signature(Counter(), PROBES)
        assert result == Counter()

    def test_removes_functionally_duplicate_rules(self):
        # 'l' and 'l l' are functionally identical on these probes.
        counter = Counter({'l': 5, 'l l': 3})
        result = minimize_by_signature(counter, PROBES)
        assert len(result) == 1
        # The single survivor keeps the higher of the two counts.
        assert list(result.values())[0] == 5

    def test_keeps_functionally_distinct_rules(self):
        counter = Counter({'l': 5, 'u': 3, 'c': 1})
        result = minimize_by_signature(counter, PROBES)
        assert len(result) == 3
        assert set(result.keys()) == {'l', 'u', 'c'}

    def test_prefers_shorter_rule_on_tie(self):
        # Same count, functionally equivalent -> shorter chain should survive.
        counter = Counter({'u u u': 10, 'u': 10})
        result = minimize_by_signature(counter, PROBES)
        assert len(result) == 1
        assert list(result.keys())[0] == 'u'

    def test_unsupported_rules_each_keep_one_survivor(self):
        counter = Counter({'Q': 2, 'M': 4})
        result = minimize_by_signature(counter, PROBES)
        # Both are unsupported but distinct sentinel signatures (rule-specific),
        # so both should survive independently.
        assert set(result.keys()) == {'Q', 'M'}


if __name__ == "__main__":
    import pytest
    print(f"Running {__file__} directly — use `pytest {__file__}` for full output.\n")
    raise SystemExit(pytest.main([__file__, "-v"]))


def _reference_minimize(counter, probes):
    """Historic full-probe implementation used as a semantic reference."""
    import hashlib
    from collections import defaultdict
    from rulest.common import py_apply_chain
    groups = defaultdict(list)
    for rule, count in counter.items():
        outputs = []
        for word in probes:
            output = py_apply_chain(rule, word)
            if output is None:
                signature = '__UNSUPPORTED__::' + rule
                break
            outputs.append(output)
        else:
            combined = '\x00'.join(outputs).encode('utf-8', errors='replace')
            signature = hashlib.blake2b(combined, digest_size=16).hexdigest()
        groups[signature].append((rule, count))
    result = Counter()
    for group in groups.values():
        rule, count = min(group, key=lambda item: (-item[1], len(item[0].split()), item[0]))
        result[rule] = count
    return result


def test_progressive_minimization_refines_late_probe_collisions(monkeypatch):
    import rulest.minimize as minimize_module

    probes = ['abc', '!#', 'Hello', 'Password']
    counter = Counter({'@!': 5, '@#': 7, 'l': 6, 'l l': 8, 'u': 2})
    monkeypatch.setattr(minimize_module, 'MINIMIZE_PROBE_BATCH_SIZE', 1)

    result = minimize_module.minimize_by_signature(counter, probes)

    assert result == _reference_minimize(counter, probes)
    # '@!' and '@#' are identical on the first probe but differ on the next.
    assert '@!' in result and '@#' in result


def test_disk_backed_progressive_minimization_matches_full_reference(monkeypatch):
    import rulest.minimize as minimize_module

    probes = ['abc', '!#', 'Hello', 'Password']
    counter = Counter({'@!': 5, '@#': 7, 'l': 6, 'l l': 8, 'u': 2, 'u u': 3})
    monkeypatch.setattr(minimize_module, 'MINIMIZE_DISK_THRESHOLD', 1)
    monkeypatch.setattr(minimize_module, 'MINIMIZE_PROBE_BATCH_SIZE', 1)
    monkeypatch.setattr(minimize_module, 'MINIMIZE_SQLITE_BATCH_SIZE', 2)

    result = minimize_module.minimize_by_signature(counter, probes)

    assert result == _reference_minimize(counter, probes)


def test_disk_backed_worker_pool_streams_and_refines_rows(monkeypatch):
    import rulest.minimize as minimize_module

    # 500 syntactically distinct rules split into two functional classes.
    # All produce the same output on probe 1; probe 2 separates the classes.
    counter = Counter()
    for depth in range(1, 251):
        counter[' '.join(['@!'] * depth)] = depth
        counter[' '.join(['@#'] * depth)] = depth
    probes = ['abc', '!#']
    monkeypatch.setattr(minimize_module, 'MINIMIZE_DISK_THRESHOLD', 1)
    monkeypatch.setattr(minimize_module, 'MINIMIZE_PROBE_BATCH_SIZE', 1)
    monkeypatch.setattr(minimize_module, 'MINIMIZE_SQLITE_BATCH_SIZE', 64)

    result = minimize_module.minimize_by_signature(counter, probes)

    expected = _reference_minimize(counter, probes)
    assert result == expected
    assert len(result) == 2


def test_compiled_chain_probe_signatures_match_shared_rule_applicator():
    import rulest.minimize as minimize_module
    from rulest.common import py_apply_chain

    probes = ['abc', 'Password', '!@#', 'a b', 'test123']
    rules = ['l', 'u u', 'c', '$1 ^!', 's a@ @#', 'Q', '']
    for rule in rules:
        expected = [py_apply_chain(rule, word) for word in probes]
        actual = [minimize_module._apply_compiled_chain(rule.split(), word)
                  for word in probes]
        assert actual == expected
        assert minimize_module.compute_rule_signature_hash(rule, probes) == \
            minimize_module._probe_chunk_signature(rule, probes, 0, len(probes))


def test_progressive_minimizer_avoids_full_probe_pass_for_unique_rules(monkeypatch):
    import rulest.minimize as minimize_module

    # Most substitutions are distinguishable on the first, deliberately
    # high-entropy alphabet probe.  Only no-op substitutions need later probes.
    replacements = '!@#$%^&*()-_=+[]{}|;:,.<>?/~0123456789'
    counter = Counter()
    for original in 'abcdefghijklmnopqrstuvwxyz':
        for replacement in replacements:
            rule = 's' + original + replacement
            counter[rule] = 1

    monkeypatch.setattr(minimize_module.mp, 'cpu_count', lambda: 1)
    monkeypatch.setattr(minimize_module, 'MINIMIZE_PROBE_BATCH_SIZE', 8)

    calls = [0]
    original_apply = minimize_module._py_apply_single_rule

    def counted_apply(operation, word):
        calls[0] += 1
        return original_apply(operation, word)

    monkeypatch.setattr(minimize_module, '_py_apply_single_rule', counted_apply)
    from rulest.common import BUILTIN_PROBES
    result = minimize_module.minimize_by_signature(counter, BUILTIN_PROBES)

    full_scan_calls = len(counter) * len(BUILTIN_PROBES)
    assert result
    assert calls[0] < full_scan_calls * 0.4


def test_disk_backed_minimizer_returns_original_counter_when_first_pass_is_unique(monkeypatch):
    import rulest.minimize as minimize_module

    # The first prioritized probe distinguishes every substitution.  The disk
    # backend should therefore skip all later passes and avoid rebuilding a
    # multi-million-entry Counter from SQLite.
    replacements = '!@#$%^&*()-_=+[]{}|;:,.<>?/~0123456789'
    counter = Counter()
    for original in 'abcdef':
        for replacement in replacements:
            counter['s' + original + replacement] = 1

    monkeypatch.setattr(minimize_module, 'MINIMIZE_DISK_THRESHOLD', 1)
    monkeypatch.setattr(minimize_module.mp, 'cpu_count', lambda: 1)

    result = minimize_module.minimize_by_signature(counter, minimize_module._PRIORITY_PROBES)

    assert result is counter


def test_disk_backed_minimizer_returns_original_when_late_probes_split_collision(monkeypatch):
    import rulest.minimize as minimize_module

    counter = Counter({'@!': 5, '@#': 7})
    monkeypatch.setattr(minimize_module, 'MINIMIZE_DISK_THRESHOLD', 1)
    monkeypatch.setattr(minimize_module, 'MINIMIZE_PROBE_BATCH_SIZE', 1)
    monkeypatch.setattr(minimize_module.mp, 'cpu_count', lambda: 1)

    result = minimize_module.minimize_by_signature(counter, ['abc', '!#', 'Hello'])

    assert result is counter
    assert result == Counter({'@!': 5, '@#': 7})


def test_sqlite_progress_helpers_show_vm_operation_activity(monkeypatch):
    import sqlite3
    import rulest.minimize as minimize_module

    created = []

    class FakeProgress:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.updated = 0
            self.closed = False
            created.append(self)

        def update(self, amount):
            self.updated += amount

        def set_postfix(self, *args, **kwargs):
            pass

        def close(self):
            self.closed = True

    monkeypatch.setattr(minimize_module, "tqdm", FakeProgress)
    conn = sqlite3.connect(":memory:")

    try:
        value = minimize_module._sqlite_scalar_progress(
            conn,
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000) "
            "SELECT SUM(x) FROM n",
            "Test SQLite scan",
            progress_ops=100,
        )
        assert value == 500500
        assert created
        assert created[0].updated > 0
        assert created[0].closed
        # Unknown SQLite VM-op totals must not render as a permanently empty bar.
        assert "{bar}" not in created[0].kwargs["bar_format"]
        assert "{n_fmt}" in created[0].kwargs["bar_format"]
    finally:
        conn.close()


def test_sqlite_progress_helpers_skip_empty_bar_for_fast_query(monkeypatch):
    import sqlite3
    import rulest.minimize as minimize_module

    created = []

    def fake_tqdm(**kwargs):
        created.append(kwargs)
        raise AssertionError("Fast SQL query must not create an empty progress bar")

    monkeypatch.setattr(minimize_module, "tqdm", fake_tqdm)
    conn = sqlite3.connect(":memory:")
    try:
        assert minimize_module._sqlite_scalar_progress(
            conn, "SELECT 42", "Fast query", progress_ops=100_000
        ) == 42
        assert not created
    finally:
        conn.close()
