"""Regression test for reverse-mode target validation."""
from rulest.rulestripper import _extract_reverse_mode
from rulest.tokenstrip_hashset import FlatHashSet64


def test_reverse_mode_validates_against_original_target():
    base = FlatHashSet64(["password"], expected_count=1)
    assert "r" in _extract_reverse_mode("drowssap", base, 2, 4, 2)
