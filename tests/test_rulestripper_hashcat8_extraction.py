from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hashcat_rule_ops import apply_hashcat8_operator
from rulest import rulestripper
from rulest.rulestripper import _extract_hashcat8_mode, py_apply_chain


def test_rulestripper_extracts_lowercase_and_uppercase_hex_operators() -> None:
    base = {"fizz"}

    lower_hex = bytes(apply_hashcat8_operator("h", b"fizz")).decode("ascii")
    upper_hex = bytes(apply_hashcat8_operator("H", b"fizz")).decode("ascii")

    assert lower_hex == "66697a7a"
    assert upper_hex == "66697A7A"
    assert _extract_hashcat8_mode(lower_hex, base, 1, 4) == {"h"}
    assert _extract_hashcat8_mode(upper_hex, base, 1, 4) == {"H"}


def test_rulestripper_extracts_self_inverse_keyboard_shift_operator() -> None:
    source = "abc123!@#[]"
    target = bytes(apply_hashcat8_operator("S", source.encode("ascii"))).decode("ascii")

    assert target == "ABC!@#123{}"
    assert _extract_hashcat8_mode(target, {source}, 1, len(source)) == {"S"}


def test_rulestripper_extracts_vnx_with_terminal_insert() -> None:
    source = "abcdef"
    target = bytes(apply_hashcat8_operator("v", source.encode("ascii"), 2, ord("-"))).decode("ascii")

    assert target == "ab-cd-ef-"
    assert _extract_hashcat8_mode(target, {source}, 1, len(source)) == {"v2-"}
    assert py_apply_chain("v2-", source) == target


def test_rulestripper_extracts_vnx_for_partial_final_chunk_and_base36_n() -> None:
    partial_source = "abcde"
    partial_target = bytes(
        apply_hashcat8_operator("v", partial_source.encode("ascii"), 2, ord("-"))
    ).decode("ascii")
    assert partial_target == "ab-cd-e"
    assert _extract_hashcat8_mode(partial_target, {partial_source}, 1, 5) == {"v2-"}

    base36_source = "abcdefghijKLM"
    base36_target = bytes(
        apply_hashcat8_operator("v", base36_source.encode("ascii"), 10, ord("_"))
    ).decode("ascii")
    assert base36_target == "abcdefghij_KLM"
    assert _extract_hashcat8_mode(base36_target, {base36_source}, 1, 13) == {"vA_"}


def test_rulestripper_rejects_mixed_vnx_markers_and_unrepresentable_arguments() -> None:
    assert not _extract_hashcat8_mode("ab-cdXef-", {"abcdef"}, 1, 4)
    # Whitespace and backslash cannot be emitted unambiguously as a plain rule argument.
    assert not _extract_hashcat8_mode("ab cd ef ", {"abcdef"}, 1, 4)
    assert not _extract_hashcat8_mode("ab\\cd\\ef\\", {"abcdef"}, 1, 4)


def test_hashcat8_extraction_is_wired_into_rulestripper_workers() -> None:
    class EmptyPostings:
        @staticmethod
        def get(_kind, _key, default=()):
            return default

    old_config = rulestripper._WORKER_CONFIG
    old_membership = rulestripper._WORKER_MEMBERSHIP
    old_postings = rulestripper._WORKER_POSTINGS
    try:
        rulestripper._WORKER_CONFIG = (1, 4, 3, True)
        rulestripper._WORKER_MEMBERSHIP = {"fizz"}
        rulestripper._WORKER_POSTINGS = EmptyPostings()
        assert "h" in rulestripper._process_one_target_word("66697a7a")
        rulestripper._WORKER_CONFIG = (1, 4, 3, False)
        assert "h" not in rulestripper._process_one_target_word("66697a7a")
    finally:
        rulestripper._WORKER_CONFIG = old_config
        rulestripper._WORKER_MEMBERSHIP = old_membership
        rulestripper._WORKER_POSTINGS = old_postings


def test_hashcat8_modes_respect_depth_limit() -> None:
    assert not _extract_hashcat8_mode("66697a7a", {"fizz"}, 0, 4)
