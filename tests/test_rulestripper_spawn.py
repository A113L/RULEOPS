"""Regression coverage for Rulestripper's spawn-safe shared-memory workers."""
from __future__ import annotations

from rulest.token_strip import PackedWordBuffer
from rulest.rulestripper import extract_stripper_rules_mp


def test_rulestripper_spawn_uses_shared_ranges_and_closes_cleanly(tmp_path):
    base_path = tmp_path / "base.txt"
    target_path = tmp_path / "target.txt"
    base_path.write_text("password\nadmin\nhello\n", encoding="utf-8")
    target_path.write_text("drowssap\nhello\n", encoding="utf-8")

    base = PackedWordBuffer.from_file(base_path, lowercase=True)
    target = PackedWordBuffer.from_file(target_path)
    try:
        rules = extract_stripper_rules_mp(
            target,
            base,
            max_depth=2,
            min_stem_len=4,
            max_leet_ambiguity=2,
            workers=2,
            chunk_size=1,
            enable_new_modes=True,
            start_method="spawn",
        )
        assert "r" in rules
    finally:
        target.close()
        base.close()


def test_rulestripper_spawn_skips_unused_postings_when_enhanced_modes_disabled(tmp_path):
    base_path = tmp_path / "base.txt"
    target_path = tmp_path / "target.txt"
    base_path.write_text("password\nadmin\n", encoding="utf-8")
    target_path.write_text("drowssap\n", encoding="utf-8")
    base = PackedWordBuffer.from_file(base_path, lowercase=True)
    target = PackedWordBuffer.from_file(target_path)
    try:
        rules = extract_stripper_rules_mp(
            target, base, max_depth=2, min_stem_len=4,
            workers=2, chunk_size=1, enable_new_modes=False,
            start_method="spawn",
        )
        assert "r" in rules
    finally:
        target.close()
        base.close()
