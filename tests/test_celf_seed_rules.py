
import pytest

from rulest.celf_seed_rules import load_celf_seed_rules


def test_loads_valid_curated_rules_deduplicates_and_obeys_depth(tmp_path):
    first = tmp_path / "curated-a.rule"
    second = tmp_path / "curated-b.rule"
    first.write_text(
        "# curated rules\n"
        "c$1\n"
        "c$1\n"
        "l\n"
        "c $2\n"
        "not-a-hashcat-rule\n"
        ":\n",
        encoding="ascii",
    )
    second.write_text("u$1\n$2\nl\n", encoding="ascii")

    rules, stats = load_celf_seed_rules(
        [first, second], max_rules=10, max_depth=1, existing_rules={"$2"}
    )

    assert rules == ["c$1", "l", "u$1"]
    assert stats.files == 2
    assert stats.valid == 3
    assert stats.duplicates == 2
    assert stats.already_present == 1
    assert stats.over_depth == 1
    assert stats.invalid == 2
    assert stats.capped is False


def test_rule_cap_is_applied_after_validation_and_dedup(tmp_path):
    rules_file = tmp_path / "curated.rule"
    rules_file.write_text("bad\nc$1\nc$1\nl\nu$1\n", encoding="ascii")

    rules, stats = load_celf_seed_rules([rules_file], max_rules=2, max_depth=2)

    assert rules == ["c$1", "l"]
    assert stats.valid == 2
    assert stats.invalid == 1
    assert stats.duplicates == 1
    assert stats.capped is True


def test_zero_limit_disables_import_and_negative_limit_is_rejected(tmp_path):
    rules_file = tmp_path / "curated.rule"
    rules_file.write_text("c$1\n", encoding="ascii")

    rules, stats = load_celf_seed_rules([rules_file], max_rules=0)
    assert rules == []
    assert stats.files == 0

    with pytest.raises(ValueError, match="0 or greater"):
        load_celf_seed_rules([rules_file], max_rules=-1)


def test_missing_rule_file_fails_explicitly(tmp_path):
    missing = tmp_path / "missing.rule"
    with pytest.raises(FileNotFoundError, match="not found"):
        load_celf_seed_rules([missing], max_rules=10)


def test_accepts_more_than_one_thousand_seed_rules(tmp_path, monkeypatch):
    # Keep this a focused import-limit test: the production Hashcat validator
    # is covered elsewhere, while these synthetic ASCII rules exercise the
    # loader's cap handling without relying on a particular command grammar.
    from rulest import celf_seed_rules

    monkeypatch.setattr(
        celf_seed_rules.HashcatRuleValidator,
        "validate_rule_for_gpu",
        staticmethod(lambda _rule: True),
    )
    rules_file = tmp_path / "large-curated.rule"
    expected = [f"synthetic-rule-{index:04d}" for index in range(1505)]
    rules_file.write_text("\n".join(expected) + "\n", encoding="ascii")

    rules, stats = load_celf_seed_rules([rules_file], max_rules=1505)

    assert rules == expected
    assert len(rules) == 1505
    assert stats.valid == 1505
    assert stats.capped is True


def test_celf_seed_status_reports_optional_disabled_state_and_stage_s_only(tmp_path):
    from rulest.celf_seed_rules import format_celf_seed_status_messages

    disabled = format_celf_seed_status_messages(
        [], [], None, max_rules=1000, max_depth=2
    )
    assert len(disabled) == 1
    assert "Disabled (optional)" in disabled[0]
    assert "no custom CELF seed file" in disabled[0]

    stage_s_only = format_celf_seed_status_messages(
        [], [], None, max_rules=1000, max_depth=2,
        stage_seed_path=tmp_path / "stage-s.rule",
    )
    assert "Stage S only" in stage_s_only[0]
    assert "CELF pool" in stage_s_only[0]


def test_celf_seed_status_reports_zero_valid_rules_and_validation_counts(tmp_path):
    from rulest.celf_seed_rules import (
        CelfSeedLoadStats,
        format_celf_seed_status_messages,
    )

    messages = format_celf_seed_status_messages(
        [tmp_path / "curated.rule"],
        [],
        CelfSeedLoadStats(
            files=1, lines=17, valid=0, invalid=12, duplicates=2,
            over_depth=3, capped=False,
        ),
        max_rules=2500,
        max_depth=2,
    )
    assert "curated.rule" in messages[0]
    assert "max_rules=2,500" in messages[0]
    assert "accepted=0" in messages[1]
    assert "lines_scanned=17" in messages[1]
    assert "invalid=12" in messages[1]
    assert "duplicates=2" in messages[1]
    assert "over_depth=3" in messages[1]
    assert "limit_reached=no" in messages[1]
