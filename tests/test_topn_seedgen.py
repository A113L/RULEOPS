"""Regression tests for the PCFG-Lite Top-N seed generator."""

import os
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rulest import topn_seedgen as topn


def test_digit_and_year_detection_is_ascii_only():
    assert topn._is_digit_str("2026")
    assert not topn._is_digit_str("²")
    assert topn._looks_like_year("2024")
    assert topn._looks_like_year("24")
    assert not topn._looks_like_year("2040")
    assert not topn._looks_like_year("٢٠٢٤")


def test_stream_top_n_zero_reads_entire_plain_wordlist(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("alpha\nbeta\nalpha\ngamma\n", encoding="utf-8")

    assert topn.stream_top_n(target, top_n=0) == ["alpha", "beta", "gamma"]


def test_stream_top_n_aggregates_frequency_format(tmp_path):
    target = tmp_path / "target-counts.txt"
    target.write_text(
        "3 alpha\n2 beta\n7 alpha\n5 gamma\n", encoding="utf-8"
    )

    assert topn.stream_top_n(target, top_n=2) == ["alpha", "gamma"]
    assert topn.stream_top_n(target, top_n=0) == ["alpha", "gamma", "beta"]


def test_affix_scan_keeps_long_digit_patterns_but_not_long_special_patterns():
    passwords = ["12345678root12345678"] * 5 + ["a!!!!!"]

    suffixes, prefixes, years = topn.extract_affixes(passwords)

    assert suffixes["12345678"] == 5
    assert prefixes["12345678"] == 5
    assert "!!!!!" not in suffixes
    assert topn._min_count_for("1234") == topn.MIN_SUFFIX_COUNT
    assert topn._min_count_for("12345") == topn.MIN_LONG_DIGIT_SUFFIX_COUNT


def test_affix_scan_profiles_years():
    suffixes, _prefixes, years = topn.extract_affixes(["hello2024"] * 3)

    assert suffixes["2024"] == 3
    assert years["2024"] == 3


def test_budgeted_affixes_reserves_space_for_long_digit_patterns():
    items = [
        ("12345678", 100),
        ("1234", 95),
        ("87654321", 90),
        ("5678", 85),
        ("22", 80),
    ]

    selected = topn._budgeted_affixes(items, budget=4, reserve_frac=0.5)

    assert selected == ["12345678", "87654321", "1234", "5678"]


def test_budgeted_affixes_backfills_from_long_pool_when_short_pool_runs_out():
    items = [
        ("123456", 100),
        ("654321", 90),
        ("987654", 80),
        ("1234", 70),
    ]

    selected = topn._budgeted_affixes(items, budget=4, reserve_frac=0.5)

    assert len(selected) == 4
    assert sum(len(value) > topn.MAX_AFFIX_LEN for value in selected) == 3


def test_adaptive_budgets_favor_families_supported_by_target_data():
    budgets = topn._adaptive_primary_budgets(
        suffixes=Counter({"123": 1000}),
        prefixes=Counter(),
        years=Counter(),
        budgets_src=topn.FAMILY_BUDGET_STANDARD,
        budget_base=10_000,
    )

    assert set(budgets) == set(topn._PRIMARY_BUDGET_FAMILIES)
    assert budgets["suffix_digit"] == max(budgets.values())
    assert all(value > 0 for value in budgets.values())


def test_adaptive_budgets_fall_back_to_static_priors_without_evidence():
    budgets = topn._adaptive_primary_budgets(
        suffixes=Counter(),
        prefixes=Counter(),
        years=Counter(),
        budgets_src=topn.FAMILY_BUDGET_STANDARD,
        budget_base=10_000,
    )

    assert set(budgets) == set(topn._PRIMARY_BUDGET_FAMILIES)
    assert all(value > 0 for value in budgets.values())
    assert budgets["suffix_digit"] > budgets["prefix_digit"]


def test_parallel_affix_scan_matches_single_process_result(monkeypatch):
    # Lower the threshold for a small deterministic multiprocessing test.
    monkeypatch.setattr(topn, "MIN_PASSWORDS_FOR_PARALLEL_SCAN", 10)
    passwords = [f"user{index % 10}2024!" for index in range(20)]

    expected = topn.extract_affixes(passwords)
    actual = topn.extract_affixes_parallel(passwords, workers=2)

    assert actual == expected


def test_default_worker_count_uses_all_logical_cpus(monkeypatch):
    monkeypatch.setattr(topn.os, "cpu_count", lambda: 16)
    assert topn.default_worker_count() == 16

    monkeypatch.setattr(topn.os, "cpu_count", lambda: None)
    assert topn.default_worker_count() == 1


def test_generate_seeds_respects_limit_and_deduplicates():
    passwords = [
        "Password123",
        "Summer2024!",
        "admin999",
        "letmein!",
        "welcome2025",
        "Qwerty42",
        "12345678admin12345678",
    ]

    seeds = topn.generate_seeds(
        passwords,
        max_seeds=96,
        show_progress=False,
        adaptive=True,
        workers=1,
    )

    assert 0 < len(seeds) <= 96
    assert len(seeds) == len(set(seeds))
    assert all(topn._valid(rule) for rule in seeds)


def test_generate_seeds_can_disable_adaptive_budgeting(monkeypatch):
    def unexpected_adaptive_call(*_args, **_kwargs):
        raise AssertionError("adaptive budgeting should be disabled")

    monkeypatch.setattr(topn, "_adaptive_primary_budgets", unexpected_adaptive_call)

    seeds = topn.generate_seeds(
        ["password123", "admin2024!", "qwerty99"],
        max_seeds=32,
        show_progress=False,
        adaptive=False,
        workers=1,
    )

    assert seeds


def test_generator_does_not_starve_long_digit_suffixes():
    seeds = topn.generate_seeds(
        ["password12345678"] * 5,
        max_seeds=500,
        show_progress=False,
        adaptive=False,
        workers=1,
    )

    assert "$1 $2 $3 $4 $5 $6 $7 $8" in seeds


def test_run_writes_seed_file_and_reports_loaded_passwords(tmp_path, monkeypatch):
    monkeypatch.setattr(topn, "ProgressBar", None)
    target = tmp_path / "target.txt"
    output = tmp_path / "generated" / "topn.rule"
    target.write_text(
        "password123\nadmin2024!\nqwerty99\npassword123\n", encoding="utf-8"
    )

    stats = topn.run(
        target_path=target,
        output_path=output,
        top_n=0,
        max_seeds=64,
        workers=1,
    )

    lines = output.read_text(encoding="utf-8").splitlines()
    assert stats["passwords_loaded"] == 3
    assert stats["workers"] == 1
    assert lines[0] == "# Top-N seed rules generated by rulest.topn_seedgen"
    assert lines[1] == f"# count={stats['seeds_generated']}"
    assert len(lines[2:]) == stats["seeds_generated"]
