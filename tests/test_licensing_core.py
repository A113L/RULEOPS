"""Unit tests for offline licensing and per-module DEMO counters."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from licensing import core


@pytest.fixture()
def isolated_licensing(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "USAGE_DB", tmp_path / "license_usage.sqlite3")
    monkeypatch.setattr(core, "LICENSE_FILE", tmp_path / "license.lic")
    monkeypatch.setattr(core, "PUBLIC_KEY_FILE", tmp_path / "missing_public.pem")
    yield tmp_path


def test_demo_starts_with_three_runs_each(isolated_licensing):
    assert core.is_fully_licensed() is False
    for module in core.MODULES:
        assert core.module_mode(module) == "DEMO"
        assert core.remaining_demo_runs(module) == 3


def test_independent_module_counters(isolated_licensing):
    for _ in range(3):
        core.record_module_run("RULEST")
    assert core.module_mode("RULEST") == "DEMO_LIMITED"
    assert core.module_mode("RULE_RANKER") == "DEMO"
    assert core.module_mode("CONCENTRATOR") == "DEMO"
    assert core.remaining_demo_runs("RULEST") == 0
    assert core.remaining_demo_runs("ranker") == 3


def test_fourth_run_stays_limited_without_extra_count(isolated_licensing):
    for _ in range(3):
        core.record_module_run("CONCENTRATOR")
    status = core.record_module_run("CONCENTRATOR")
    assert status["recorded"] is False
    assert status["mode"] == "DEMO_LIMITED"
    assert core.get_module_usage_count("CONCENTRATOR") == 3


def test_celf_restrictions_demo_limited(isolated_licensing):
    for _ in range(3):
        core.record_module_run("RULE_RANKER")
    rules = core.celf_restrictions("RULE_RANKER")
    assert rules["mode"] == "DEMO_LIMITED"
    assert rules["celf_advanced_allowed"] is False
    assert rules["greedy_allowed"] is False
    assert rules["max_candidates"] == 500
    assert rules["max_budget"] == 64

    opts = core.apply_celf_limits(
        {"candidates": 20000, "budget": 5000, "select_mode": "greedy", "use_celf": True},
        "RULE_RANKER",
    )
    assert opts["select_mode"] == "frequency"
    assert opts["candidates"] <= 500
    assert opts["budget"] <= 64
    assert opts["use_celf"] is False


def test_celf_soft_caps_in_demo(isolated_licensing):
    rules = core.celf_restrictions("RULEST")
    assert rules["mode"] == "DEMO"
    assert rules["celf_advanced_allowed"] is True
    opts = core.apply_celf_limits({"candidates": 99999, "budget": 9999}, "RULEST")
    assert opts["candidates"] == 5000
    assert opts["budget"] == 500


def test_license_summary_shape(isolated_licensing):
    summary = core.license_summary()
    assert summary["edition"] == "DEMO"
    assert summary["fully_licensed"] is False
    assert summary["demo_limit"] == 3
    assert set(summary["modules"]) == set(core.MODULES)



def test_normalize_module_aliases(isolated_licensing):
    assert core.normalize_module("rulest") == "RULEST"
    assert core.normalize_module("ranker") == "RULE_RANKER"
    assert core.normalize_module("concentrator") == "CONCENTRATOR"
    with pytest.raises(ValueError):
        core.normalize_module("unknown-tool")


def test_can_start_full_run_modes(isolated_licensing):
    gate = core.can_start_full_run("RULEST")
    assert gate["allowed"] is True
    assert gate["mode"] == "DEMO"
    for _ in range(3):
        core.record_module_run("RULEST")
    gate = core.can_start_full_run("RULEST")
    assert gate["mode"] == "DEMO_LIMITED"
