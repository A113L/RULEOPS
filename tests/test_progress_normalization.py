"""Keep the GA/minimizer bars aligned with the standard Stage 0/1/2 format."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rulest.common import STANDARD_PROGRESS_BAR_FORMAT
from rulest.genetic import _ga_progress_fields
from rulest.minimize import _progress_tick


class _FakeBar:
    def __init__(self):
        self.updated = 0
        self.postfix = None

    def update(self, amount):
        self.updated += amount

    def set_postfix(self, fields, refresh=False):
        self.postfix = dict(fields)


def _plain(value):
    # Strip the small ANSI SGR sequences used by common.cyan/green.
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", str(value))


def test_standard_progress_format_includes_elapsed_and_remaining_eta():
    assert STANDARD_PROGRESS_BAR_FORMAT == (
        "{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}"
    )


def test_ga_progress_fields_include_rules_hits_speed_and_budget():
    fields = _ga_progress_fields(
        rules=1234, hits=98765, speed="12.3M combos/s", budget_left=42.2,
    )
    plain = {key: _plain(value) for key, value in fields.items()}
    assert plain["rules"] == "1,234"
    assert plain["hits"] == "98,765"
    assert plain["spd"] == "12.3M combos/s"
    assert plain["budget"] == "42s"
    assert set(plain) == {"rules", "hits", "spd", "budget"}


def test_minimizer_progress_fields_include_processed_rules_and_hit_total(monkeypatch):
    import rulest.minimize as minimize_module

    bar = _FakeBar()
    monkeypatch.setattr(minimize_module, "_fmt_speed", lambda value, unit: f"{value:.1f} {unit}/s")
    monkeypatch.setattr(minimize_module._progress_tick, "last_update", time.time())

    pending = _progress_tick(
        bar, pending=7, done=25, start_time=time.time() - 5.0,
        hits_total=9876, force=True,
    )

    plain = {key: _plain(value) for key, value in bar.postfix.items()}
    assert pending == 0
    assert bar.updated == 7
    assert plain["rules"] == "25"
    assert plain["hits"] == "9,876"
    assert plain["spd"].endswith("rules/s")


def test_progress_format_is_shared_by_stage_and_postprocessing_modules():
    from rulest import token_strip, gpu_engine, genetic, minimize

    assert token_strip.STANDARD_PROGRESS_BAR_FORMAT is STANDARD_PROGRESS_BAR_FORMAT
    assert gpu_engine.STANDARD_PROGRESS_BAR_FORMAT is STANDARD_PROGRESS_BAR_FORMAT
    assert genetic.STANDARD_PROGRESS_BAR_FORMAT is STANDARD_PROGRESS_BAR_FORMAT
    assert minimize.STANDARD_PROGRESS_BAR_FORMAT is STANDARD_PROGRESS_BAR_FORMAT


def test_stage1_progress_reports_total_rule_hit_events(monkeypatch):
    import rulest.gpu_engine as gpu_module

    bars = []

    class _Tqdm(_FakeBar):
        def __init__(self, *args, **kwargs):
            super().__init__()
            bars.append(self)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    monkeypatch.setattr(gpu_module, "tqdm", _Tqdm)
    monkeypatch.setattr(
        gpu_module.HashcatRuleValidator, "validate_rules_for_gpu",
        staticmethod(lambda rules: list(rules)),
    )
    engine = gpu_module.GPUEngine.__new__(gpu_module.GPUEngine)
    engine.params = {"WORDS_PER_BATCH": 2}
    engine.upload_bloom_filter = lambda _bloom: None
    engine.compile_kernel = lambda: True
    engine._rules_version = 0
    engine.gpu_rules = []
    engine.rule_index = {}
    engine.queue = object()
    engine._consecutive_errors = 0
    engine._MAX_CONSECUTIVE_ERRORS = 3
    engine.prepare_words_data = lambda batch: batch
    engine._run_single_kernel = lambda _batch, _profile=None: ["r1", "r1", "r2"]

    result = engine.process_all_words_single_rule(["a", "b", "c"], ["r1"], object())

    assert result == {"r1": 4, "r2": 2}
    plain = {key: _plain(value) for key, value in bars[-1].postfix.items()}
    assert plain["rules"] == "2"
    assert plain["hits"] == "6"
    assert "spd" in plain


def test_stage2_progress_reports_total_chain_hit_events(monkeypatch):
    import rulest.gpu_engine as gpu_module

    bars = []

    class _Tqdm(_FakeBar):
        def __init__(self, *args, **kwargs):
            super().__init__()
            bars.append(self)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    monkeypatch.setattr(gpu_module, "tqdm", _Tqdm)
    engine = gpu_module.GPUEngine.__new__(gpu_module.GPUEngine)
    engine.params = {"CHAINS_PER_BATCH": 2, "WORD_SUB_BATCH": 2}
    engine._consecutive_errors = 0
    engine._MAX_CONSECUTIVE_ERRORS = 3
    engine.set_base_words = lambda _words: None
    engine._compute_chain_seqs = lambda _chains: ([], [])
    engine.get_word_batch_data = lambda start, end: {"num_words": end - start}
    engine._run_chain_kernel = lambda _bd, _chains, _seqs, _profile=None: ["r1", "r1", "r2"]

    result = engine._run_chains_against_words(["a", "b", "c"], ["c1", "c2"])

    # Two word sub-batches each emitted three hit events.
    assert result == {"r1": 4, "r2": 2}
    plain = {key: _plain(value) for key, value in bars[-1].postfix.items()}
    assert plain["rules"] == "2"
    assert plain["hits"] == "6"
    assert "spd" in plain
