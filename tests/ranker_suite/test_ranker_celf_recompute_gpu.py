"""Tests for rule_ranker.celf_recompute_gpu's greedy ROUND LOGIC
(fixed sorted-order scan, upper_bound/last_bound pruning, tie-breaks,
budget cutoff) in isolation from real OpenCL/GPU kernels.

celf_select_recompute_gpu() constructs a real _GpuScorer internally,
which needs an actual GPU. To test the selection algorithm itself
(the lazy upper-bound logic), this monkeypatches _GpuScorer with a small
pure-Python/NumPy fake backed by an explicit rule -> covered-hash-ids
mapping, so exact coverage/selection outcomes can be asserted without
any device present. See conftest.py for why `import pyopencl` still
needs to succeed even though no real OpenCL is exercised here.
"""
import math
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rule_ranker import celf_recompute_gpu as crg


class _FakeScorer:
    """Drop-in stand-in for celf_recompute_gpu._GpuScorer. `coverage`
    maps rule string -> set of covered hash ids (ints in
    range(cracked_size)); `active` starts as every hash id and shrinks
    exactly like the real GPU-side `active` bitmap does."""

    def __init__(self, rules, coverage, cracked_size):
        self.rules = rules
        self.coverage = {r: set(c) for r, c in coverage.items()}
        self.active = set(range(cracked_size))
        self.score_batch_calls = 0
        self.dispatched_rule_counts = []

    def score_batch(self, rule_indices, wordlist_path):
        self.score_batch_calls += 1
        self.dispatched_rule_counts.append(len(rule_indices))
        out = np.zeros(len(rule_indices), dtype=np.int64)
        for i, ridx in enumerate(rule_indices):
            rule_str = self.rules[int(ridx)]
            out[i] = len(self.coverage.get(rule_str, set()) & self.active)
        return out

    def apply_winner_and_clear(self, rule_idx, rule_str, wordlist_path):
        newly = self.coverage.get(rule_str, set()) & self.active
        self.active -= newly
        return len(newly)

    def remaining_active_count(self):
        return len(self.active)


def _run(monkeypatch, rules, coverage, cracked_size, budget=None, rule_batch_size=2,
         cost_alpha=0.0):
    fake = _FakeScorer(rules, coverage, cracked_size)
    monkeypatch.setattr(crg, "_GpuScorer", lambda *a, **k: fake)
    encoded_unused = np.zeros((len(rules), 4), dtype=np.uint8)  # _GpuScorer ctor args are ignored by the fake
    cracked_hashes_sorted = np.arange(cracked_size, dtype=np.uint32)
    selected = crg.celf_select_recompute_gpu(
        rules, wordlist_path="unused.txt", cracked_hashes_sorted=cracked_hashes_sorted,
        rule_batch_size=rule_batch_size, words_per_gpu_batch=1000,
        device_id=None, budget=budget, cost_alpha=cost_alpha,
    )
    return selected, fake


class TestGreedyRoundLogic:
    def test_picks_best_coverage_first_and_saturates(self, monkeypatch):
        rules = ["a", "b", "c"]
        coverage = {
            "a": {0, 1, 2},   # covers 3
            "b": {2, 3},      # covers 2
            "c": {4},         # covers 1, disjoint
        }
        selected, fake = _run(monkeypatch, rules, coverage, cracked_size=5, budget=2)
        # "a" (3) picked first, then "b" only has {3} left uncovered (gain 1)
        # once {0,1,2} are gone, same as "c" (gain 1) -- tie broken by
        # lower original index, i.e. earlier rule in `rules` -> "b" (idx 1)
        # beats "c" (idx 2).
        picked = [r for r, _g in selected]
        assert picked[0] == "a"
        assert selected[0][1] == 3
        assert picked[1] == "b"
        assert selected[1][1] == 1
        assert fake.remaining_active_count() == 1  # only hash id 4 left (from unpicked "c")

    def test_zero_gain_candidates_never_selected(self, monkeypatch):
        rules = ["a", "b"]
        coverage = {"a": {0, 1}, "b": set()}
        selected, _fake = _run(monkeypatch, rules, coverage, cracked_size=2)
        assert [r for r, _g in selected] == ["a"]

    def test_budget_cuts_off_selection(self, monkeypatch):
        rules = ["a", "b", "c"]
        coverage = {"a": {0}, "b": {1}, "c": {2}}
        selected, _fake = _run(monkeypatch, rules, coverage, cracked_size=3, budget=2)
        assert len(selected) == 2

    def test_no_candidates_with_any_hit_returns_empty(self, monkeypatch):
        rules = ["a", "b"]
        coverage = {"a": set(), "b": set()}
        selected, fake = _run(monkeypatch, rules, coverage, cracked_size=4)
        assert selected == []
        # One call for the upper-bound pass itself (both come back 0);
        # the greedy loop then has nothing with upper_bound > 0 to
        # even start a round with, so no further dispatches happen.
        assert fake.score_batch_calls == 1

    def test_lazy_bound_skips_dominated_candidates_without_gpu_call(self, monkeypatch):
        # "a" covers everything (gain 10). Once picked, every other
        # candidate's true gain against the now-empty active set is 0
        # -- their static upper_bound (their own full-universe count,
        # e.g. "b" covers 5 of the ORIGINAL 10) is a valid bound that's
        # still > 0, so a naive scan would want to re-check them, but
        # since best_gain in round 2 starts at 0 and every remaining
        # candidate's own upper_bound is also compared against
        # best_gain found so far in that round -- this test mainly
        # pins down that saturation (best_gain <= 0) correctly stops
        # the loop instead of continuing to emit zero-gain picks.
        rules = ["a", "b", "c"]
        coverage = {
            "a": set(range(10)),
            "b": set(range(5)),
            "c": set(range(3)),
        }
        selected, fake = _run(monkeypatch, rules, coverage, cracked_size=10)
        assert [r for r, _g in selected] == ["a"]
        assert fake.remaining_active_count() == 0

    def test_round_one_is_exact_scored_not_read_off_the_raw_bound(self, monkeypatch):
        # Round 1 must NOT trust the pass-1 upper_bound as an exact score:
        # that bound comes from the raw (possibly duplicate-inflated)
        # counting kernel, so even the first pick gets one singleton
        # rescore before it is accepted as the round's winner -- the same
        # exact-vs-bound separation rulest's _celf_select_from_upper_bounds
        # enforces. Calls: 1 for the upper-bound pass, 1 singleton
        # exact-score for round 1's pick ("a"), 1 singleton exact-score for
        # round 2's pick ("b") -- three score_batch calls total.
        rules = ["a", "b"]
        coverage = {"a": {0, 1}, "b": {2}}
        selected, fake = _run(monkeypatch, rules, coverage, cracked_size=3)
        assert [r for r, _g in selected] == ["a", "b"]
        assert fake.score_batch_calls == 3

    def test_ties_broken_by_lower_original_index(self, monkeypatch):
        rules = ["first", "second"]
        coverage = {"first": {0}, "second": {1}}
        selected, _fake = _run(monkeypatch, rules, coverage, cracked_size=2)
        # Both have gain 1 in round 1; "first" has the lower index (0)
        # so upper_bound sort (stable, descending on equal values)
        # keeps it first.
        assert selected[0][0] == "first"


def _mix64_reference(x):
    with np.errstate(over="ignore"):
        x = (np.uint64(x) + np.uint64(0x9E3779B97F4A7C15)) & np.uint64(0xFFFFFFFFFFFFFFFF)
        x = ((x ^ (x >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)) & np.uint64(0xFFFFFFFFFFFFFFFF)
        x = ((x ^ (x >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)) & np.uint64(0xFFFFFFFFFFFFFFFF)
        return (x ^ (x >> np.uint64(31))) & np.uint64(0xFFFFFFFFFFFFFFFF)


class TestBuildOpenAddressingTableVectorized:
    """_build_open_addressing_table() is the vectorized (NumPy,
    wave-based) replacement for the original per-key Python `for h in
    ...: while occupied[...]: ...` loop that built the GPU hash table.
    Pure NumPy, no OpenCL involved, so it's directly testable without a
    GPU. These tests check it against a reference implementation of
    that original loop for exact behavioral equivalence (same table
    contents are reachable via the same linear-probe lookup rule,
    same occupied-bit convention), not just "doesn't crash"."""

    @staticmethod
    def _reference_loop_build(cracked, table_size, mask):
        hash_table = np.zeros(table_size, dtype=np.uint64)
        occupied = np.zeros((table_size + 31) // 32, dtype=np.uint32)
        for h in np.asarray(cracked, dtype=np.uint64):
            slot = int(_mix64_reference(np.uint64(h))) & mask
            while occupied[slot >> 5] & (1 << (slot & 31)):
                slot = (slot + 1) & mask
            hash_table[slot] = h
            occupied[slot >> 5] |= np.uint32(1 << (slot & 31))
        return hash_table, occupied

    @staticmethod
    def _lookup(hash_table, occupied, mask, key):
        """Mirrors the GPU kernel's lookup_cracked_slot() probe rule."""
        slot = int(_mix64_reference(np.uint64(key))) & mask
        for _ in range(len(hash_table)):
            word, bit = slot >> 5, slot & 31
            if occupied[word] & (1 << bit):
                if hash_table[slot] == key:
                    return slot
            else:
                return -1
            slot = (slot + 1) & mask
        return -1

    def _table_size_for(self, n):
        table_size = 1
        target = max(2, int(math.ceil(n * 2.0)))
        while table_size < target:
            table_size <<= 1
        return table_size

    def test_matches_reference_occupied_bitcount(self):
        rng = np.random.default_rng(42)
        cracked = np.unique(rng.integers(0, 2**64, size=5000, dtype=np.uint64))
        table_size = self._table_size_for(len(cracked))
        mask = table_size - 1

        ref_table, ref_occ = self._reference_loop_build(cracked, table_size, mask)
        vec_table, vec_occ = crg._build_open_addressing_table(cracked, table_size, mask)

        assert vec_occ.dtype == np.uint32
        assert vec_occ.shape == ref_occ.shape
        vec_bits_set = np.unpackbits(vec_occ.view(np.uint8), bitorder='little').sum()
        ref_bits_set = np.unpackbits(ref_occ.view(np.uint8), bitorder='little').sum()
        assert vec_bits_set == ref_bits_set == len(cracked)

    def test_every_key_findable_via_gpu_probe_rule(self):
        rng = np.random.default_rng(7)
        cracked = np.unique(rng.integers(0, 2**64, size=20000, dtype=np.uint64))
        table_size = self._table_size_for(len(cracked))
        mask = table_size - 1

        vec_table, vec_occ = crg._build_open_addressing_table(cracked, table_size, mask)
        for key in cracked[:2000]:
            assert self._lookup(vec_table, vec_occ, mask, int(key)) != -1

    def test_no_key_collisions_in_stored_table(self):
        rng = np.random.default_rng(99)
        cracked = np.unique(rng.integers(0, 2**64, size=3000, dtype=np.uint64))
        table_size = self._table_size_for(len(cracked))
        mask = table_size - 1

        vec_table, vec_occ = crg._build_open_addressing_table(cracked, table_size, mask)
        occ_bits = np.unpackbits(vec_occ.view(np.uint8), bitorder='little')[:table_size]
        occupied_keys = vec_table[occ_bits.astype(bool)]
        assert len(occupied_keys) == len(cracked)
        assert set(occupied_keys.tolist()) == set(cracked.tolist())

    def test_small_and_edge_sizes(self):
        for n in (0, 1, 2, 5):
            cracked = np.arange(n, dtype=np.uint64) * np.uint64(2654435761)
            cracked = np.unique(cracked)
            table_size = self._table_size_for(max(len(cracked), 1))
            mask = table_size - 1
            vec_table, vec_occ = crg._build_open_addressing_table(cracked, table_size, mask)
            bits_set = np.unpackbits(vec_occ.view(np.uint8), bitorder='little').sum()
            assert bits_set == len(cracked)
            for key in cracked:
                assert self._lookup(vec_table, vec_occ, mask, int(key)) != -1


def test_opencl_source_keeps_fnv1a64_as_uint64_before_lookup():
    src = crg.get_recompute_kernel_source(num_cracked=8, hash_table_size=16)
    # CELF uses FNV-1a-64. Truncating the kernel result to uint32 makes
    # every lookup effectively search for the low 32 bits in a uint64 table,
    # which can turn a valid cracked universe into zero hits.
    assert src.count('ulong h = fnv1a_hash_64(result_temp, (unsigned int)out_len);') == 5
    assert src.count('unsigned int h = fnv1a_hash_64(result_temp, (unsigned int)out_len);') == 0


def test_uint64_cracked_fingerprint_with_high_bits_is_preserved():
    from rule_ranker.hashing import build_open_addressing_table_uint64

    # Regression fixture: this key is intentionally larger than uint32.
    key = np.uint64(0xF123456789ABCDEF)
    table, states = build_open_addressing_table_uint64(
        np.array([key], dtype=np.uint64)
    )
    occupied = np.packbits(states == 2, bitorder='little')
    pad = (-len(occupied)) % 4
    if pad:
        occupied = np.concatenate([occupied, np.zeros(pad, dtype=np.uint8)])
    occupied = occupied.view(np.uint32)

    mask = len(table) - 1
    slot = int(_mix64_reference(key)) & mask
    found = False
    for _ in range(len(table)):
        word, bit = slot >> 5, slot & 31
        if occupied[word] & (1 << bit):
            if table[slot] == key:
                found = True
                break
        else:
            break
        slot = (slot + 1) & mask
    assert found


def test_opencl_source_contains_empty_rotate_guard_and_overflow_abort():
    src = crg.get_recompute_kernel_source(num_cracked=8, hash_table_size=16)
    assert 'if (in_len <= 0)' in src
    assert 'if (in_len*2>MAX_OUTPUT_LEN) return -2;' in src
    assert 'if (in_len+1>MAX_OUTPUT_LEN) return -2;' in src
    assert 'if (result < 0)' in src


class TestCostWeightedCelf:
    """cost_alpha ported from rulest's `_celf_select_from_upper_bounds`:
    heap priority becomes gain / cost(rule) instead of raw gain, where
    cost(rule) = max(1, token_count) ** cost_alpha."""

    def test_default_cost_alpha_is_unchanged_equal_cost_greedy(self, monkeypatch):
        rules = ["a", "b", "c"]
        coverage = {"a": {0, 1, 2}, "b": {2, 3}, "c": {4}}
        selected, _fake = _run(monkeypatch, rules, coverage, cracked_size=5, budget=2,
                                cost_alpha=0.0)
        picked = [r for r, _g in selected]
        assert picked == ["a", "b"]
        assert [g for _r, g in selected] == [3, 1]

    def test_cost_alpha_prefers_cheaper_rule_at_equal_gain(self, monkeypatch):
        # "short rule" and "much longer four word rule" cover the same 2
        # hashes -- equal raw gain, so the equal-cost greedy (cost_alpha=0)
        # falls back to the deterministic tie-break (lower original index),
        # picking whichever rule happens to come first in the candidate
        # list regardless of length.
        rules = ["much longer four word rule", "short rule"]
        coverage = {
            "much longer four word rule": {0, 1},
            "short rule": {0, 1},
        }
        selected_equal_cost, _ = _run(monkeypatch, rules, coverage, cracked_size=2,
                                       budget=1, cost_alpha=0.0)
        assert selected_equal_cost[0][0] == "much longer four word rule"

        # With cost_alpha > 0, the 2-token rule is cheaper than the 5-token
        # one, so gain/cost ranks it higher even though it comes second in
        # `rules` -- this is the one thing the old equal-cost greedy could
        # not express at all.
        selected_cost_weighted, _ = _run(monkeypatch, rules, coverage, cracked_size=2,
                                          budget=1, cost_alpha=1.0)
        assert selected_cost_weighted[0][0] == "short rule"

    def test_cost_alpha_does_not_change_raw_gain_bookkeeping(self, monkeypatch):
        # Reported/returned gains must stay true coverage counts, never
        # cost-normalized scores, no matter what cost_alpha is.
        rules = ["one two three four five", "x"]
        coverage = {"one two three four five": {0, 1, 2}, "x": {0, 1, 2}}
        selected, fake = _run(monkeypatch, rules, coverage, cracked_size=3, budget=1,
                               cost_alpha=2.0)
        assert selected[0][0] == "x"
        assert selected[0][1] == 3  # raw gain, not gain/cost
        assert fake.remaining_active_count() == 0


def test_compacted_exact_hits_split_by_counts_and_keep_duplicates_for_unique():
    rule_indices = [10, 20, 30]
    counts = np.asarray([2, 3, 1], dtype=np.int32)
    compact_hits = np.asarray([91, 5, 12, 12, 13, 7], dtype=np.uint32)
    slot_parts = {idx: [] for idx in rule_indices}

    nonempty = crg._append_compacted_exact_hits(
        rule_indices, compact_hits, counts, slot_parts)

    assert nonempty == 3
    assert np.array_equal(np.unique(np.concatenate(slot_parts[10])), [5, 91])
    assert np.array_equal(np.unique(np.concatenate(slot_parts[20])), [12, 13])
    assert np.array_equal(np.unique(np.concatenate(slot_parts[30])), [7])


def test_compacted_exact_hits_support_empty_rule_segments():
    rule_indices = [1, 2, 3, 4]
    counts = np.asarray([0, 2, 0, 1], dtype=np.int32)
    compact_hits = np.asarray([8, 9, 7], dtype=np.uint32)
    slot_parts = {idx: [] for idx in rule_indices}

    nonempty = crg._append_compacted_exact_hits(
        rule_indices, compact_hits, counts, slot_parts)

    assert nonempty == 2
    assert slot_parts[1] == []
    assert np.array_equal(slot_parts[2][0], [8, 9])
    assert slot_parts[3] == []
    assert np.array_equal(slot_parts[4][0], [7])


def test_compacted_exact_hits_reject_wrong_result_size_and_counts():
    with pytest.raises(ValueError, match="expected 4"):
        crg._append_compacted_exact_hits(
            [4, 5], np.asarray([10], dtype=np.uint32),
            np.asarray([2, 2]), {4: [], 5: []})
    with pytest.raises(ValueError, match="non-negative"):
        crg._append_compacted_exact_hits(
            [4], np.asarray([], dtype=np.uint32),
            np.asarray([-1]), {4: []})



def test_fresh_exact_batch_scans_past_interleaved_nonfresh_heap_entries():
    import heapq

    heap = [(-10, 0, 10), (-9, 1, 9), (-8, 2, 8), (-7, 3, 7), (-6, 4, 6)]
    heapq.heapify(heap)
    fresh = {0, 2, 3, 4}

    batch = crg._collect_fresh_exact_batch(
        heap, fresh, 2, lambda bound, idx: True, scan_factor=4)

    assert batch == [0, 2]
    assert fresh == {3, 4}
    # The non-fresh entry was not consumed or reordered relative to the heap.
    assert heapq.heappop(heap)[1] == 1


def test_exact_batch_kernel_uses_per_rule_segments_and_gpu_compaction():
    source = crg.get_recompute_kernel_source(num_cracked=8, hash_table_size=16)
    start = source.index("void score_exact_batch_kernel(")
    end = source.index("// Clears a small, EXPLICIT list", start)
    kernels = source[start:end]
    score_kernel = kernels[:kernels.index("void compact_exact_hits_kernel(")]
    compact_kernel = kernels[kernels.index("void compact_exact_hits_kernel("):]

    assert "rule_hit_counts[rule_idx]" in score_kernel
    assert "rule_idx * words_per_rule_cap" in score_kernel
    assert "atomic_add" in score_kernel
    assert "hit_total_count" not in score_kernel
    assert "hit_rule_ids" not in score_kernel
    assert "rule_offsets[mid + 1] <= packed_idx" in compact_kernel
    assert "compact_hit_slots[packed_idx]" in compact_kernel


def test_gpu_exact_dedup_kernel_hashes_per_rule_and_returns_unique_counts():
    source = crg.get_recompute_kernel_source(num_cracked=8, hash_table_size=16)
    start = source.index("void score_exact_gpu_unique_batch_kernel(")
    end = source.index("// Compact only successful entries", start)
    kernel = source[start:end]

    assert "unique_table_capacity - 1U" in kernel
    assert "atomic_cmpxchg" in kernel
    assert "if (prior == slot) return" in kernel
    assert "rule_unique_counts[rule_idx]" in kernel
    assert "unique_hit_list[rule_idx * words_per_rule_cap" in kernel
    assert "atomic_add" in kernel


def test_exact_gpu_unique_plan_respects_memory_budget():
    from types import SimpleNamespace

    device = SimpleNamespace(
        global_mem_size=8 * 1024**3,
        max_mem_alloc_size=2 * 1024**3,
    )
    capacity, required = crg._exact_gpu_unique_plan(79_857, 256, device)
    assert capacity == 262_144
    assert required == 256 * 262_144 * 4

    # A much larger chunk would exceed the conservative 512 MiB budget.
    assert crg._exact_gpu_unique_plan(600_000, 256, device) == (0, 0)

    # Budget the hit-list and winner-cache allocations too, not just the hash
    # table. At 4 GiB the table alone fits the 1/16 budget, but all scratch
    # allocations together do not.
    smaller_device = SimpleNamespace(
        global_mem_size=4 * 1024**3,
        max_mem_alloc_size=2 * 1024**3,
    )
    assert crg._exact_gpu_unique_plan(79_857, 256, smaller_device) == (0, 0)


def test_exact_gpu_unique_plan_falls_back_when_device_memory_is_unknown():
    from types import SimpleNamespace

    assert crg._exact_gpu_unique_plan(79_857, 256, SimpleNamespace()) == (0, 0)


def test_record_exact_batch_winner_uses_byte_offsets_not_subbuffers(monkeypatch):
    from types import SimpleNamespace

    class Buffer:
        def get_sub_region(self, *_args, **_kwargs):
            raise AssertionError("D2D winner caching must not create aligned sub-buffers")

    captured = {}

    def fake_enqueue_copy(queue, dst, src, **kwargs):
        captured.update(queue=queue, dst=dst, src=src, **kwargs)
        return object()

    monkeypatch.setattr(crg, "cl", SimpleNamespace(enqueue_copy=fake_enqueue_copy))
    scorer = object.__new__(crg._GpuScorer)
    scorer.exact_gpu_unique_enabled = True
    scorer._last_exact_batch_rule_positions = {41: 2}
    scorer._last_exact_batch_counts = np.asarray([0, 2, 3], dtype=np.int32)
    scorer._exact_words_per_rule_cap = 17
    scorer.exact_hit_slots_g = Buffer()
    scorer.exact_winner_slots_g = Buffer()
    scorer.queue = object()
    scorer._last_winner_d2d_event = None
    scorer.exact_winner_d2d_copies = 0
    scorer.exact_winner_d2d_bytes = 0
    scorer._last_single_hits = (41, np.asarray([1, 2], dtype=np.uint32))
    scorer._last_gpu_recorded_hits = None
    scorer.exact_profiling_enabled = False

    assert scorer.record_exact_batch_winner(41) == 3
    assert captured["src_offset"] == 2 * 17 * 4
    assert captured["byte_count"] == 3 * 4
    assert captured["dst_offset"] == 0
    assert captured["src"] is scorer.exact_hit_slots_g
    assert captured["dst"] is scorer.exact_winner_slots_g
    assert scorer._last_gpu_recorded_hits == (41, 3)
    assert scorer._last_single_hits is None


class TestOpenCLBuildWarnings:
    def test_opencl_build_suppresses_only_pyopencl_compiler_notice(self, monkeypatch):
        import warnings

        class FakeCompilerWarning(Warning):
            pass

        class FakeProgram:
            def __init__(self, context, source):
                self.context = context
                self.source = source

            def build(self, **kwargs):
                warnings.warn(
                    "Non-empty compiler output encountered. Set PYOPENCL_COMPILER_OUTPUT=1",
                    FakeCompilerWarning,
                )
                warnings.warn("unrelated warning must remain visible", UserWarning)
                return self

        class FakeCL:
            CompilerWarning = FakeCompilerWarning
            Program = FakeProgram

        monkeypatch.setattr(crg, "cl", FakeCL)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            program = crg._build_opencl_program("ctx", "kernel source", options=["-cl-std=CL1.2"])

        assert isinstance(program, FakeProgram)
        assert program.context == "ctx"
        assert program.source == "kernel source"
        assert len(caught) == 1
        assert caught[0].category is UserWarning
        assert str(caught[0].message) == "unrelated warning must remain visible"


def test_celf_profile_reports_candidate_landscape_and_first_round_work(monkeypatch):
    """The opt-in profile exposes upper-bound shape and first-winner effort."""
    monkeypatch.setenv("RANKER_GREEDY_PROFILE", "1")
    messages = []
    monkeypatch.setattr(crg, "log", lambda message: messages.append(str(message)))

    class _SilentProgress:
        def __init__(self, *args, **kwargs):
            pass

        def update(self, *_args, **_kwargs):
            pass

        def set_postfix_str(self, *_args, **_kwargs):
            pass

        def set_postfix(self, *_args, **_kwargs):
            pass

        def reset_rate_window(self, *_args, **_kwargs):
            pass

        def close(self):
            pass

    monkeypatch.setattr(crg, "ProgressBar", _SilentProgress)

    class _ProfileScorer:
        def __init__(self, *_args, **_kwargs):
            self.active = set(range(10))
            self.calls = 0
            self.last_gpu_dispatches = 1
            self.exact_stage_profile = {
                "exact_kernel_gpu": [4, 0.125],
                "unique_cpu": [12, 0.250],
            }
            self.exact_batch_cap = 128
            self.exact_gpu_unique_enabled = True
            self.exact_gpu_unique_capacity = 8
            self.exact_gpu_unique_bytes = 256
            self.exact_gpu_unique_batches = 1
            self.recorded_exact_winners = []

        def record_exact_batch_winner(self, rule_idx):
            self.recorded_exact_winners.append(int(rule_idx))

        def score_exact_batch(self, rule_indices, _wordlist_path, progress_callback=None):
            exact = {0: 5, 1: 6, 2: 4, 3: 0}
            return {int(idx): (exact[int(idx)], None) for idx in rule_indices}

        def score_batch(self, rule_indices, _wordlist_path):
            indices = [int(i) for i in rule_indices]
            self.calls += 1
            # The first pass deliberately represents duplicate-inflated
            # upper bounds; later singleton scores represent exact gains.
            if self.calls == 1:
                return np.asarray([10, 8, 7, 0], dtype=np.int64)
            exact = {0: 5, 1: 6, 2: 4, 3: 0}
            tightened = {0: 5, 1: 8, 2: 7, 3: 0}
            if len(indices) > 1:
                return np.asarray([tightened[i] for i in indices], dtype=np.int64)
            return np.asarray([exact[indices[0]]], dtype=np.int64)

        def apply_winner_and_clear(self, _rule_idx, _rule_str, _wordlist_path):
            self.active.difference_update(range(6))
            return 6

        def remaining_active_count(self):
            return len(self.active)

    scorer_instances = []
    def _make_profile_scorer(*args, **kwargs):
        instance = _ProfileScorer(*args, **kwargs)
        scorer_instances.append(instance)
        return instance

    monkeypatch.setattr(crg, "_GpuScorer", _make_profile_scorer)
    rules = ["seed", "winner", "challenger", "no-hit"]
    selected = crg.celf_select_recompute_gpu(
        rules,
        wordlist_path="unused.txt",
        cracked_hashes_sorted=np.arange(10, dtype=np.uint32),
        rule_batch_size=4,
        words_per_gpu_batch=100,
        device_id=None,
        budget=1,
        cost_alpha=0.0,
    )

    assert selected == [("winner", 6)]
    assert scorer_instances[0].recorded_exact_winners == [1]
    log_text = "\n".join(messages)
    assert "candidate pool: total=4, active=3 (75.00%), zero-hit=1" in log_text
    assert "top-1 priority upper bound: rule=0, raw_hits=10" in log_text
    assert "top-10 raw upper-bound distribution: n=3, min=7, median=8.0" in log_text
    assert "top-100 raw upper-bound distribution: n=3" in log_text
    assert "first winner: rule=1, exact_gain=6, seed_rule=0" in log_text
    assert "exact_verified=2 (excluding seed)" in log_text
    assert "upper_bounds_tightened=2" in log_text
    assert "seed_exact=1" in log_text
    assert "winner_after_celf=" in log_text
    assert "exact scoring internals" in log_text
    assert "exact_kernel_gpu" in log_text
    assert "unique_cpu" in log_text
    assert "not additive to GPU event durations" in log_text


def test_exact_batch_default_is_256_and_environment_override_is_respected(monkeypatch):
    monkeypatch.delenv("RANKER_EXACT_BATCH", raising=False)
    assert crg._requested_exact_batch_cap() == 256
    monkeypatch.setenv("RANKER_EXACT_BATCH", "192")
    assert crg._requested_exact_batch_cap() == 192
    monkeypatch.setenv("RANKER_EXACT_BATCH", "0")
    assert crg._requested_exact_batch_cap() == 1


def test_unique_exact_slots_skips_concat_for_single_chunk(monkeypatch):
    slots = np.asarray([9, 3, 9, 4], dtype=np.uint32)

    def fail_concat(*_args, **_kwargs):
        raise AssertionError("single chunk must not be concatenated")

    monkeypatch.setattr(crg.np, "concatenate", fail_concat)
    assert np.array_equal(crg._unique_exact_slots([slots]), [3, 4, 9])
    assert crg._unique_exact_slots([]).dtype == np.uint32


def test_unique_exact_slots_still_merges_and_deduplicates_multiple_chunks():
    parts = [np.asarray([8, 2, 8], dtype=np.uint32),
             np.asarray([2, 5], dtype=np.uint32)]
    assert np.array_equal(crg._unique_exact_slots(parts), [2, 5, 8])


def test_exact_event_profile_duration_is_reported_in_seconds():
    class _Profile:
        start = 1_000_000
        end = 4_500_000

    class _Event:
        profile = _Profile()

    assert crg._GpuScorer._event_seconds(_Event()) == pytest.approx(0.0035)


def test_exact_event_profile_duration_is_optional_for_unprofiled_events():
    class _Event:
        @property
        def profile(self):
            raise RuntimeError("profiling not enabled")

    assert crg._GpuScorer._event_seconds(_Event()) is None
