"""Regression tests for Stage 3 memory/progress behaviour on large wordlists."""
from types import SimpleNamespace

import numpy as np

from rulest.genetic import GeneticRuleEvolver, _ga_uses_full_sweep, _hit_count
from rulest.gpu_engine import GPUEngine


def test_large_wordlist_does_not_force_generation_zero_or_periodic_full_sweeps():
    # Large lists run bounded samples throughout GA; the exact candidate pass
    # later restores counts against the full wordlist.
    assert _ga_uses_full_sweep(0, True, False, 4) is False
    assert _ga_uses_full_sweep(4, True, False, 4) is False
    assert _ga_uses_full_sweep(0, True, True, 4) is False
    assert _ga_uses_full_sweep(4, True, True, 4) is True
    assert _ga_uses_full_sweep(1, False, False, 4) is True


def test_hit_bitmap_population_count_matches_set_count():
    packed = np.zeros(3, dtype=np.uint8)
    packed[0] = (1 << 0) | (1 << 3) | (1 << 7)
    packed[1] = (1 << 2) | (1 << 5)
    assert _hit_count(packed) == 5
    assert _hit_count({0, 3, 7, 10, 13}) == 5


def test_eval_on_engine_replaces_empty_bucket_with_compact_bitmap():
    class FakeEngine:
        def evaluate_chains_for_ga(self, chains):
            bitmap = np.zeros(2, dtype=np.uint8)
            bitmap[0] = 0b00000101
            bitmap[1] = 0b00000010
            return {"a b": bitmap}

    evolver = GeneticRuleEvolver.__new__(GeneticRuleEvolver)
    hit_words = {"a b": set(), "c d": set()}
    evolver._eval_on_engine(FakeEngine(), ["a b", "c d"], hit_words)

    assert isinstance(hit_words["a b"], np.ndarray)
    assert _hit_count(hit_words["a b"]) == 3
    assert hit_words["c d"] == set()


def test_gpu_ga_evaluator_builds_bitmaps_not_python_integer_sets():
    # Exercise the GPU-engine aggregation without calling OpenCL.  The real
    # kernel's small (word-index, chain-string) result rows are converted into
    # one bit per word as batches complete.
    fake = SimpleNamespace(
        params={"CHAINS_PER_BATCH": 10, "WORD_SUB_BATCH": 4},
        _base_words_precomputed=(None, np.zeros(8, dtype=np.int32), None),
    )
    fake._compute_chain_seqs = lambda chains: ([], [])

    def get_batch(start, end):
        return {"num_words": end - start, "start": start}

    fake.get_word_batch_data = get_batch

    def run_kernel(batch, chains, _precomputed, return_word_idx, _profile):
        assert return_word_idx is True
        if batch["start"] == 0:
            return [(0, "a b"), (1, "a b"), (3, "c d")]
        return [(0, "c d"), (3, "a b")]

    fake._run_chain_kernel = run_kernel
    result = GPUEngine.evaluate_chains_for_ga(fake, ["a b", "c d"])

    assert isinstance(result["a b"], np.ndarray)
    assert isinstance(result["c d"], np.ndarray)
    assert _hit_count(result["a b"]) == 3  # local indices 0, 1, 7
    assert _hit_count(result["c d"]) == 2  # local indices 3, 4


def test_gpu_ga_count_only_verification_does_not_allocate_hit_bitmaps():
    # The post-GA exact correction only needs the number of matches per chain.
    # It must not allocate one dense word bitmap per candidate chain.
    fake = SimpleNamespace(
        params={"CHAINS_PER_BATCH": 10, "WORD_SUB_BATCH": 4},
        _base_words_precomputed=(None, np.zeros(8, dtype=np.int32), None),
    )
    fake._compute_chain_seqs = lambda chains: ([], [])
    fake._ensure_ga_verify_base_buffers = lambda: False

    def get_batch(start, end):
        return {"num_words": end - start, "start": start}

    fake.get_word_batch_data = get_batch

    def run_count_kernel(batch, chains, _precomputed, _profile):
        if batch["start"] == 0:
            return {"a b": 2, "c d": 1}
        return {"a b": 1, "c d": 1}

    fake._run_chain_count_kernel = run_count_kernel
    result = GPUEngine.evaluate_chains_for_ga(fake, ["a b", "c d"], return_counts=True)

    assert result == {"a b": 3, "c d": 2}
    assert all(not isinstance(value, np.ndarray) for value in result.values())


def test_popcount_lookup_is_portable_and_covers_all_byte_values():
    # This lookup must not depend on int.bit_count(), which is unavailable on
    # older Python runtimes used by some RULEOPS installations.
    from rulest.genetic import _POPCOUNT8

    expected = [bin(value).count("1") for value in range(256)]
    assert _POPCOUNT8.tolist() == expected


def test_gpu_engine_run_cleanup_closes_shared_base_and_target_owners(tmp_path):
    from rulest.io_utils import load_wordlist

    base_path = tmp_path / "base.txt"
    target_path = tmp_path / "target.txt"
    base_path.write_bytes(b"alpha\nbeta\n")
    target_path.write_bytes(b"alpha!\nbeta!\n")

    base_words = load_wordlist(base_path)
    target_words = load_wordlist(target_path)
    base_data_mmap = base_words._data_shm._mmap
    base_offsets_mmap = base_words._offsets_shm._mmap
    target_data_mmap = target_words._data_shm._mmap
    target_offsets_mmap = target_words._offsets_shm._mmap

    engine = GPUEngine({})
    engine.set_base_words(base_words)
    engine._bloom_target_owner = target_words
    engine._bloom_recovery_fn = lambda: target_words

    engine.release_run_references()

    assert engine._base_words_precomputed is None
    assert engine._base_words_owner is None
    assert engine._bloom_recovery_fn is None
    assert engine._bloom_target_owner is None
    assert base_data_mmap.closed
    assert base_offsets_mmap.closed
    assert target_data_mmap.closed
    assert target_offsets_mmap.closed

    # The CLI also closes its owning references; this must be idempotent.
    base_words.close()
    target_words.close()


def test_replacing_worker_wordlist_closes_old_attachment_not_parent(tmp_path):
    import pickle
    from rulest.io_utils import load_wordlist

    path = tmp_path / "shared.txt"
    path.write_bytes(b"alpha\nbeta\ngamma\n")
    parent_words = load_wordlist(path)
    parent_mmap = parent_words._data_shm._mmap
    first_attachment = pickle.loads(pickle.dumps(parent_words))
    second_attachment = pickle.loads(pickle.dumps(parent_words))
    first_mmap = first_attachment._data_shm._mmap
    second_mmap = second_attachment._data_shm._mmap

    engine = GPUEngine({})
    engine.set_base_words(first_attachment)
    engine.set_base_words(second_attachment)

    assert first_mmap.closed
    assert not second_mmap.closed
    assert not parent_mmap.closed
    assert engine._base_words_owner is second_attachment

    engine.release_run_references()
    assert second_mmap.closed
    assert not parent_mmap.closed
    parent_words.close()
    assert parent_mmap.closed


def test_reusing_same_parent_wordlist_does_not_close_it_early(tmp_path):
    from rulest.io_utils import load_wordlist

    path = tmp_path / "same.txt"
    path.write_bytes(b"one\ntwo\n")
    words = load_wordlist(path)
    data_mmap = words._data_shm._mmap

    engine = GPUEngine({})
    engine.set_base_words(words)
    engine.set_base_words(words)

    assert not data_mmap.closed
    assert engine._base_words_owner is words
    engine.release_run_references()
    assert data_mmap.closed


def test_ga_exact_count_mode_uses_device_count_kernel_and_accumulates(monkeypatch):
    """Final GA verification must use scalar GPU counts, not hit-record output."""
    engine = GPUEngine({})
    engine.params = {'CHAINS_PER_BATCH': 8, 'WORD_SUB_BATCH': 2}
    engine._base_words_precomputed = (
        np.zeros(1, dtype=np.uint8),
        np.arange(5, dtype=np.int32),
        np.ones(5, dtype=np.int32),
    )
    engine._compute_chain_seqs = lambda chains: ([0] * len(chains), [1] * len(chains))
    engine.get_word_batch_data = lambda start, end: {
        'words_flat': np.zeros(max(1, end - start), dtype=np.uint8),
        'word_offsets': np.zeros(end - start, dtype=np.int32),
        'word_lengths': np.ones(end - start, dtype=np.int32),
        'num_words': end - start,
        'num_rules': 1,
    }
    calls = []

    def fake_count_kernel(words, chains, _precomputed=None, _profile=None):
        calls.append((words['num_words'], tuple(chains)))
        n = words['num_words']
        return {chains[0]: n, chains[1]: max(0, n - 1)}

    engine._run_chain_count_kernel = fake_count_kernel
    engine._run_chain_kernel = lambda *a, **k: (_ for _ in ()).throw(
        AssertionError('legacy per-hit output path must not be used for return_counts')
    )

    result = engine.evaluate_chains_for_ga(['a b', 'c d'], return_counts=True)

    assert result == {'a b': 5, 'c d': 2}
    assert [n for n, _ in calls] == [2, 2, 1]


def test_ga_exact_count_mode_prefers_resident_base_sweep():
    engine = GPUEngine({})
    engine.params = {'CHAINS_PER_BATCH': 8, 'WORD_SUB_BATCH': 2}
    engine._base_words_precomputed = (
        np.zeros(1, dtype=np.uint8),
        np.arange(5, dtype=np.int32),
        np.ones(5, dtype=np.int32),
    )
    engine._compute_chain_seqs = lambda chains: ([0] * len(chains), [1] * len(chains))
    engine._ensure_ga_verify_base_buffers = lambda: True
    calls = []

    def fake_sweep(chains, _precomputed=None, _profile=None):
        calls.append(tuple(chains))
        return {chain: index + 3 for index, chain in enumerate(chains)}

    engine._run_chain_count_sweep = fake_sweep
    engine.get_word_batch_data = lambda *_a: (_ for _ in ()).throw(
        AssertionError('resident sweep should not slice and re-upload BASE')
    )

    result = engine.evaluate_chains_for_ga(['a b', 'c d'], return_counts=True)
    assert result == {'a b': 3, 'c d': 4}
    assert calls == [('a b', 'c d')]
