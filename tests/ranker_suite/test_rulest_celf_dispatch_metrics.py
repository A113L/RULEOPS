"""CPU-only coverage for RULEST's CELF kernel-dispatch accounting."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from rulest.gpu_engine import GPUEngine


def test_celf_kernel_dispatch_counters_track_actual_categories():
    engine = object.__new__(GPUEngine)
    engine._celf_kernel_dispatch_totals = {
        "total": 0, "score": 0, "winner_compaction": 0, "clear": 0,
    }
    engine._celf_kernel_dispatch_last = {
        "total": 0, "score": 0, "winner_compaction": 0, "clear": 0,
    }

    engine._celf_begin_kernel_operation()
    engine._celf_note_kernel_dispatch("score")
    engine._celf_note_kernel_dispatch("score")
    engine._celf_note_kernel_dispatch("winner_compaction")
    engine._celf_note_kernel_dispatch("clear")

    counts = engine.celf_dispatch_counts()
    assert counts == {
        "total": 4, "score": 2, "winner_compaction": 1, "clear": 1,
        "last_total": 4, "last_score": 2,
        "last_winner_compaction": 1, "last_clear": 1,
    }

    engine._celf_begin_kernel_operation()
    counts = engine.celf_dispatch_counts()
    assert counts["total"] == 4
    assert counts["last_total"] == 0


def test_celf_profile_includes_kernel_dispatch_counts():
    engine = object.__new__(GPUEngine)
    engine._celf_kernel_dispatch_totals = {
        "total": 7, "score": 4, "winner_compaction": 1, "clear": 2,
    }
    engine._celf_kernel_dispatch_last = {
        "total": 1, "score": 0, "winner_compaction": 0, "clear": 1,
    }
    engine._celf_profile = {
        "calls": 1, "batch_calls": 1, "singleton_calls": 0,
        "candidate_scores": 4, "wall_s": 1.0, "host_alloc_s": 0.0,
        "host_enqueue_s": 0.0, "wait_wall_s": 0.0, "kernel_gpu_s": 0.0,
        "h2d_gpu_s": 0.0, "fill_gpu_s": 0.0, "readback_gpu_s": 0.0,
        "upper_calls": 1, "exact_calls": 0, "record_calls": 0,
        "upper_candidates": 4, "exact_candidates": 0, "record_candidates": 0,
        "upper_singletons": 0, "exact_singletons": 0, "record_singletons": 0,
    }

    summary = engine.celf_profile_summary()
    assert "GPU kernel launches=7" in summary
    assert "score=4" in summary
    assert "winner_compaction=1" in summary
    assert "clear=2" in summary
