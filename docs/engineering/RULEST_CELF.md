# RULEST CELF: exact selection and GPU execution

> [← Documentation index](../README.md)


**Scope:** RULEST → Rule selection (`rulest/selection.py`).

**Scope:** RULEST greedy selection (`rulest/selection.py` and its GPU support).
This is separate from Rule Ranker's CELF post-processing; see
[`CELF_RANKER.md`](CELF_RANKER.md) for that implementation.

RULEST CELF selects rules by exact marginal coverage against the active TARGET
set. Upper bounds are used to prune and order candidates, not to commit a winner.
GPU optimizations described here preserve the exact scoring, covered-target
semantics, deterministic tie-breaking and selected-rule output.

## Stale zero-gain candidates and batched draining

Large or duplicate-heavy candidate pools can leave stale heap entries whose raw
upper bound remains positive after their true marginal gain has fallen to zero.
Scoring those entries one at a time creates many tiny GPU launches. The selector
now drains subsequent stale entries in batches: it refreshes their inexpensive
raw-hit bounds, then exact-scores only candidates whose tightened bound remains
positive. A batch shares the same `covered` bitmap.

If a batch contains a live candidate, that candidate is compared using its exact
gain and normal CELF challenger processing continues. Positive non-winners are
reinserted with their exact gains as admissible bounds; zero-gain candidates are
discarded. Approximate bounds never choose the winner. The initial upper-bound
pass, configured batch size, GPU hash table, winner snapshot and output ordering
are otherwise unchanged.

## Winner bitmap snapshot and compaction

The normal GPU path preserves the current exact winner without copying its full
bitmap to the host or rescanning BASE solely to reconstruct its hits:

1. Exact Mode scores candidates and produces a distinct-target bitmap row.
2. When a candidate becomes the current exact leader, its row is copied
   device-to-device into a persistent winner snapshot on the same in-order queue.
3. At the end of the greedy round, a GPU compaction kernel turns set bits into
   TARGET IDs; only the compact ID prefix is copied to the host.
4. The active TARGET state is updated from those IDs.

The older Record Mode BASE rescan remains a guarded fallback for missing snapshot
support, OpenCL errors, invalid compact counts, or a mismatch between the
compacted ID count and the exact gain. The fallback protects correctness; a
nonzero Record Mode count is not automatically an error.

## Experimental lazy bitmap initialization

Epoch-based lazy initialization of the exact-batch seen bitmap is experimental
and disabled by default. It avoids clearing the full
`candidate_count × bitmap_words` matrix before each exact scoring pass, but a
production verification run observed an exact-gain mismatch while it was enabled.
The deterministic full-buffer clear therefore remains the default.

For a controlled A/B test on a validated OpenCL driver, set:

```bash
RULEST_CELF_LAZY_BITMAP_INIT=1
```

If CELF detects a mismatch between batched exact gains and the independently
recorded winner, it discards the partial selection, resets GPU coverage, disables
lazy initialization for the retry and reruns with standard full bitmap clears.
A mismatched result is not accepted.

## Profiling and validation

Set `RULEST_CELF_PROFILE=1` (or enable the corresponding application profiling
option) to collect winner snapshot and device-copy counts, GPU compaction calls
and bytes, seen-bitmap clear work, and CPU-side heap / callback / winner-commit
timings. A successful normal GPU run should show snapshot and compaction calls
and substantially fewer `record` calls / `exact_record_scans`.

The dead-seed batching change is covered by `tests/test_selection.py`, including
randomized comparison against exact greedy selection. Hardware OpenCL benchmarking
was not available for the original implementation note; confirm launch counts
and host enqueue time on the target GPU when measuring performance.
