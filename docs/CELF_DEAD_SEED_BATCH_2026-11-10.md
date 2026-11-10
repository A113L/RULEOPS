# CELF dead-seed batching — 2026-11-10

## Log diagnosis

The attached RTX 3060 Ti run selected 78,211 rules, but the CELF scorer made
2,050,494 calls. Of those, 1,485,268 were exact singleton calls. The profile
reported 274.903 s in host enqueue time, versus 102.197 s in GPU kernel time.
Winner bitmap fetch, snapshot, and compaction costs were comparatively small.

This pattern is caused by CELF repeatedly popping a stale candidate whose raw
upper bound is still positive but whose exact marginal gain has fallen to zero.
The old loop exact-scored one such seed per callback, then continued to the
next candidate. Large saturated/duplicate-heavy pools therefore created a very
large number of tiny GPU launches and synchronizations.

## Fix

After the first zero-gain seed, the selector now drains subsequent stale seeds
in batches. It first refreshes their cheap raw-hit bounds and then exact-scores
only candidates whose tightened bound remains positive. If an exact batch
contains a live candidate, it becomes the current exact winner and normal CELF
challenger processing continues. Positive non-winners are reinserted with
those exact gains as admissible bounds; zero-gain candidates are discarded.

All exact scores in a drain batch use the same `covered` bitmap. No approximate
gain is used for winner selection, and the ordinary CELF comparison/tie logic
is preserved. The initial upper-bound pass, configured batch size, GPU hash
table, winner bitmap snapshot, and output ordering are not changed.

## Validation

- `tests/test_selection.py` includes dead-seed batching coverage and randomized
  comparison against exact greedy selection.
- Hardware OpenCL benchmarking is not available in this build environment.
  Confirm the reduction in `modes ... singleton` and host enqueue time on the
  RTX 3060 Ti after deployment.
