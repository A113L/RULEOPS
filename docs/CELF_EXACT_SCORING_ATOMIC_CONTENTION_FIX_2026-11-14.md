# CELF exact-batch GPU write-path fix — 2026-11-14

## Problem

The multi-rule exact kernel appended every match to one shared output stream via
`atomic_add(hit_total_count, 1)`. All work-items for all candidates in a batch
contended on that single counter. The host then sorted all compact records by
local rule ID (`np.argsort`) before it could deduplicate each candidate's hits.
This path could dominate first-round exact challenger resolution when many
candidate/word pairs matched active targets.

## Change

`score_exact_batch_kernel` now assigns a deterministic output cell to each
`(rule, word)` pair:

- output index: `rule_idx * num_words + word_idx`;
- successful hit: cracked-target slot (`uint32`);
- no hit: `UINT32_MAX` sentinel.

Every work-item writes only to its own cell. The exact batch no longer has a
global append atomic, hit counter, local-rule-ID stream, or host-side global
sort. The host copies one contiguous rule-major matrix per word chunk, filters
sentinels per row, and retains the existing final `np.unique` across chunks.

Exact gains, active-target checks, CELF priority comparisons, and deterministic
tie-breaking are unchanged. `apply_winner_and_clear` still receives the exact
unique slot list for a winning candidate.

## Transfer trade-off

The transfer size is now fixed at `n_rules * n_words * sizeof(uint32)` for each
exact chunk, instead of copying only matching compact records plus rule IDs.
For the observed first-round landscape, where the highest raw upper bounds are
at the full wordlist size, the dense matrix avoids both global atomic
serialization and CPU sorting while transferring at most 4 bytes per
(rule, word) pair. Later rounds with sparse matches may transfer unused
sentinel cells; the new profile reports matrix MiB and non-empty rule rows so
this trade-off can be measured on the target GPU.

## Verification

- `pytest -q`: 570 passed, 5 skipped, 7 warnings.
- Focused CELF tests: 23 passed.
- Generated OpenCL kernel source passed `clang -x cl -cl-std=CL1.2 -fsyntax-only`.
- The GPU integration test was skipped because this environment has no real
  PyOpenCL/OpenCL runtime. No RTX 3060 Ti benchmark was performed here.
