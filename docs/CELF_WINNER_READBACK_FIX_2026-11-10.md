# CELF winner bitmap readback fix — 2026-11-10

## Root cause

The GPU winner bitmap snapshot and compaction path reached its final device-buffer-to-host-array copy with a `byte_count` keyword. The installed PyOpenCL read-buffer overload derives the transfer length from the destination NumPy array and does not accept `byte_count`. This raised an API argument error and caused CELF to fall back to the verified Record Mode scan for each selected winner.

## Fix

The compacted TARGET ID readback now passes the correctly sized `host_ids` NumPy view and `is_blocking=False`, without `byte_count`. The view length (`n_ids`) defines the exact transfer size. Buffer-to-buffer snapshot copies retain `byte_count`, which is supported by that separate PyOpenCL overload.

## Expected runtime indicators

With the GPU path working, expect:

- `winner_snapshot_calls > 0`
- `winner_compaction_calls > 0`
- `winner_bitmap_fetches > 0` (or the corresponding winner bitmap counters in the active profile format)
- `exact_record_scans` substantially below `selected`, ideally zero when every winner has a valid snapshot
- no `Winner bitmap materialization failed` warnings

## Validation

- Python syntax compilation: 86 files passed.
- CELF-focused regression tests: 30 passed.
- Hardware OpenCL execution was not available in the build environment; confirm the runtime counters on the target GPU.
