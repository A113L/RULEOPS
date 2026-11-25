# Performance diagnostics and progress reporting

> [← Documentation index](../README.md)


This page records implementation details that are useful when interpreting
progress output. It is not a benchmark report and does not claim a universal
speedup.

## SQLite minimization progress

The minimizer's candidate-evaluation phases have known work counts and retain
percentage progress bars. Inter-pass SQLite statements do not expose a reliable
final work total, even though SQLite's progress handler reports virtual-machine
(VM) instruction activity.

The UI therefore creates an activity indicator lazily, on the first SQLite
progress callback, and reports accumulated VM operations and elapsed time. It
does not display an empty `/?` bar, invent a percentage, or leave a misleading
`0/?` line for very short statements that finish before the first callback.

## Reading performance numbers

- A progress percentage describes the stage whose total is known; it is not
  necessarily the percentage of the complete multi-stage job.
- GPU event time is device execution time. Host enqueue and synchronization
  measurements can overlap with device work and should not be added as if all
  categories were independent.
- Compare runs only when input files, parameters, device, driver and runtime are
  equivalent. The CELF-specific measurement caveats live in
  [`CELF_RANKER.md`](CELF_RANKER.md) and [`RULEST_CELF.md`](RULEST_CELF.md).
