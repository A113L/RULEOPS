# Progress indicator fix — SQLite minimization phases

## Problem

The progressive minimizer displayed accurate percentage bars for candidate evaluation (`Minimize probes` / `Refine probes`). Inter-pass SQLite statements used `tqdm(total=None)`, however, so their output looked like an empty bar with `/?` even while SQLite's progress handler was reporting VM instructions. Very short aggregate queries could finish before the first callback and leave a misleading `0/?` line.

## Change

- Keep percentage bars for phases with a known candidate count.
- For long SQLite statements, show the actual accumulated SQLite VM-op count and elapsed time instead of an empty, indeterminate bar.
- Create the SQLite activity indicator lazily on the first progress callback.
- Do not render an empty progress bar for short SQL statements that finish before the first callback.
- Do not estimate or invent a percentage for SQLite operations whose total VM work is not knowable in advance.

## Validation

- `python -m compileall -q .` — passed.
- `pytest -q tests/test_minimize.py` — 19 passed.
- Full GPU-dependent tests were not run in this environment because `pyopencl` is unavailable.
