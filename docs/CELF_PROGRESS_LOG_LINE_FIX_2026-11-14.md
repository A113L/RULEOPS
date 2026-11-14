# CELF progress/log line separation fix — 2026-11-14

## Problem

CELF progress updates keep the current progress frame open with a carriage return (`\r`). The regular `ranker_postprocess.log()` implementation used `print()`, which appended `[CELF]` diagnostics to that still-open frame in redirected and captured output. This produced lines such as `heap=886,686[CELF]` and `rescored=9985[CELF]`.

## Change

- Added `write_log_line()` to `rule_ranker.progress`.
- Active progress bars are tracked weakly by output stream.
- Before a log message is emitted, the current progress row is cleared and terminated; the message is printed on its own line; the live progress frame is then redrawn.
- Routed `ranker_postprocess.log()` through this helper. Calls made without an active progress bar remain ordinary newline-terminated log lines.
- Added regression tests for the two observed CELF output cases.

This change affects terminal/log rendering only. It does not alter scoring, compaction, CELF priority ordering, tie-breaking, or selected rules.

## Verification

- `tests/ranker_suite`: 156 passed, 1 skipped.
- The skipped test requires a real PyOpenCL/OpenCL runtime, unavailable in the test environment.
