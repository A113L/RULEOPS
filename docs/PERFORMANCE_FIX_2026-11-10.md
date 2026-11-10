# RULEOPS performance repair — 2026-11-10

This patch uses the supplied fast RULEST v3 archive as a reference while preserving the current RULEOPS application and its additional features.

## Changes

- **STAGE 0 membership:** on POSIX systems using `fork`, RULEOPS now prefers CPython's native exact `set[str]` when the OS reports sufficient available RAM. This avoids computing each 64-bit FNV fingerprint in a Python character loop for every membership check. Worker processes inherit the set copy-on-write. If available RAM is insufficient, or the platform uses `spawn`, RULEOPS retains the compact shared hash-table/Bloom-filter path.
- **STAGE 1 word preparation:** BASE is flattened once and GPU batches are views into the cached packed data. This avoids rebuilding batch offsets/lengths and repeatedly preparing word slices for each launch. Very large packed wordlists that exceed the int32 offset limit retain the previous bounded-batch fallback.
- **UI:** the single RULEST sidebar button remains in place; no RULEST dropdown/submenu was reintroduced.

## Compatibility and validation

- The GPU rule semantics, seed-family generation, STAGE S chain scan, and STAGE 2 search kernel were not rewritten: comparison with the supplied fast RULEST archive showed those core paths already match closely. The patch avoids a risky wholesale downgrade of RULEOPS.
- 192 focused tests passed (Stage 0, shared wordlists, hash table, common utilities, profiling, and minimization).
- All 84 Python files passed AST parsing / syntax validation.
- A live OpenCL/GPU benchmark was not possible in this environment because `pyopencl` and the user's RTX 3060 Ti are not available here.

## Interpreting the supplied log

The recorded STAGE 1 workload was 12,913,529 BASE words × 6,043 atomic rules = about 78.05 billion word-rule combinations. At the logged 927.6 million combinations/second, the arithmetic predicts about 84.1 seconds. Therefore that specific 84-second STAGE 1 run is consistent with the logged throughput; it does not by itself demonstrate a `flatten` regression. The supplied log ends at STAGE 1 completion and does not contain STAGE S timing, so it cannot establish the SEED PASS runtime.
