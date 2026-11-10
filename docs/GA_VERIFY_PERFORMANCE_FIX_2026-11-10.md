# Stage 3 GA Verify performance improvement (2026-11-10)

## What changed

The final full-BASE correction for sampled GA candidates now uses a dedicated
OpenCL count-only kernel (`count_rule_chains_gpu`). It applies the same ordered
Hashcat rule-chain transformation and the same Bloom-filter test as the normal
chain-search kernel, but increments one GPU-side counter per candidate chain.
It does not emit chain strings or word indices for every hit and does not decode
those records in Python.

When the flattened BASE arrays fit the conservative VRAM budget, RULEOPS uploads
the flattened word bytes, offsets, and lengths once per GPU. The arrays stay
resident for the duration of GA Verify. Each candidate batch runs the wordlist
in bounded slices against those resident arrays, accumulating into one counter
buffer. The queue is synchronized and the small counter array is copied back
once per candidate batch. The resident arrays are released when GA Verify ends.

If the device cannot safely hold the full flattened BASE, RULEOPS falls back to
the bounded per-word-slice upload path. This preserves operation on lower-memory
GPUs instead of requiring a full-BASE GPU allocation.

## Candidate batch tuning

The default GA Verify candidate batch is now 128 chains (previous maximum: 64),
with a hard range of 16–256. Override it with:

```text
RULEOPS_GA_VERIFY_BATCH_SIZE=128
```

Lower the value on an unusual driver/device or raise it up to 256 if testing
shows a benefit. Invalid environment values safely fall back to 128.

## Validation

- 549 tests passed; 5 skipped (the skips require unavailable OpenCL hardware or
  legacy paths not used by the current RULEOPS build).
- OpenCL kernel template formatting passed.
- The generated OpenCL C source passed Clang OpenCL 1.2 syntax validation.
- No real GPU benchmark was possible in the build environment because it has no
  PyOpenCL/OpenCL runtime. Measure the improvement on the target GPU using the
  `[S3] Exact verification` and `S3 VERIFY` progress output.
