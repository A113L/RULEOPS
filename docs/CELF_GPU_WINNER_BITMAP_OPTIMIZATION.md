# CELF GPU winner-bitmap optimization

This build adds an exact winner-bitmap path to CELF selection. It does not change
candidate scoring, greedy priority, tie-breaking, upper bounds, or TARGET coverage
semantics.

## Normal path

1. Exact Mode scores a batch and writes one distinct-target bitmap row per candidate.
2. Whenever a candidate becomes the current exact leader, its bitmap row is copied
   device-to-device into a persistent winner snapshot. The copy is ordered on the
   same in-order OpenCL queue; no host bitmap readback is required.
3. Subsequent candidate scores may reuse the scratch bitmap without overwriting the
   preserved winner snapshot.
4. When the greedy round closes, a GPU compaction kernel turns set bits into TARGET
   IDs. Only the compact ID prefix is copied to the host.
5. The active TARGET set is updated from those IDs, as before.

The former Record Mode BASE rescan remains a guarded fallback for missing snapshot
support, OpenCL errors, invalid compact counts, or a mismatch between compacted ID
count and the exact gain. That fallback preserves correctness over speed.

## Profiling

Set `RULEST_CELF_PROFILE=1` (or use the application's profiling option) to report:

- winner bitmap snapshots and bytes copied device-to-device;
- GPU compaction calls and compacted ID bytes;
- remaining seen-bitmap clear calls and bytes;
- CPU-side CELF heap build, heap push/pop, score-callback wall time, winner commit,
  and controller/progress/other time.

A successful normal GPU run should show winner snapshots and compaction calls, and
should substantially reduce `record` calls / `exact_record_scans`. A nonzero Record
Mode count is not necessarily an error: it can be the guarded compatibility fallback.

## Exact-batch bitmap initialization

Epoch-based lazy initialization is experimental and disabled by default. It
avoids clearing the whole `candidate_count x bitmap_words` seen matrix before
every exact scoring pass by initializing each candidate/target-word bitmap cell
only on first touch in the current generation. Despite the atomic first-touch
lock, the production verification log showed an exact-gain mismatch while this
mode was active. The deterministic full-buffer clear therefore remains the
normal path.

To opt in for a controlled A/B benchmark on a validated OpenCL driver, set:

```bash
RULEST_CELF_LAZY_BITMAP_INIT=1
```

When CELF detects a mismatch between batched exact gains and the independently
recorded winner, it discards the partial selection, resets GPU coverage, turns
off lazy bitmap initialization for the retry, and reruns using standard full
bitmap clears. It does not accept or keep the mismatched result.

## PyOpenCL buffer-copy compatibility fix

The winner and optional epoch snapshots use the buffer-to-buffer overload of
`cl.enqueue_copy`. That overload accepts `byte_count`, `src_offset`,
`dst_offset`, and `wait_for`; it does not accept the host-transfer-only
`is_blocking` keyword. The snapshots are still asynchronous and remain ordered
before subsequent CELF work by the in-order command queue. Host/device copies
are unchanged.
