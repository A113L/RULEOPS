# CELF GPU Exact Scoring, Deduplication, Progress, and Profiling

**Implementation note:** 2026-11-14

**Area:** Rule Ranker / CELF recompute-GPU selection

## 1. Overview

The CELF selector uses upper bounds to avoid exact scoring every candidate on every round, but it never commits a winner from an approximate bound. Bounds are used to order and narrow the challenger set. A candidate must receive an exact marginal-gain evaluation, with duplicate cracked-target hits removed, before it can replace the current winner. The committed winner is then applied to the active-target state.

The changes covered here address four related areas:

1. Reduce exact-scoring result transfers by deduplicating candidate hits on the GPU when the wordlist is available as one resident chunk.
2. Retain the selected candidate's exact hit slots on the GPU and copy the winner's slots GPU-to-GPU instead of rerunning the full scoring pass just to record them.
3. Batch exact challenger verification and expose actual GPU kernel-dispatch counts and detailed stage timings.
4. Report first-round work separately from selected-rule progress, and calculate steady-state throughput and ETA from a moving time window.

The selected-rule ordering, exact marginal gains, active-target semantics, and deterministic tie-break rule are preserved.

## 2. CELF scoring and correctness

### 2.1 Upper bounds are not exact gains

The initial upper-bound pass and `batch_tighten` can count multiple base words that produce the same cracked target. Their values are therefore admissible upper bounds, not necessarily unique-target marginal gains.

These values may tighten heap priorities, but they are never allowed to replace the current winner directly. The selector resolves any candidate that can still beat the current exact winner with an exact, duplicate-aware score first. Equal priorities continue to use the original candidate index as the tie-break.

### 2.2 Fresh exact challengers are coalesced

Candidates promoted from the heap for exact verification are gathered into bounded batches rather than launching a full wordlist pass for every challenger individually. The selector scans a bounded heap window for fresh challengers that can still beat the current winner, while preserving deferred heap entries. Each candidate still receives its own exact gain before it is allowed to compete for the winner.

The effective exact batch cap is bounded by:

- `RANKER_EXACT_BATCH` (default: `256`),
- the implementation maximum of `256`, and
- the GPU dispatch-item limit for the current word-chunk size.

The speculative `batch_tighten` batch uses `RANKER_GREEDY_RESCORE_BATCH` (default: `256`) and is also bounded by the configured rule batch and GPU dispatch capacity.

### 2.3 Exact deduplication for one resident word chunk

When all words are available in one resident chunk and the GPU scratch allocation is safe, exact batch scoring uses a per-rule open-addressing hash set directly on the GPU:

1. Each `(rule, word)` work-item applies the Hashcat rule and looks up the resulting hash in the cracked-target table.
2. The target must still be active in the current CELF state.
3. Each rule owns an independent power-of-two open-addressing table. The table capacity is at least twice the number of words, keeping the maximum possible unique insertion count below the table capacity.
4. `atomic_cmpxchg` inserts a target slot only once per rule. Duplicate word-to-target hits for that rule are ignored.
5. A per-rule counter records the number of unique active target slots. The kernel also retains the unique slot list in GPU memory.
6. The host reads back only the small vector of per-rule counters. It does not read the per-hit slot lists or call CPU `np.unique()` on this single-chunk path.

When a candidate from the exact batch becomes the winner, the implementation copies its retained slot list into the winner buffer with a GPU-to-GPU copy. The winner is then applied to the active-target bitmap without another full base-word scoring pass solely to reconstruct its hits.

The scratch planner includes the per-rule hash tables, batch hit output, and persistent winner cache. It limits aggregate scratch to the smaller of one-sixteenth of reported global device memory and 512 MiB, and checks the hash-table allocation against the device's `max_mem_alloc_size`. A failed or unsafe allocation falls back to the compact exact path rather than weakening correctness.

### 2.4 Multi-chunk and fallback path

A wordlist split across multiple chunks must also remove duplicates that occur in different chunks. It therefore uses the compact hit-stream fallback:

- each rule writes hits into a bounded segment for the current chunk;
- the host reads the small per-rule counters and compacts the actual hit slots;
- the compact slot stream is read back and accumulated per rule across chunks;
- final `np.unique()` removes duplicates across all chunks before the exact gain is returned.

The fallback is also used when the GPU unique-table path is disabled or cannot be allocated. Set `RANKER_EXACT_GPU_DEDUP=0` to force the fallback for diagnosis or comparison.

No dense `rules × words` result matrix is transferred to the host. The single-chunk GPU-dedup path avoids result-slot D2H transfers entirely; the fallback transfers only compacted actual hits, not sentinel entries for misses.

## 3. Progress reporting and throughput metrics

### 3.1 First-round work is separate from selected rules

The first CELF round may score and tighten many candidates before the first winner is committed. During that work:

- `selected/N` remains at zero until a winner is committed;
- inner scoring callbacks report the current stage, chunk progress, batch size, GPU dispatches, and rescoring count;
- durable round-progress log messages are emitted periodically (the callback throttles them to about eight seconds).

This avoids presenting rescored candidates as already selected rules.

### 3.2 Moving throughput and ETA

The CELF progress bar uses a **30-second rolling window** with a **10-second minimum observation period**:

- `rule/s` is the selected-rule rate over the moving window;
- ETA is derived from the remaining selection budget and this recent `rule/s` value;
- while the window is warming up, the rate and ETA are shown as unavailable;
- after an idle window, the displayed rate can fall to `0.0` and ETA is suppressed instead of retaining a stale estimate.

When the first winner is committed, the rolling-rate window is reset. The overall elapsed timer and selected count are not reset. This prevents a long initial pass from diluting the steady-state throughput while keeping the displayed elapsed duration end-to-end.

The postfix also reports:

- `avg_rule/s`: cumulative average selected-rule rate since the first winner; this is diagnostic and is not the ETA rate;
- `rescored/s`: rescoring throughput over its own rolling window, starting after the first winner;
- `rescored`: rescoring work in the current round;
- `gpu_dispatches`: actual kernel launches counted for the current round;
- `heap`: remaining active candidates in the heap.

The distinction matters: `rule/s` is expected to respond to recent slowdowns or speedups, while `avg_rule/s` changes more gradually. The two values should not be interpreted as competing measurements.

### 3.3 GPU dispatch accounting

`gpu_dispatches` and the final `gpu_kernel_dispatches` profile count actual OpenCL kernel launches used by CELF operations, including exact scoring, batch tightening, singleton exact scoring, and winner application. They are more useful for launch-overhead analysis than counting only high-level scorer method calls.

## 4. Profiling

Set `RANKER_GREEDY_PROFILE=1` to collect the CELF stage breakdown and exact-scoring internals.

The high-level profile separates:

- `upper_bound_pass` — initial candidate upper bounds;
- `seed_exact` — exact evaluation of the seed candidate in each round;
- `batch_tighten` — batched upper-bound tightening;
- `fresh_resolve_exact_batch` — exact verification of fresh challengers;
- `apply_winner_and_clear` — updating the active-target state after a winner.

The exact-scoring profile can separately report rule packing, H2D transfer, GPU unique-table reset, count reset, exact kernel time, small counter D2H transfer and wait, winner-slot D2D copies, compact-result fallback operations, and total exact-batch wall time.

**Timing caveat:** GPU event durations are device-side measurements. Fields ending in `_wait_wall` include synchronization with previously queued work; they overlap with device execution and must not be added to GPU event durations as if they were independent stages.

## 5. Configuration reference

| Setting | Default | Purpose |
|---|---:|---|
| `RANKER_EXACT_BATCH` | `256` | Maximum requested fresh exact-verification batch; effective size may be clamped by dispatch capacity. |
| `RANKER_GREEDY_RESCORE_BATCH` | `256` | Speculative batch size used to tighten candidate bounds; effective size is clamped by rule-batch and dispatch limits. |
| `RANKER_EXACT_GPU_DEDUP` | enabled (`1`) | Enables per-rule GPU open-addressing deduplication when the one-resident-chunk and memory-safety conditions are met. Set to `0` to force compact-result fallback. |
| `RANKER_GREEDY_PROFILE` | disabled (`0`) | Enables detailed CELF stage and exact-scoring profiling. |
| `RULEST_CELF_LOG_INTERVAL` | `0.5` seconds in the web heartbeat | Controls the web progress heartbeat interval; increase it to reduce log volume. |

The batch settings are ceilings, not promises that every exact batch will contain 256 rules. The actual batch size depends on the remaining eligible challengers, the heap bounds, word-chunk size, and the GPU dispatch limit.

## 6. Observed run: 2026-11-14, 16:54:47–17:00:37

The following measurements come from the run excerpt supplied with this change. They describe that specific input and device; they are not a hardware-independent speedup claim.

### 6.1 Workload and first winner

- Candidate count reported by the upper-bound distribution: `999,999`.
- Active challengers at the start of the first CELF round: `886,686`.
- Selection budget: `250,000` rules.
- Word chunk: `79,857` words.
- First winner: rule index `2`, exact gain `79,054`; seed rule index `119`.
- First winner committed after `65.5 s` with `4,294` GPU dispatches and `1,098,753` rescored candidates.
- First-round work: `549,376` exact-verified challengers (excluding the seed), `549,376` upper bounds tightened, and one seed exact evaluation.

The long first round is not explained by the candidate count alone. The log's top-100 raw upper bounds were all `79,857`, indicating that the initial bounds were very loose for this workload. Many challengers therefore needed tightening or exact verification before the first winner could be proven.

### 6.2 Completion and throughput

The progress bar reached `250,000/250,000` at `17:00:37`, showing `05:49` elapsed from the CELF progress-bar start. The final line reported:

- rolling `rule/s`: `926.4`;
- cumulative `avg_rule/s`: `880.2`;
- rolling `rescored/s`: `7,142.8`;
- progress: `100.0%`.

The preceding samples showed short-term variation (for example, `983.3`, `899.7`, `894.4`, `917.3`, and `926.4 rule/s`). This is expected for a moving-window measurement and is why the cumulative `avg_rule/s` is reported separately.

The final greedy profile reported `3,692,210` candidate rescoring operations after the initial pass, `rescore_batch=256`, `exact_batch_cap=256`, and `518,200` GPU kernel dispatches.

### 6.3 GPU deduplication and transfer results

The run used the one-chunk GPU per-rule open-addressing path:

- exact batches: `9,081`;
- unique-table capacity: `262,144` slots per rule;
- hash-table allocation: `256.0 MiB`;
- total exact-dedup scratch: `334.3 MiB` for batch cap `256`;
- compact result-slot D2H reads: `0`;
- GPU compaction launches: `0`;
- hit-data D2H: `0.0 MiB`;
- small counter D2H reads: `9,081`, totaling `4.478 MiB`;
- non-empty rule rows: `1,173,810`;
- winner-slot D2D cache: `6,866` copies, `24.4 MiB`.

The fresh exact-resolve batches averaged `129.3` rules; `2,147` of `9,081` batches reached the cap of `256`.

### 6.4 High-level stage profile

| Stage | Calls / candidates | Time | Share |
|---|---:|---:|---:|
| `upper_bound_pass` | `999,999` | `58.4 s` | `15.5%` |
| `seed_exact` | `250,000` | `68.4 s` | `18.1%` |
| `fresh_resolve_exact_batch` | `1,173,810` | `75.5 s` | `20.0%` |
| `batch_tighten` | `2,268,400` | `154.0 s` | `40.8%` |
| `apply_winner_and_clear` | `250,000` | `21.4 s` | `5.7%` |
| **Instrumented total** | | **377.7 s** | **100.0%** |

`batch_tighten` was the largest measured high-level stage in this run. It is therefore the clearest next profiling/optimization target. Any proposed change must preserve the rule that tightened bounds cannot directly become exact winners.

### 6.5 Exact-scoring internals

| Exact-scoring operation | Calls | Time |
|---|---:|---:|
| Rule packing and enqueue on CPU | `9,081` | `4.05 s` |
| Rules H2D | `9,081` | `0.14 s` |
| GPU unique-table reset | `9,081` | `2.94 s` |
| Exact kernel on GPU | `9,081` | `62.29 s` |
| Small count D2H readback wait | `9,081` | `64.51 s` |
| Winner slots D2D | `6,866` | `0.04 s` |
| Total exact-batch wall time | `9,081` | `71.21 s` |

The `64.51 s` count-readback wait includes synchronization and is not additive to the `62.29 s` GPU event time. The profile also recorded approximately `0.01 s` for count D2H device events and `0.03 s` for count resets.

## 7. Validation and benchmark interpretation

The implementation is intended to preserve exact CELF results while changing where deduplication occurs and how work is measured. The run profiles above demonstrate the GPU unique path and the resulting transfer behavior for the recorded single-chunk workloads. Multi-chunk and forced-fallback correctness remains important because duplicates may cross chunk boundaries.

The recorded runs do not, by themselves, establish a speedup against a controlled baseline. A valid before/after benchmark must keep the input files, rule set, selection budget, word-chunk size, batch settings, GPU, OpenCL runtime, and driver the same. Compare at least:

- first-winner latency and first-round rescoring/dispatch counts;
- total CELF elapsed time and selected-rule throughput;
- `batch_tighten` and `fresh_resolve_exact_batch` time;
- compact result D2H bytes versus small counter D2H bytes;
- GPU memory used by exact-dedup scratch;
- final selected-rule coverage and exact output ordering.

Do not infer a hardware speedup from `rule/s` alone or compare rolling `rule/s` from one run with cumulative throughput from an older log.
