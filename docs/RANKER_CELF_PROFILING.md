# Rule Ranker CELF GPU profiling

The `Enable GPU profiling` toggle is located inside the **Optimize ruleset** workflow panel, directly below that panel heading. It is therefore visible when the Optimize ruleset tab is selected and is not shown in Rank rules or Analyze CSV.

When enabled, RULEOPS starts that Ranker job with `RANKER_GREEDY_PROFILE=1`. The CELF
scorer then emits its detailed stage breakdown and creates its OpenCL command queue with
`PROFILING_ENABLE`, allowing GPU event timings to be collected where supported by the
OpenCL driver. Profiling is opt-in because event instrumentation and extra accounting
can affect runtime. It does not change the scoring algorithm or selection semantics.

The setting applies only to the Optimize ruleset workflow; Rank, Analyze CSV, and RULEST
runs are not affected. When disabled, RULEOPS removes the variable from the child
process environment so a stale server-shell setting cannot silently enable Ranker
profiling.

## First-round difficulty report

With profiling enabled, the Ranker also emits a candidate-landscape report after
`upper_bound_pass` and a first-winner report when the first CELF round commits.
These diagnostics help distinguish a difficult rule pool from scoring overhead:

- `candidate pool`: total candidates, candidates with at least one raw hit, and
  zero-hit candidates.
- `top-1 priority upper bound`: the heap's leading candidate, with its rule index,
  raw upper-bound hit count, and cost-normalized priority. The raw count is a
  pruning bound and may include duplicate outputs; it is not an exact gain.
- `top-10` and `top-100 raw upper-bound distribution`: min, median, mean and max
  raw upper-bound hit counts among the highest raw-bound candidates.
- `first winner`: exact deduplicated gain and rule index for the first committed
  winner, plus the seed candidate index.
- `first-round challenger work`: exact challenger verifications (excluding the
  seed), candidates whose bounds were batch-tightened, seed exact count, total
  rescored candidates, and GPU dispatch count.
- `winner_after_celf`: elapsed time from the start of CELF selection to committing
  the first winner. `upper_bound_plus_first_winner` adds the measured upper-bound
  pass duration, so the two major phases can be compared directly.

The top-10/top-100 distributions are deliberately labelled *raw upper bounds*:
the scoring kernel counts `(word, rule)` hits before per-rule deduplication. Only
`exact_gain` is a deduplicated marginal coverage value that may decide the winner.
The extra distribution pass is performed only when `RANKER_GREEDY_PROFILE=1`.
