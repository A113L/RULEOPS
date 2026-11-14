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
