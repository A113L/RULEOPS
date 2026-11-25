# Changelog

## [Unreleased] — Independent Persistent Run Archive scrollbars

- Added a separate, keyboard-accessible scroll region to each tool category in **PERSISTENT RUN ARCHIVE**, keeping long histories from scrolling the other tools.
- Added category-specific scrollbar colors for RULEST, Rule Ranker, Concentrator, Rulestripper, Rule Minimizer and Aether, with compact viewport-aware heights and updated frontend cache keys.

## [Unreleased] — RULEST expanded output format

- Added a RULEST output-format selector for compact Hashcat lines or Concentrator-style expanded operator spacing, available in both CLI and Control Center UI.
- Unified Hashcat operator tokenization between RULEST and Concentrator and included RULEST's `v`/`B` extended operators so expanded output does not silently omit them.

## [Unreleased] — Explicit RULEST CELF seed logging

- Added startup log messages that always state whether optional CELF seed injection is disabled, enabled, or configured for Stage S only. Enabled imports now report source files, accepted rules, scanned lines, validation rejects, duplicates, depth rejects and limit status, including when zero rules are accepted.
- Added a post-merge summary showing how many external rules were added, how many already existed in extraction, and the final CELF candidate-pool size. Early cancellation before CELF selection is now reported explicitly.

## [Unreleased] — English user guide for all RULEOPS tools

- Added the complete English CLI + UI guide covering all Control Center tools, standalone CLI utilities, common run/storage workflows, example pipelines and troubleshooting.
- Replaced the earlier Polish-language guide and updated the project README, documentation index and project website links.

## [Unreleased] — Documentation structure and consolidation

- Reorganized `docs/` into user guides, engineering references and operations documentation, with a central index and updated project-site links.
- Consolidated overlapping CELF, profiling and fix notes into canonical RULEST / Rule Ranker references; removed redundant standalone notes and the duplicated commit digest.
- Corrected stale documentation about wordlist duplicate preservation, Rule Ranker GPU CELF scoring and installation commands.

> [← Documentation index](README.md)


## [Unreleased] — Curated RULEST CELF seed candidates

- Added `--celf-seed-rules` / `--celf-seed-max-rules` to import validated, deduplicated rules from one or more curated files into RULEST's CELF candidate pool. Imported rules receive the normal exact marginal-coverage scoring; they are not preselected. The default cap is 1,000, but there is no fixed upper bound: any positive integer is accepted. Added an opt-in web UI toggle that reuses the uploaded Custom seed rules file for CELF, with upload and saved-library selectors directly in Rule selection.
- Added loader regression tests for validation, depth filtering, duplicate handling, candidate caps, imports above 1,000 rules and missing input files.

## [Unreleased] — Aether report export and validation improvements

- Added a configurable rule count to interactive Aether HTML report downloads. Users can choose how many of the fastest rules to export directly from the report; the export is independent of the optimization setting. Commit: [56c8ac5](https://github.com/A113L/RULEOPS/commit/56c8ac5e6679f707d0ae9c345f3d6a60a0eb9d77).
- Deferred full rule validation until optimized-rule generation. Uploading or selecting a reusable rule file no longer runs the expensive full validation path, avoiding unnecessary delays and upload timeouts. Commits: [aec1a23](https://github.com/A113L/RULEOPS/commit/aec1a2335abe069451a9776b0af51990f31a94b6), [b117348](https://github.com/A113L/RULEOPS/commit/b11734898534fe0276f27aa44a72bd93d1f8dae7).
- Reworked Aether opcode heatmap to benchmark individual one-command rules on the GPU and subtract the no-op baseline; results are grouped by operator and saved to a separate JSON report. Up to four argument variants per operator are sampled to keep profiling bounded.

## [Unreleased] — Aether Hashcat 8 rule-chain support

- Replaced Aether's one-operation-only kernel dispatch with a sequential OpenCL rule interpreter, allowing supported multi-command Hashcat `-r` lines to execute as complete chains.
- Enabled Aether benchmarking for Hashcat 8.0 `h`, `H`, `S`, `vNX`, and `BNX` operators, including their use inside supported rule chains.
- Expanded the packed rule buffer to 256 bytes so up to 31 three-byte operations are not silently truncated.
- Aligned CLI and directory discovery with the web uploader: `.rule`, `.rules`, `.hr`, `.hashcat`, and `.txt` files are now accepted case-insensitively.
- Updated Aether preflight validation and UI copy to distinguish malformed rules, CLI-only rules, and valid commands not yet implemented by the Aether interpreter.
- Kept unsupported commands out of benchmark results rather than timing them as identity/no-op transformations.

## 2026-11-25 — RULEOPS storage quota

- Increased the default aggregate RULEOPS data-storage quota from 10 GiB to 50 GiB. The `RULEOPS_MAX_DATA_STORAGE_BYTES` environment variable can still override the default.

## 2026-11-25 — Absolute file paths in persistent Run storage

- Persistent run history now records the absolute server-side path for each selected input, separately from its display filename and dataset fingerprint.
- Run-history artifact details display absolute paths while retaining relative artifact identifiers for safe preview and download routes.
- Older run manifests remain readable; when they do not contain a recorded input path, the UI clearly marks that path as unavailable.

## 2026-11-25 — Rulestripper: Hashcat 8 extraction modes

- Added reverse extraction for `h` and `H` by decoding lowercase and uppercase hexadecimal output back into BASE candidates.
- Added reverse extraction for `S` using the same byte-level keyboard mapping as Hashcat (the mapping is self-inverse).
- Added reverse extraction for `vNX`, including the terminal inserted byte when the source length is divisible by `N`; `N` supports Hashcat base-36 values 1–35.
- Kept extraction bounded to direct, single-operator matches and verified every candidate by reapplying the generated rule.

## v2.6.5 — Hashcat 8 rule operators across CPU and GPU engines

- Added byte-exact support for Hashcat 8 operators `h` (lowercase hexadecimal),
  `H` (uppercase hexadecimal), `S` (keyboard Shift Case), `vNX` (insert a byte
  after every N input bytes, including a terminal insertion when divisible),
  and `BNX` (add the operand byte modulo 256 at base-36 position N).
- Centralized the byte-level Python semantics in `hashcat_rule_ops.py` and
  aligned RULEST, Rulestripper, Concentrator and Rule Minimizer interpreters.
- Extended the RULEST OpenCL rule-chain kernel and atomic rule generator, both
  Rule Ranker OpenCL kernels, and the Aether OpenCL benchmark kernel.
- Updated Rule Ranker validation so valid `vNX` rules are no longer discarded
  and the five new operators pass the legacy Ranker and current CELF paths.
- Completed Aether preflight validation for the new operators. It benchmarks
  supported single-operation rules and continues to report malformed, CLI-only
  and valid-but-not-benchmarkable rules separately with source line numbers.
- Added CPU semantic, validator, generator and kernel-source regression tests.

## v2.6.5 — Aether Hashcat rule validation and benchmark safety

- Added a Hashcat 8 rule-file preflight validator before Aether GPU timing. It
  reports malformed rules, `-j/-k`-only commands and valid Hashcat commands
  that the current Aether kernel does not implement as separate categories.
- Aether benchmarks only the explicitly supported single-operation subset;
  valid chained rules are reported as unsupported by the current kernel rather
  than receiving misleading timings.
- The Aether upload UI and reusable-library selection show validation counts;
  line-numbered JSON and text reports are saved with each benchmark output.
- Preserved literal `#` and whitespace operands instead of truncating rule
  commands as inline comments, and corrected Hashcat `E` title-case behavior.
- Fixed `_sorted.rule` output so performance metadata is written as standalone
  comment lines and never appended to executable Hashcat rule commands.

## v2.6.5 — Aether run-history unification

- Removed Aether's separate persistent history panel and dedicated history API; previous Aether benchmarks now appear in the shared **Run storage** page alongside every other tool.
- New Aether runs write the common run-history manifest, including per-input output stems and rule counts, so multi-file benchmarks remain grouped by their original rule filenames.
- Migrated existing `.aether-run.json` folders into the unified Run storage view without rewriting or discarding their saved results.
- Unified preview, artifact downloads, whole-run ZIP downloads and run-folder deletion through the shared Run storage endpoints. Aether artifact details are filtered to the selected rule file, while ZIP and deletion actions clearly apply to the complete multi-input run folder.
- Kept the live Aether benchmark gallery for the current run; only persistent history moved to Run storage.


## 2026-11-24 — Persistent run history for the other tools (v2.6.5 follow-up)

- Added a persistent archive to the Run storage page for RULEST, Rule Ranker,
  Concentrator, Rulestripper and Rule Minimizer. Aether remains in its dedicated
  gallery and is intentionally excluded from this shared history.
- Grouped saved runs first by tool and then by the relevant rule filename or
  primary input: RULEST seed rules (or built-in/generated seeds plus TARGET),
  Ranker source rules/CSV, each Concentrator input ruleset, Rulestripper TARGET
  wordlist, and Minimizer input ruleset.
- Added per-run detail pages with safely previewable artifacts, individual
  downloads, status and storage metadata, plus a guarded action to delete one
  complete run folder.
- Added a one-click ZIP download for all artifacts in a selected run; the
  action is enabled only after that run has finished and has saved outputs.
- Added a small run-history manifest alongside the existing dataset fingerprint
  manifest. It records display names and lifecycle status without duplicating
  generated artifacts; older runs continue to use the existing manifest or
  saved command-log inference where available.
- Kept global run-storage cleanup and Aether history behavior separate. Shared
  history preview/download and delete routes enforce authenticated/CSRF access,
  direct `runs/` child validation, regular-file checks, symlink rejection and
  active-job storage locks.
- The Aether separation described above was superseded by the later v2.6.5
  run-history unification entry at the top of this changelog.

## 2026-11-24 — Persistent Aether benchmark gallery (v2.6.5 follow-up)

- Added a persistent Aether run archive backed by the existing `runs/` storage
  folders. Previous benchmark sessions remain available after page reloads and
  application restarts, with each uploaded rule filename shown as a direct link
  to that file's saved charts, interactive report and downloadable artifacts.
- Added a per-run folder deletion action with server-side run identity checks,
  symlink-safe file access, CSRF protection and safeguards against deleting
  storage while a job or upload is active.
- Kept the all-artifacts ZIP download in the existing Aether output-files panel
  on the right and corrected the gallery note so it no longer says the ZIP is
  below the gallery.
- Confirmed the completion chime is wired to successful job completion: the
  Aether launch response registers its job ID, status polling detects the
  matching completed state, and the browser plays the enabled Web Audio chime
  after user interaction unlocks audio. Failed or cancelled runs stay silent.

## 2026-11-24 — Fix Aether interactive report styling (v2.6.5 follow-up)

- Fixed the Aether HTML preview response to send one report-specific Content
  Security Policy instead of combining it with the global application policy.
  Browsers enforce multiple CSP headers cumulatively; the previous combination
  blocked the report's embedded CSS and JavaScript, leaving it unstyled and
  non-interactive. The preview remains sandboxed, script-limited to inline code,
  and has no network access.

## 2026-11-24 — Aether interactive performance reports (v2.6.5 follow-up)

- Added a self-contained interactive HTML report for every visualized Aether
  rule file alongside the existing PNG dashboard. The relative performance
  pie can be selected by tier to inspect the exact Hashcat rule commands,
  GPU Kernel Time, GPU throughput, End-to-End Time and coefficient of variation.
- Added per-tier search, pagination and export of the complete selected tier
  as a standalone `.rule` file. Tier thresholds use the same tie-preserving
  relative grouping as the statistical PNG chart.
- Updated the Aether UI gallery and artifact list to surface interactive HTML
  reports next to the PNG previews, and added a restricted inline-preview route
  for current-run Aether HTML artifacts with a sandboxed Content Security Policy.

## 2026-11-24 — Aether benchmark timing accuracy (v2.6.5 follow-up)

- Fixed the Top 10 chart to show the complete Hashcat rule-file command for
  each result without rank prefixes. Removed 15-character truncation and
  disabled MathText parsing so special rule characters such as `$`, `^` and
  backslashes are displayed literally. The chart title and note now clarify
  that `.rule` files contain commands rather than descriptive rule names.

- Switched Aether's primary timing metric to OpenCL event profiling: each
  rule's GPU Kernel Time is derived from device-side event START/END timestamps,
  with warm-up launches excluded from the sample. The benchmark now requires an
  OpenCL GPU and no longer silently reports CPU-device timings as GPU results.
- Added a separate End-to-End Time diagnostic covering the host enqueue loop
  and queue completion wait. JSON reports and sorted-rule files record both
  metrics; ranking, throughput and the optimization time budget use GPU Kernel
  Time. Corrected throughput to count one word-rule application per kernel
  launch rather than multiplying by the number of benchmark iterations twice.
- Made `cl.command_queue_properties.PROFILING_ENABLE` unconditional for Aether's
  OpenCL command queue. The UI now shows an always-on profiling status and
  explains the distinction between GPU Kernel Time and End-to-End Time; JSON
  metadata records that event profiling was enabled.

- Unified Aether's dictionary-mode workload: both modes now submit exactly
  the configured `Max words` count per rule. Identical mode repeats the same
  16-word seed dictionary; diverse mode generates deterministic content
  variants while preserving the same per-position character classes and
  word-length profile. This removes the previous 16-versus-`Max words`
  workload mismatch.
- Updated the Aether UI with an explicit words-per-rule explanation, a live
  corpus-mode summary, and a clear statement that the two modes use equal
  GPU work-item counts. JSON reports, sorted-rule headers and statistical
  dashboard titles now record the corpus mode and word count.

## 2026-11-23 — RULEOPS v2.6.5

### Aether integration

- Integrated Aether as the seventh tool in the authenticated RULEOPS web
  interface, including rule-file uploads, benchmark controls, live stage and
  run monitoring, per-file dashboard gallery, output downloads and run-history
  handling.
- Added GPU/OpenCL rule-throughput benchmarking, optional fastest-first rule
  optimization, and per-file performance dashboards to the unified workflow.
- Added Aether-specific navigation and active-stage reporting so its progress
  is displayed independently from Concentrator and RULEST.
- Exposed the cumulative optimization budget in microseconds in the web UI and
  convert it to seconds at the Aether CLI boundary, preserving the engine
  interface and report units.
- Updated the About page, project tool count and visible version metadata to
  reflect the seven-tool release.
- Aether reports, sorted-rule files and dashboard images now use the original
  uploaded rule-file names; internal upload IDs are no longer exposed in
  downloadable artifact filenames. Duplicate basenames receive a short
  numeric suffix to keep every output distinct.
- Updated `docs/index.html` to feature Aether and describe the complete set of
  seven integrated tools.
- Balanced Aether's performance categories using tie-preserving relative
  tiers per rule file instead of fixed 10/100 µs cut-offs; the fastest-rules
  chart now shows the delta from the fastest result and places the fastest rule
  at the top.

## 2026-11-21

### Optional functional minimization in RULEST

- Added `--no-minimize` to skip the signature-based functional-equivalence
  pruning stage while retaining the extracted rule candidates.
- Added a positive `Functional rule minimization` toggle to the RULEST engine
  configuration UI. It is enabled by default, preserving the previous pipeline
  behaviour; the setting is passed through the web API to the CLI.
- Run output headers now record when minimization was skipped, and the stage
  profiler reports the user-selected skip state.

### UI: expose `--select-cost-profile` on the Rule selection panel

- Added an optional CELF cost-profile picker (upload JSON or choose a saved
  `reports/*.json` pcfg-profile) next to Cost alpha / Selection budget.
- The selected profile is passed through to `run_rulest.py` as
  `--select-cost-profile`, composing with `--select-cost-alpha` the same way
  the CLI does. Only meaningful when Selection mode is Greedy.
- Reuses the existing `/api/tools/pcfg-profiles` list/load endpoints; no new
  backend storage was required.


## 2026-11-20

### CELF cost-aware selection informed by aggregate corpus profiles

Why: on `--pcfg-max-seeds 0` (unlimited) runs, PCFG-Lite's family-budget
weighting -- adaptive or `--pcfg-profile`-informed -- almost never actually
binds: `generate_seeds()` auto-scales its attempt budget up to match the
observed affix inventory, and the fixed `MIN_SUFFIX_COUNT`/`MIN_YEAR_COUNT`
frequency thresholds, not the family weights, end up being what limits each
family's candidate count on a multi-million-row corpus. The result is a huge
candidate pool whose composition barely differs between configurations, and
downstream CELF then picks the final rule set purely from real per-rule
marginal coverage -- so seed-side tuning has no visible effect on the final
coverage curve at any `--select-budget`, matching observed runs where
coverage differed by ~0.01-0.3 percentage points across cuts from 75k to
220k+ rules of otherwise very differently-generated pools.

Since CELF's own ranking is what actually decides which rules occupy a
small cap, that is also the only place composition-profile information can
still move the needle on a smaller rule set:

- Added `build_profile_cost_weights()` / `_rule_profile_multiplier()` to
  `rulest/selection.py`: given a pcfg-profile summary, each candidate's
  CELF cost is now additionally multiplied by how over/under-represented its
  literal `$c`/`^c` digit/letter/symbol characters are in the corpus (cheap
  for common classes, costlier for rare ones, clamped to [0.4x, 3x]).
  Structural rules with no literal-char tokens (`c`, `u`, `t`, `l`, `:`, ...)
  are unaffected. This changes the actual *ranking order* CELF uses, not
  just which seeds exist in the pool, so it is visible at any cap size.
- `select_rules_by_marginal_coverage(..., cost_profile=...)` accepts a raw
  `ruleops.pcfg-profile.v1` report (dict/path/JSON text) or an
  already-summarized one; `--select-cost-profile PATH` wires it into
  `rulest/cli.py`'s CELF stage. Composes with `--select-cost-alpha` (chain
  depth) -- either or both may be set.
- The existing `cost_alpha<=0` fast path (`_ConstantCosts`, no per-rule
  Python loop) is preserved exactly when no cost profile is supplied, so
  default behaviour and performance are unchanged; the per-rule cost loop
  only runs when a profile is actually given.
- Practical recommendation for anyone chasing bigger differentiation at
  small `--select-budget` sizes: binding `--pcfg-max-seeds` to a few times
  your eventual cap (instead of 0/unlimited) re-enables the seed-side family
  budgets as a real pre-filter, which is cheap and speeds up CELF, but the
  coverage ceiling itself (consistently ~40% across very different rule
  sets against the same base/target in observed runs) looks like a property
  of affix-style rules against that base wordlist, not of any one tool's
  ranking -- raising it further needs structural coverage PCFG-Lite doesn't
  model yet (see the known-gap note in the PCFG-profile entry below), not
  more of the same affix families.

### CELF shared-memory target-table construction

- Changed `_GpuExactScorer` and CELF initialization to retain the original `SharedWordList` instead of converting it into a Python `list[str]`.
- Added a CELF-specific packed view that exposes the existing SharedMemory byte payload and `uint64` record offsets directly. Per-record `int32` lengths are derived without decoding or re-encoding target strings.
- Reworked target fingerprinting and open-addressing insertion into bounded batches. The builder no longer creates corpus-sized `valid_ids` or fingerprint arrays, and fills the target-ID-to-slot map as entries are inserted.
- Removed the table-sized `placed` boolean mask and `flatnonzero()` slot-index array. The immutable occupied bitmap is also reused for host-side active-target resets instead of copied again.
- Released the temporary host fingerprint table immediately after its OpenCL buffer is created. Target order, duplicate entries, target IDs, and the existing CELF matching rules are preserved.

### Top-N budget scaling for unlimited runs

- Removed the small fixed attempt-budget ceiling used by unlimited Top-N generation. The initial budget now starts higher and can grow according to the affix inventory observed during the scan, up to a bounded maximum.
- Scaled internal candidate-pool limits with each family budget instead of relying on small fixed slices, preventing large inputs from being constrained by the previous hard-coded pool sizes.

Commit: [ddfaf08](https://github.com/A113L/RULEOPS/commit/ddfaf08a80e024bcbc0fd30167586d5642cbc85a)

### Expanded PCFG-Lite pattern families

- Added dedicated families for case-only transformations, title-style variants with digit or year suffixes, length adjustment, digit insertion/overwrite, date-shaped patterns, and month/season tokens.
- Assigned the new families separate standard and complementary budget shares, then rebalanced those shares to retain capacity for the established affix and combination families.
- Extended aggregate-profile calibration to use class-combination and length-bucket statistics for relevant case, title, digit, date, and length-adjustment families.
- Added saved-profile discovery and loading in the Top-N UI, while retaining JSON upload; the selected profile can be passed through the CLI/API path to the generator.

Commits: [455629f](https://github.com/A113L/RULEOPS/commit/455629f5a4402f1586b3e65b1c70efc6d5c5a9c5), [fe94a70](https://github.com/A113L/RULEOPS/commit/fe94a70cc055306b772b8534c1b5d7d71d88d732)

### Profile-informed Top-N / PCFG-Lite budget priors

- Added `load_pcfg_profile()` and `summarize_pcfg_profile()` to `rulest.topn_seedgen` to read `ruleops.pcfg-profile.v1` reports and extract aggregate character-class shares for budget calibration. The attached profile is used only as aggregate metadata; it is not treated as a wordlist and contributes no raw passwords, affixes, or candidate values.
- Added `profile_informed_priors()` for both standard and complementary modes. It adjusts the existing priors for rule families associated with digits, special characters, and case transformations, applies bounded multipliers, and renormalizes the weights so their total remains unchanged. Families without a corresponding profile signal keep their configured prior.
- Profile-based priors are applied before the existing per-run adaptive pass. When adaptive budgeting is enabled, the five directly observable prefix, suffix, and year families are then rebalanced using frequency evidence from the current Top-N sample. `--no-adaptive-budget` disables this second pass; combo families without direct scan evidence continue to use their configured, profile-informed priors.
- Added `--pcfg-profile PATH` to the CLI and an optional `pcfg_profile` JSON field to `/api/tools/topn-seeds`. The Top-N panel reads and parses the selected JSON in the browser, then sends the aggregate object to the endpoint without requiring a separate server-side upload. CLI and API results report the digit, symbol, and uppercase shares used for calibration.
- The saved plain profile for `hashmob.medium.found` contains about 12.9 million entries, with digit presence at 77.2%, symbol presence at 2.6%, and uppercase presence at 14.6%. These corpus measurements move the relevant priors away from generic defaults while preserving the overall budget total.
- Scope limitation: this change recalibrates existing rule-family priors; it does not expand the structures represented by PCFG-Lite. For example, the same Medium profile classifies about 14.1% of entries as digits-only, a structure not represented by the current prefix/suffix-oriented families and therefore outside this calibration step.

Commit: [7a95559](https://github.com/A113L/RULEOPS/commit/7a95559fc4705f7662da6ff10498c78569987b83)

### PCFG frequency-weight diagnostics and safe large-count handling

- Added streamed weight diagnostics: minimum/maximum/mean, approximate median/p95/p99 ranges, logarithmic weight buckets, and top-1/top-10/top-100 concentration.
- Added explicit detection of totals and individual weights that exceed signed `int64` and JavaScript safe-integer limits. Aggregation and ratio calculations use Python arbitrary-precision integers and decimal division to avoid fixed-width overflow.
- Added `--input-format auto|plain|count-value` so numeric prefixes are not silently interpreted as frequency counts when the input is a plain wordlist; strict frequency mode accounts for malformed rows.
- Extended consistency checks, CLI warnings, documentation, and regression tests. Existing CHANGELOG history is retained.


### PCFG profile quality and comparison metrics

- Added weighted and unweighted length and character-class distributions so frequency-weighted observations can be distinguished from source-entry counts.
- Added input acceptance coverage, class-combination diversity metrics, weighted-versus-unweighted deltas, and automatic profile consistency checks.
- Added `--compare` to compare a new aggregate profile with a previously saved profile, including distribution changes in percentage points and diversity deltas.
- Expanded the PCFG profile documentation and tests. Existing changelog entries are retained.

### Aggregate PCFG corpus profiling

- Added a standalone PCFG corpus profiler that reports weighted length and broad character-class distributions, plus simple length-policy indicators.
- Supports plain and frequency-formatted wordlists; repeated plain lines remain separate observations and frequency rows use their leading count as weight.
- The report contains aggregate metrics only and does not emit raw values, affixes, password candidates, or Hashcat rules.
- Added CLI entry point `run_pcfg_profile.py`, report documentation, and focused tests.

- Follow-up: removed dictionary deduplication from `load_wordlist()` as well. Every valid input entry is now retained in its original order, including duplicates. The optional Stage 0 membership hash index remains a separate lookup accelerator and does not alter the loaded wordlist.
  Commit: [e2d80a3](https://github.com/A113L/RULEOPS/commit/e2d80a3b70d93a8ddf58de8f9af44739a7fe080b)

- Removed the redundant target-wordlist deduplication pass from the initial CELF phase. Most source dictionaries are already deduplicated upstream, so sorting and compacting them again added startup time without providing value. A later loader change also stopped filtering repeated entries, preserving the source wordlist exactly.
  Commit: [fd95de0](https://github.com/A113L/RULEOPS/commit/fd95de0fd81c5ab199c276d635b52bac44aacfdc)

### Top-N / PCFG-Lite seed generation

- Added lightweight pattern profiling over the first *N* entries of the TARGET wordlist to derive seed rules from observed digit, special-character, prefix, suffix, and year patterns.
- Added adaptive family budgets that blend observed TARGET frequencies with static family priors; adaptive budgeting can be disabled.
- Added complementary mode to favor patterns that Stage 0 is less likely to produce.
- Extended numeric prefix/suffix analysis from 4 to 8 digits, with a higher minimum frequency for longer affixes and a reserved share of the budget for them.
- Integrated Top-N generation into the web UI and CLI. Generated seeds can be registered as the active seed upload for a subsequent RULEST run.
- Fixed `0 = unlimited` handling for the Top-N input and seed limits, and added Top-N to the GUI active-stage display.

Commits: [57dec98](https://github.com/A113L/RULEOPS/commit/57dec983411e59386fdf52186a48c66e48a6d6eb), [94e00a1](https://github.com/A113L/RULEOPS/commit/94e00a1303b543602500c08cc2e0fdd5a926683a), [e12d285](https://github.com/A113L/RULEOPS/commit/e12d2854220076c8568dbc83fa03cfc7b72acd4c)

### Parallel Top-N affix scanning

- Added multiprocessing for the CPU-bound affix scan.
- Uses all detected logical CPU cores by default for inputs of at least 50,000 passwords; smaller inputs retain the single-process path to avoid multiprocessing overhead.
- Added a worker-count parameter for callers that need to control parallelism.

Commit: [2c4dbb2](https://github.com/A113L/RULEOPS/commit/2c4dbb22fc5b7d7560ab35200e4557633f53b423)

### Stage S seed-family expansion

- Expanded the built-in seed families from A–M to A–Q.
- Added **N** for combined prefixes and suffixes, **O** for internal character/digit insertions, **P** for extended numeric patterns, and **Q** for date-plus-special-character combinations.
- Added additional combinations involving transformations, dates, and special characters at higher rule depths.

Commit: [fb9f587](https://github.com/A113L/RULEOPS/commit/fb9f587f2a03d986d698b1b96ce8eeab38fea84b)

### CELF memory cleanup

- Explicitly released large temporary rule-pool and deduplication structures once CELF inputs had been prepared.
- Added garbage-collection points before the long-running selection/output phases to reduce retained memory overhead.

Commit: [4c8d042](https://github.com/A113L/RULEOPS/commit/4c8d04243c3a28bbce4f9d25e6c09ba3f5408bde)

### Project website

- Added the public RULEOPS project website and SVG favicon.
- Updated the website content and layout, and linked the site from the README.

Commits: [8c91610](https://github.com/A113L/RULEOPS/commit/8c9161081f1297805bac25228306489ceb169e97), [3fac18f](https://github.com/A113L/RULEOPS/commit/3fac18f006615f90c132da52d72804fc4041033c), [9c44cfa](https://github.com/A113L/RULEOPS/commit/9c44cfa0e304e75aeff1a10e0d190fcdf06defee), [598c439](https://github.com/A113L/RULEOPS/commit/598c439e4c6fc2cbf82f2c6bf4dc2664de44da36)

## 2026-11-19

### Unified pause, resume, and early-quit controls

- Unified `p` (pause), `r` (resume), and `q` (early quit) handling across RULEST pipeline stages and worker processes.
- Started the run-wide controller before wordlist loading so long input-loading operations can also be interrupted.
- Added safe partial-result handling and skipped later expensive stages when an early quit makes them unnecessary.
- Extended the web control endpoint to accept `early_quit` and `quit` aliases.

Commit: [686c69c](https://github.com/A113L/RULEOPS/commit/686c69c1dd8542141d8f736224a44b59d176264a)

### Rule minimizer memory optimization

- Reworked the standalone and integrated minimizers to use compact NumPy records, fixed-width signatures, and source indexes.
- Processed candidates in batches and refined signature collisions progressively.
- Replaced the previous SQLite-backed large-input path with offset-indexed in-memory processing.
- Added and updated minimizer tests.

Commit: [19d10f4](https://github.com/A113L/RULEOPS/commit/19d10f41dcd1defca76bad2b4f112f7042289356)

### Runtime directory initialization

- Added a shared initializer that recreates the `runs/` and `uploads/` directories, including missing parent directories, when the application starts.
- Added tests for missing runtime directories.

Commit: [eddc2f3](https://github.com/A113L/RULEOPS/commit/eddc2f37fc28c4c612de3e814099a37330be1d46)

### Admin password reset instructions

- Documented a command-line procedure for resetting the local admin password.
- The procedure prompts for the new password without echoing it and enforces a minimum length of 12 characters.

Commit: [3d4c360](https://github.com/A113L/RULEOPS/commit/3d4c360c7ab1523212767e723be1a457ca61ada9)
