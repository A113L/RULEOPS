# Changelog

## 2026-11-20

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
