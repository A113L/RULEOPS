# Changelog

Notable project changes, grouped by release date. Related implementation and follow-up commits are consolidated into a single entry.

## 2026-11-20

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
