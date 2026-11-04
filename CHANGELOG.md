# Changelog

## [2.4.7] - 2026-11-04

### Added
- Offline licensing with per-module DEMO counters (RULEST, Rule Ranker, Concentrator each get 3 full runs).
- After the third full run of a module, that module automatically enters **DEMO LIMITED** mode.
- Strong CELF restrictions in DEMO LIMITED (no greedy/advanced CELF; tight candidate and budget caps) while basic demonstration remains available.
- Separate administrator and regular user authentication roles. First-time setup creates the administrator.
- Administrator can install a signed `license.lic`, reset DEMO counters, and set/clear the user password.
- Activating a valid PROFESSIONAL or ENTERPRISE license restores full capability on all modules.

### Changed
- Application version set to **2.4.7** across server banner, web UI and VERSION file.
- License status is exposed via `/api/license` and included in `/api/auth/me` and `/api/status`.

### Notes
- DEMO usage is stored in `license_usage.sqlite3` and survives restarts and re-logins.
- Counters are independent per module.
- The private license issuer (`license_admin.py`) remains owner-only and must not be shipped to customers.



## [Unreleased]

### Fixed
- Fixed the web UI tab freezing partway through long-running jobs, most noticeably during CELF rule selection. The ranker's progress bar redraws in place roughly twice per second for the entire duration of a stage; the server used to turn every one of those redraws into a brand-new persisted log entry, and the browser appended one new DOM element per entry and never removed old ones. Over a multi-hour CELF run this grew into tens of thousands of live DOM nodes, which progressively slowed the page down until the tab stopped responding — while the underlying engine process kept running and exited normally, which is why the process appeared to "finish" even though the browser was already frozen.
- The server now throttles bare carriage-return progress redraws to at most one persisted log entry every 2 seconds (real newline-terminated log lines are never throttled, and stage detection still runs on every redraw so the displayed stage stays responsive).
- The web UI now caps the number of rendered log rows in the live terminal (oldest rows are trimmed) and the in-memory log buffer used for the "download log" export, independent of how long a run lasts. The full, untruncated log remains available via the saved `engine.log` run output.

### Verification
- Automated suite: 472 passed, 5 skipped (one requires a physical OpenCL runtime; four exercise a replaced legacy API path) — unchanged.

## [2.4.6] - 2026-11-04

### Security
- Bounded the threaded web server to a configurable maximum number of concurrent connections; excess clients receive HTTP 503 with `Retry-After`.
- Added absolute request-header deadlines and idle timeouts to reduce Slowloris-style connection exhaustion.
- Added upload idle timeouts, sustained minimum-throughput checks, maximum transfer deadlines, strict `Content-Length` validation and rejection of transfer-encoded request bodies.
- Added per-file upload, aggregate temporary-upload and total `runs/` data quotas, free-disk reserve checks, and a storage watchdog that stops active jobs before the configured data quota/reserve is breached.
- Persisted per-IP login throttles in an owner-only SQLite database, with progressive lockouts up to one hour; state now survives server restarts.
- Added a restrictive Content Security Policy and additional cross-origin, permissions and content-type security headers. Moved login inline CSS/JavaScript into same-origin static files and removed Python version disclosure from the Server header.
- Added `security.sqlite3` and its SQLite sidecar files to `.gitignore`.

### Changed
- Added configurable server limits documented in `SECURITY_HARDENING.md` and `README.md`.
- Updated frontend asset cache keys and displayed application version to `2.4.6`.

### Verification
- Automated suite: 472 passed, 5 skipped (one requires a physical OpenCL runtime; four exercise a replaced legacy API path).
- Focused tests cover connection admission, slow headers, upload timeouts/rate/quota enforcement, persistent login throttling and CSP headers.
- No physical GPU benchmark or external network penetration test was performed as part of this web-layer hardening.

## [2.4.5] - 2026-11-04

### Fixed
- Restored the CELF greedy-selection control flow from the supplied earlier RULEST archive after the newer control loop showed significantly longer real-world runtimes.
- Kept the current OpenCL scoring kernel and compact candidate-index worker calls, while restoring the archived seed evaluation, stale-bound refresh and exact challenger rescoring sequence.
- Added a precise initial upper-bound progress bar in the web log: completed candidates, total candidates, percentage, current/average/recent `rules/s`, batch count and ETA.
- Made the upper-bound percentage parseable by the UI phase-progress indicator.
- Added smoothed `selected rules/s` and lazy upper-bound throughput to live CELF monitoring.

### Changed
- Updated application version and frontend cache keys to `2.4.5`.

### Verification
- 460 tests passed; 5 skipped (one requires a real OpenCL runtime, four cover a replaced legacy API path).
- No physical GPU benchmark was available in the build environment; runtime improvement must be confirmed on the target GPU.


## [2.4.4.2] - 2026-11-04

### Changed
- Applied the unified low-contrast monitor typography to the Run storage page.
- Separated the storage page kicker, title and description with consistent spacing and UI sans-serif typography.
- Refined storage summary cards, cleanup panel, warning copy and destructive-action button to match the shared RULEOPS visual language.
- Improved Run storage layout behavior on tablet and mobile widths.
- Updated frontend cache keys and server version to `2.4.4.2`.

## [2.4.4] - 2026-11-04

### Added
- Added a live `LOCAL ENGINE` badge that reflects the actual RULEOPS job lifecycle across RULEST, Rule Ranker and Concentrator (`RUNNING`, `PAUSED`, `STOPPING`, `COMPLETE`, `STOPPED`, `ERROR`, `READY`, and `OFFLINE`).
- Added a global **Run storage** page with directory count, file count and disk-usage summary.
- Added a confirmed global cleanup action for saved run directories across all three tools.

### Fixed
- Prevented run-directory deletion while an engine job is active/stopping or a file upload is in progress.
- Kept `runs/uploads/`, `auth.json`, application files and configuration outside the global run-folder cleanup scope.
- Cleared stale output references after their run directory is deleted.
- Added authenticated and CSRF-protected run-storage APIs.

### Changed
- Updated frontend cache keys and server version to `2.4.4`.

## [2.4.2] - 2026-11-04

### Added
- Added live CELF upper-bound pass logs with candidate progress, current-batch throughput, recent throughput and average `rules/s`.
- Added greedy CELF selection speed (`rules/s`) and average selection throughput to the web heartbeat.

### Fixed
- Fixed `exact_scans` reporting to include candidates evaluated by batched exact GPU scoring, rather than only singleton recording scans.
- Split CELF exact scoring, recording scans and lazy upper-bound refresh counters into separate metrics.

### Changed
- Updated the application version and frontend cache keys to `2.4.2`.

## [2.4.1] - 2026-11-04

### Changed
- Unified the active-job status component across RULEST, Rule Ranker and Concentrator.
- Applied the same separated label/title hierarchy, spacing, muted colors and UI sans-serif typography to every tool monitor.
- Standardized runtime and process metadata labels and values across all three monitors.
- Updated frontend cache keys and server version to `2.4.1`.

## [2.4.0] - 2026-11-04

### Changed
- Refined the RULEST, Rule Ranker and Concentrator sidebar and workflow navigation.
- Kept the Adaptive MAB / Legacy exhaustive controls prominent and connected to the Ranker launch options.
- Reworked monitor panel headings into separated, lower-contrast kicker and title lines for better spacing and readability.
- Updated monitor descriptions to use the application UI typography instead of tightly packed monospace text.
- Bumped frontend asset cache keys to ensure browsers load the updated styles.

### Fixed
- Added explicit project-root Python path configuration so the combined Ranker and RULEOPS test suites collect correctly.

## [2.3.0] - 2026-11-04

### Changed
- Rebranded the unified application as RULEOPS.
- Moved RULEST, Rule Ranker and Concentrator into a persistent three-program sidebar; RULEST has an expandable submenu.
- Promoted the Rule Ranker Adaptive MAB / Legacy exhaustive selector to the top of the Rule Ranker page.
- Added an explicit active-mode indicator and retained the selected ranking mode across page refreshes in the same browser session.
- Kept Legacy selection connected to the Ranker CLI `--legacy` flag; MAB-only tuning is disabled while Legacy is selected.

