# Per-tool run status metrics

Every RULEOPS tool now presents the same five-card run summary:

- **Engine Status** — idle, running, paused, stopping, completed, stopped or failed.
- **Active Stage** — the latest pipeline phase reported by the active tool.
- **Elapsed Time** — wall-clock time for that tool's current or most recent run.
- **Output Files** — output artifacts owned by that tool's run.
- **ETA** — a live estimate for the active stage, derived from elapsed stage time and reported progress. It is recalculated as progress updates; it is not a guarantee for the complete multi-stage run. The display waits for enough progress to avoid publishing unstable early estimates, and shows paused, finishing, or unavailable states when appropriate.

The server-backed tools (RULEST, Rule Ranker, Concentrator, Rulestripper and Rule Minimizer) consume the existing `/api/status` payload. A card is populated only when `data.tool` matches its tool key; other tool cards remain idle and show zero outputs. Output lists and their counters are scoped the same way so one tool's artifacts are not displayed as another tool's results.

Email Rule Extractor runs fully in the browser, so its five cards are driven by its local file-processing and download lifecycle. Extraction processes input in yielding batches so the UI can report processed lines and calculate a live ETA without freezing the page. Its output-file count changes to one when extraction generates a downloadable `.rule` artifact and resets when the input is cleared or replaced.
