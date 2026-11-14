# Rule Ranker: CELF profiling toggle placement fix

## What was wrong

The `opt_profile` checkbox was placed between the workflow tab bar and the workflow panels. The previous integration test only asserted that the checkbox existed somewhere in the Ranker workflow area, so it passed without proving that the setting belonged to the **Optimize ruleset** panel.

## Fix

- Move the profiling card into `#ranker-optimize-panel`, directly below its heading.
- Keep the checkbox ID (`opt_profile`) and the `profile` option wiring unchanged, so the existing server-side `RANKER_GREEDY_PROFILE=1` override continues to work.
- Increase the switch hit area and add a visible keyboard-focus outline.
- Change the `styles.css` and `app.js` query-string build identifiers on the main page, forcing browsers and intermediaries to request the updated assets after deployment.
- Tighten the integration test to assert that `opt_profile` is nested inside the Optimize panel and is absent from the shared workflow-tab area.

## Verification

- `node --check web/app.js`: passed.
- HTML structure check: `opt_profile` is inside `#ranker-optimize-panel` and its ID is unique.
- `pytest -q`: 560 passed, 5 skipped.
- The real OpenCL integration test is skipped when no OpenCL runtime is available; no RTX 3060 Ti benchmark was run.

## Deployment

Replace the project files with this archive, restart the RULEOPS server, open **Rule Ranker → Optimize ruleset**, and refresh the browser. The profiling card appears directly below the Optimize panel heading. It is not shown in **Rank rules** or **Analyze CSV**.
