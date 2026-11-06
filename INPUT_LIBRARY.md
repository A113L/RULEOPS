# Reusable input library

RULEOPS now retains uploaded wordlists and Hashcat rule files for reuse between jobs and across server restarts.

## Storage layout

- `runs/library/wordlists/` — BASE, TARGET, Rule Ranker wordlists and cracked-password lists.
- `runs/library/rules/` — RULEST seed files, Rule Ranker candidate/source rulesets and Concentrator rule collections.
- Workflow-specific CSV files remain temporary in `runs/uploads/` and are removed after the job.

Each reusable file is stored under a generated opaque ID plus its sanitized original filename. The upload is first streamed into `runs/uploads/` and then moved atomically into its library folder on the same filesystem. This avoids a second full-size copy for large dictionaries. The library is included in the overall RULEOPS data-storage quota.

## Reusing inputs

After an upload, use the corresponding **Or reuse saved wordlist/rule file** dropdown in the UI. BASE and TARGET have separate selectors but share the wordlist library. The rule selectors share the rules library. Concentrator can add multiple saved rules files and ignores duplicate selections.

Selections are mounted into the same input slots used by freshly uploaded files, so the existing workflows and command-line arguments do not change. Reusable assets are not removed when a job ends, when the server restarts, or when **Delete all run folders** is used. That cleanup only removes generated run directories.

## Completion sound

The top-bar **Completion sound** checkbox enables a short three-note browser sound after a job launched in the current tab finishes successfully. The setting is stored in that browser's local storage. Failed or manually stopped jobs do not play the success sound. Audio is initialized after the first user interaction to comply with browser autoplay restrictions.
