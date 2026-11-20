# PCFG-profile guided optimization (hashmob.medium) — integrated into UI + CLI

## Source profile
- File: `pcfg_hashmob_medium.json` / `hashmob.medium.plain.json`
- Schema: ruleops.pcfg-profile.v1
- Corpus: hashmob.medium.found (~12.9 M entries)
- Key composition signals:
  - Length: 8-11 ≈ 62 %, 2-7 ≈ 33 %, ≥12 ≈ 5 %
  - Class combos (weighted):
    - lowercase+digits ≈ 49.2 %
    - lowercase only ≈ 20.6 %
    - digits only ≈ 14.1 %
    - lowercase+uppercase+digits ≈ 11.2 %
    - symbols presence ≈ 2.6 % (rare)

## Integrated changes (no extra standalone command required)

### Web UI (RULEOPS)
In the **Top-N Seed Injection** panel:
- New toggle: **Digit-heavy (PCFG profile)**
- Mutually exclusive with **Complementary mode**
- When enabled together with **Enable Top-N seeds**, the in-run injection uses the digit-heavy family budget prior
- The same toggle is passed to the standalone Top-N generator button (`/api/tools/topn-seeds`)

### CLI (pipeline preserved)
New flag (works with existing stages 0–3, selection, etc.):

```
--topn-digit-heavy
```

Example (full pipeline unchanged):

```bash
python run_rulest.py base.txt target.txt -o out.rule \
  --topn-seeds --topn-digit-heavy --topn-n 400000 --topn-max-seeds 15000
```

Also available on the helper:

```bash
python run_topn_seedgen.py target.txt -o seeds.rule --digit-heavy
```

Mutual exclusion with `--topn-complementary` is enforced in CLI, UI and API.

### Family budget prior
`FAMILY_BUDGET_DIGIT_HEAVY` in `rulest/topn_seedgen.py`:
- ↑ suffix_digit, year, depth2_transform, leet_basic, leet_year
- ↓ pure special-char budgets

### Static rule set (optional)
`reports/hashmob_optimized.rule` — ordered for early marginal coverage on this composition shape. Can be uploaded as custom seed rules in the UI or passed via `--seed-rules`.

## Recommended usage for higher coverage
1. In the UI: enable **Top-N seeds** + **Digit-heavy (PCFG profile)** (+ Adaptive budgets on).
2. Or CLI: `--topn-seeds --topn-digit-heavy`.
3. Prefer CELF / marginal selection when ranking the final rule list.
