# PCFG-profile guided optimization (hashmob.medium)

> This file previously described a planned `--topn-digit-heavy` /
> `FAMILY_BUDGET_DIGIT_HEAVY` toggle that was never actually implemented.
> What shipped instead is the more general, continuous mechanism below
> (`--pcfg-profile` / `profile_informed_priors`), which supersedes that plan.
> See `docs/CHANGELOG.md` for the full history, including the CELF
> cost-profile follow-up this file now also documents.

## Source profile

- File: `reports/hashmob.medium.plain.json` (example)
- Schema: `ruleops.pcfg-profile.v1` (see `run_pcfg_profile.py` / `docs/PCFG_PROFILE.md`)
- Corpus: hashmob.medium.found (~12.9M entries)
- Key composition signals:
  - Length: 8-11 ≈ 62%, 2-7 ≈ 33%, ≥12 ≈ 5%
  - Character-class presence: digits ≈ 77%, lowercase ≈ 85%, uppercase ≈ 15%, symbols ≈ 2.6% (rare)
  - Dominant class combinations: lowercase+digits ≈ 49%, lowercase-only ≈ 21%, digits-only ≈ 14%

## What a profile actually changes today

### 1. Seed-pool composition (`rulest/topn_seedgen.py`)

`--pcfg-profile PATH` (CLI) / `pcfg_profile=...` (`run()`/`generate_seeds()`) /
the Top-N panel's "Add profile JSON" picker in the web UI all feed the same
report through `load_pcfg_profile()` -> `summarize_pcfg_profile()` ->
`profile_informed_priors()`, which nudges all 12 `FAMILY_BUDGET_STANDARD`/
`FAMILY_BUDGET_COMPLEMENTARY` shares toward the corpus's measured
digit/symbol/uppercase prevalence before generation starts (then renormalizes
back to sum to 1.0). Per-run adaptive budgeting still runs on top of this for
the 5 directly-observable families.

**Caveat:** with `--pcfg-max-seeds 0` (unlimited), the attempt budget
auto-scales to match the observed affix inventory and the fixed
`MIN_SUFFIX_COUNT`/`MIN_YEAR_COUNT` thresholds end up being the actual limit
on most families, not these weights -- so on a large corpus this nudge can
end up barely visible in the final pool. Bind `--pcfg-max-seeds` to a finite,
cap-relative size if you want it to have more effect on the pool itself.

### 2. CELF selection ranking (`rulest/selection.py`, `rulest/cli.py`)

Because of the caveat above, the same profile is now also usable where it
has guaranteed effect regardless of `--pcfg-max-seeds`: CELF's own
cost-aware marginal-coverage ranking, which is what actually decides which
rules occupy a small `--select-budget`.

```bash
python run_rulest.py base.txt target.txt -o out.rule \
  --select-cost-profile reports/hashmob.medium.plain.json
```

`build_profile_cost_weights()` turns the same digit/symbol/uppercase shares
into per-character-class cost multipliers (common classes cheaper, rare ones
costlier, clamped to [0.4x, 3x]); `_rule_profile_multiplier()` applies that
to each candidate's literal `$c`/`^c` characters. This composes with
`--select-cost-alpha` (pure chain-depth cost) -- set either, both, or
neither.

## Recommended usage for higher coverage at a given rule-count cap

1. Generate the seed pool with `--pcfg-profile` and a **finite**
   `--pcfg-max-seeds` (a few times your eventual cap, not `0`), so the
   profile actually shapes the candidate pool.
2. Rank/select with CELF (`select_mode=greedy`) and `--select-cost-profile`
   pointed at the same report, so composition also shapes which of those
   candidates make the final cut.
3. If coverage still plateaus across very different cap sizes, that is more
   likely a ceiling of affix-style rules against your base wordlist than a
   tuning problem -- see the "known remaining gap" note in `docs/CHANGELOG.md`.
