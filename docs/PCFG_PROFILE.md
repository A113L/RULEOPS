# PCFG Corpus Profile

RULEOPS includes an aggregate-only profiler for inspecting the composition of a
wordlist before an authorized password-security assessment. It reports length
buckets, character-class presence, broad class combinations, and simple length
policy indicators. It does not produce PCFG productions, password candidates,
affix values, or Hashcat rules.

## Usage

Run from the repository root:

```bash
python run_pcfg_profile.py TARGET.txt --output reports/target-profile.json
```

Compare the current input with a previously generated aggregate profile:

```bash
python run_pcfg_profile.py MEDIUM.txt \
  --compare reports/small-profile.json \
  --output reports/medium-profile.json
```

The output contains the new profile and a `comparison` section with weighted
and unweighted percentage-point changes relative to the reference profile.

Input format can be selected explicitly. The default `auto` preserves the earlier
behavior: any line beginning with decimal digits followed by spaces or a tab is
interpreted as `COUNT VALUE`. Use `plain` when the entire line is a value, even
when it begins with digits and whitespace. Use `count-value` when every non-empty
line is expected to have a numeric count prefix; malformed lines are then counted
and excluded instead of silently treated as plain values.

```bash
# Treat every input line as a value; never parse a numeric prefix as a count.
python run_pcfg_profile.py TARGET.txt --input-format plain --output reports/target-profile.json

# Require the COUNT VALUE format on every non-empty line.
python run_pcfg_profile.py COUNTS.txt --input-format count-value --output reports/count-profile.json
```

For a UTF-8 input:

```bash
python run_pcfg_profile.py TARGET.txt --encoding utf-8 --output reports/target-profile.json
```

The input may be a plain wordlist or a frequency-formatted file whose lines are
`COUNT<space-or-tab>VALUE`. Plain duplicate lines are counted independently;
frequency-formatted records contribute their leading count as observation
weight. Empty lines and values outside the supported 2–64 character range are
reported as skipped.

## Report fields

- `input`: physical lines, accepted entries, weighted observations, and skipped
  line counts.
- `length`: minimum, maximum, weighted and unweighted means, and both weighted
  and unweighted fixed-bucket histograms.
- `composition`: weighted and unweighted presence counts for lowercase,
  uppercase, ASCII digits, symbols, and non-ASCII characters, plus broad class
  combinations and single-/multi-class totals.
- `input_coverage`: the number and percentage of non-empty source lines
  accepted for profiling, with excluded records shown separately.
- `diversity`: Shannon entropy, normalized entropy, effective category count,
  and the number of observed broad class combinations.
- `weighted_vs_unweighted`: percentage-point differences between weighted
  and entry-based length, class-presence, and class-combination distributions,
  useful when frequency counts are uneven.
- `policy_indicators`: weighted and unweighted counts below 8 characters,
  below 12 characters, and at least 12 characters.
- `weight_diagnostics`: reports minimum, maximum, mean, approximate median/p95/p99
  weight ranges, logarithmic weight buckets, top-1/top-10/top-100 concentration,
  and guards for signed-int64 and JavaScript safe-integer limits. Percentiles are
  explicitly marked as power-of-two-bucket approximations.
- `profile_consistency`: checks that input lines, histograms, class combinations,
  single-/multi-class totals, input coverage, length bounds, and weight diagnostics
  reconcile.
- `comparison` (only with `--compare`): weighted and unweighted distribution
  deltas, mean-length changes, and class-diversity changes against a reference
  profile. Positive values indicate a higher share in the candidate profile.
- `privacy`: confirms that raw values are neither retained nor emitted and that
  duplicate lines are not deduplicated.

All counts are aggregate statistics. In `auto` and `count-value` modes,
weighted counts account for the leading frequency on `COUNT VALUE` lines;
unweighted counts treat each accepted source line as one entry. In `plain` mode,
every non-empty source line is treated as a value with weight one. Repeated lines
are always retained as separate entries. Python's arbitrary-precision integers
are used for accumulation; the report warns when weighted totals or individual
weights exceed signed-int64 or JavaScript safe-integer limits. Do not convert
those values to fixed-width integers or JavaScript `Number` without an explicit
lossless representation.
The profiler does not retain password strings after processing each input line.
The report intentionally excludes specific passwords, substrings, prefixes,
suffixes, and candidate suggestions.

Input acceptance coverage describes only whether non-empty source records
fit the profiler's supported length range. It is not full PCFG grammar coverage
or a measure of candidate recovery. The diversity figures describe the
distribution of broad class combinations, not learned grammar productions.
When comparing with an earlier v1 report, weighted deltas remain available;
unweighted and diversity deltas are marked unavailable if the reference report
does not contain those newer metrics.

## Using a profile to inform Top-N / PCFG-Lite seed generation

A saved report can be fed back into `rulest.topn_seedgen` (the Top-N seed
generator behind Stage S's "Top-N Seed Injection") to nudge its family-budget
priors toward the corpus's measured digit/symbol/uppercase composition,
instead of the tool's fixed, hand-tuned defaults:

```bash
python run_topn_seedgen.py TARGET.txt -o topn_seeds.rule \
  --pcfg-profile reports/target-profile.json
```

The same `pcfg_profile` field is accepted by the `/api/tools/topn-seeds` web
endpoint, and the Top-N panel in the web UI has an optional "Add profile
JSON" upload for it (parsed entirely in the browser; the file never needs a
server-side upload slot). Only the aggregate composition shares documented
above are read -- this does not change what the profiler itself reports, and
it still never derives or uses specific passwords, affixes, or candidates.
See the "PCFG-Lite seed generation informed by aggregate corpus profiles"
entry in `docs/CHANGELOG.md` for what this does and does not improve.
