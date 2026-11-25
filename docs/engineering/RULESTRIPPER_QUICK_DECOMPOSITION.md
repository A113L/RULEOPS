# Rulestripper Fast Decomposition

> [← Documentation index](../README.md) · [User Guide — CLI + UI](../guides/USER_GUIDE.md)

## 1. Purpose

Rulestripper is a CPU-based, multiprocessing engine that empirically decomposes each TARGET entry into a candidate BASE stem plus a sequence of Hashcat rule operations.

The central question is:

> Can a word in TARGET be reconstructed from a word in BASE by applying a supported Hashcat rule or rule chain?

Rulestripper is designed for fast candidate discovery over large wordlists. It is not a GPU search engine, a password cracker, a rule-performance benchmark, or a proof that every possible decomposition has been found. It does not calculate hash recovery or TARGET coverage scores.

There is no separate `--quick` switch in the current CLI. “Fast decomposition” describes the implementation: reverse candidate generation, indexed BASE lookups, shared-memory data structures, and CPU multiprocessing.

## 2. Inputs and normalization

Rulestripper takes two newline-delimited wordlists:

- **BASE** — source words that may act as stems.
- **TARGET** — words to explain using a BASE stem and Hashcat transformations.

The loader skips empty lines and removes line terminators. BASE entries are converted to lowercase before being packed into shared memory. TARGET entries retain their original case because case differences can be part of the transformation to reconstruct.

The input files are read in two passes and packed as UTF-8 bytes plus a shared 64-bit offset table. This avoids building a large Python list containing millions of independent strings. The number of scanned TARGET entries is the number of non-empty input lines; duplicate TARGET lines are still scanned, while duplicate extracted rule chains are removed from the final result set.

Words longer than the current `MAX_WORD_LEN` limit (256 characters) are skipped by the per-target worker.

## 3. Decomposition model

For a given TARGET word, Rulestripper generates plausible source stems by reversing or removing transformations from the TARGET side, then checks whether a candidate stem is present in the BASE membership index.

A candidate chain is accepted only when all of these conditions hold:

1. The candidate stem meets the configured minimum length.
2. The candidate is found in the BASE membership structure.
3. The generated chain is accepted by Rulestripper's Hashcat-rule validator and fits the configured depth.
4. The Python rule applicator replays the chain and produces the original TARGET word exactly.

The last check is important: candidate generation is optimized to avoid scanning every BASE word, but a proposed rule is still replayed before it is retained.

The engine collects a **set of unique rule chains across the whole TARGET file**. It does not produce a permanent one-to-one mapping from each TARGET line to its source BASE word, and it does not report which individual TARGET entries were explained by each chain.

## 4. Core decomposition workflow

For each TARGET word, the worker applies the following families of checks. The first five are the original extraction families; ten extended families are enabled by default.

### 4.1 Letter and boundary decomposition

The letter mode treats digits and selected punctuation characters as boundaries and scans possible prefixes, suffixes, and middle segments. The middle segment must be long enough to qualify as a stem candidate.

For a candidate middle segment, Rulestripper:

1. Generates possible leet-decoded forms.
2. Infers possible case operations.
3. Converts the decoded middle to lowercase and checks it against BASE.
4. Builds prefix operations using Hashcat `^` and suffix operations using `$`.
5. Tries a small set of plausible operation orderings.
6. Validates and replays every complete chain against the original TARGET word.

The boundary operations are generated in the required order: prefix characters are prepended in reverse traversal order so that the final word has the original prefix order; suffix characters are appended in forward order.

### 4.2 Leet decoding

The current built-in mapping table is:

| TARGET character | Possible BASE character | Rule |
|---|---|---|
| `@` | `a` | `sa@` |
| `3` | `e` | `se3` |
| `0` | `o` | `so0` |
| `1` | `i` or `l` | `si1` or `sl1` |
| `5` | `s` | `ss5` |
| `$` | `s` | `ss$` |
| `7` | `t` | `st7` |
| `4` | `a` | `sa4` |
| `!` | `i` | `si!` |

Rulestripper explores combinations for the recognized characters. The `--leet-amb` setting limits the number of **ambiguous positions**—positions with more than one decoding option—not the total number of leet characters. The default is 3. If a middle segment exceeds that ambiguity limit, that leet-decoding path is skipped.

### 4.3 Case inference

The case-inference helper checks whether the decoded stem can be reconstructed using one of these patterns:

- `u` — uppercase the whole word;
- `c` — capitalize the first character and lowercase the remainder;
- `C` — lowercase the first character and uppercase the remainder;
- `t` — toggle the case of every character;
- `E` — Hashcat title-case behavior;
- `Tn` — toggle individual uppercase positions when every required position is within 0–9.

When no recognized pattern is found, the current implementation can fall back to no case operation. It does not enumerate every possible ordering or every possible per-character case program.

### 4.4 Candidate chain orderings

The letter decomposition does not try every permutation of all operations. It tests a constrained set of orderings to keep the search bounded:

1. Case operations, then leet substitutions, then prefix and suffix operations.
2. Leet substitutions, then case operations, then prefix and suffix operations, when both case and leet operations are present.
3. Prefix operations, then case and leet operations, then suffix operations, when a boundary prefix and case/leet work are present.

Reverse and edge-delete modes can add a leading operation before these sequences. Every constructed chain must still pass the validator and exact replay check.

## 5. The 15 extraction families

The current implementation advertises 15 extraction modes: five original families and ten extended families.

### Original families

| Family | Hashcat operation(s) | What it detects |
|---|---|---|
| **Letter** | Case, leet, `^`, `$` | A letter-based BASE stem with recognized case/leet changes and boundary characters. |
| **Digit** | `^`, `$` | A pure numeric BASE stem surrounded by alphabetic or punctuation boundaries. The middle segment must consist only of digits. |
| **Reverse** | `r` plus letter decomposition | A reversed BASE middle segment, optionally with the same case/leet and boundary reconstruction. |
| **Delete edge** | `[`, `]` plus letter decomposition | A transformation where the first or last character is removed before the remaining target structure is explained. |
| **Duplicate / fold** | `d`, `f` | A target equal to a BASE stem duplicated end-to-end (`d`) or followed by its reverse (`f`). |

### Extended families (enabled by default)

| Family | Hashcat operation(s) | What it detects |
|---|---|---|
| **Hashcat 8 byte transforms** | `h`, `H`, `S`, `vNX` | Hex encoding in lower/upper case, the self-inverse keyboard-shift mapping, and periodic marker insertion. Matching is performed on UTF-8 bytes where required. |
| **Insert** | `iNX` | A target created by inserting one character, or a two-insertion chain, into a BASE stem. |
| **Swap** | `k`, `K`, `*MN` | Swapping the first two characters, the last two characters, or two indexed positions. |
| **Range** | `xNM`, `ONM` | Extracting a contiguous range from a BASE stem or omitting a contiguous range. |
| **Character duplicate** | `zN`, `ZN`, `q` | Repeating the first character, repeating the last character, or duplicating every character. |
| **ASCII / byte transform** | `+N`, `-N`, `LN`, `RN`, `.N`, `,N` | Per-position byte arithmetic and bit-shift transformations, including uniform increment/decrement chains across several positions. |
| **Truncate** | `'N` | A TARGET that is a prefix of a longer BASE word. |
| **Purge** | `@X` | Removing every occurrence of a character from a BASE stem. |
| **Repeat** | `pN` | Repeating the same BASE word multiple times; this is an alternative to the two-copy `d` case. |
| **Separator title-case** | `eX` | Title-casing after a supported separator: hyphen, underscore, space, or period. |

The extended modes are independent detectors. They do not imply that every TARGET is transformed by all 15 families, and the families do not cover every legal Hashcat rule command.

### Positional and mode-specific limits

Several detectors intentionally generate positions only in the first ten character positions (0–9), matching the current implementation's positional search loops. This applies to insertion, swap, range, ASCII-position and truncation detection. The Hashcat 8 `vNX` detector separately supports a base-36 interval value from 1 through 35.

The double-insertion detector considers positions in the first ten positions and requires a chain depth of at least 3. Single insertion requires a depth of at least 2. Other families have their own length and depth preconditions, so the same `--max-depth` value does not make every mode equally capable.

## 6. Why decomposition is fast

Rulestripper avoids the naive strategy of testing every BASE word against every TARGET word for every possible rule family.

### 6.1 Reverse candidate generation

For many transformations, the target word itself provides a small set of possible source stems:

- Insertion detection removes one or two TARGET characters and checks the shortened candidate in BASE.
- Swap detection reverses a specific transposition and checks the resulting word.
- ASCII transforms reverse the byte operation at likely positions and check the candidate.
- Repeat and character-duplicate detection reduce the TARGET to its possible repeated stem.
- Hashcat 8 transforms reverse the byte encoding, marker insertion, or keyboard-shift mapping.

This makes the common path a sequence of candidate generation plus membership checks instead of a full BASE scan.

### 6.2 Shared BASE membership

BASE is held in packed shared memory and indexed by a compact `FlatHashSet64` membership table. Worker processes attach to the same data and index instead of constructing a large private Python set for every worker.

### 6.3 TARGET-keyed inverted postings

When extended modes are enabled, Rulestripper builds a shared TARGET lookup and four TARGET-keyed posting indexes:

- **substring** — BASE words containing a substring that occurs in TARGET;
- **omit** — BASE words that can produce a TARGET key by omitting a contiguous range;
- **prefix** — BASE words whose prefix is a TARGET word (for truncation);
- **purge** — BASE words that produce a TARGET key when a character is removed.

Only BASE-derived keys that actually occur in TARGET are stored. Posting values are BASE word indexes, not duplicated Python strings. The indexes are backed by shared memory and are used by the range, truncate, and purge detectors.

When `--no-new-modes` is selected, these enhanced-mode indexes are skipped.

### 6.4 Multiprocessing with range-only tasks

The worker pool processes TARGET ranges. A task contains only two integer offsets (`start`, `stop`), not a copied list of words. Each worker attaches to the shared BASE/TARGET buffers, membership table and optional postings indexes, then processes its assigned TARGET slice.

The parent process collects each chunk's set of rule chains, unions the sets, and sorts the final unique result. The default worker count is the available CPU count. Automatic chunk size is calculated as:

`max(500, target_word_count // (worker_count × 4) + 1)`

A user-supplied positive `--chunk-size` overrides this calculation.

This architecture reduces process serialization and redundant memory copies. Actual throughput still depends on wordlist sizes, the number of matches and candidate paths, selected modes, CPU resources, and memory bandwidth.

## 7. Toggle-chain seeds are separate from empirical matches

Unless `--no-toggle-seeds` is set, Rulestripper appends a generated collection of toggle/leet seed chains to the extracted chains.

The generator includes:

- sequential position toggles (`T0 T1 …`);
- even-position toggle patterns;
- odd-position toggle patterns;
- combinations of toggle patterns with one or two entries from the built-in leet substitution list.

These are predefined seed candidates. They are syntax-validated, but they are **not proven to reconstruct a particular BASE/TARGET pair during the extraction pass**. The final output may therefore contain chains that were added as scaffolding rather than discovered from an observed decomposition.

For a result containing only chains derived from the BASE/TARGET extraction, use `--no-toggle-seeds`.

## 8. Settings and current limits

| Setting | CLI option | Current default / behavior |
|---|---|---|
| Maximum chain depth | `--max-depth N` | `0` is converted to 31. Positive values limit the number of operations in a chain. |
| Minimum stem length | `--min-stem N` | 4 characters. |
| Leet ambiguity | `--leet-amb N` | 3 ambiguous positions. |
| Toggle-chain seeds | `--no-toggle-seeds` | Included unless disabled. |
| Extended extraction modes | `--no-new-modes` | Enabled unless disabled. |
| Worker processes | `--workers N` | `0` selects the CPU-count default; a positive value requests a worker count. |
| Words per task | `--chunk-size N` | `0` selects the automatic range size. |
| ASCII offset range | `--ascii-range N` | The argument is retained for compatibility, but the current extraction function discards it; it does not currently change the search range. |
| Debug output | `--debug` | Off by default. |

Additional implementation limits:

- TARGET words longer than 256 characters are skipped.
- The default maximum chain depth is 31.
- Several positional detectors only search positions 0–9.
- Leet decoding is limited by the ambiguous-position threshold.
- The supported command set is determined by Rulestripper's own validator and Python rule applicator; syntactically valid Hashcat commands outside that implemented subset are not necessarily extractable.
- The internal `_optimize_chain` helper is not called by the current CLI execution path; the output is not a globally minimized or coverage-ranked ruleset.

## 9. Output semantics

The CLI default output is `stripper_rules.txt`; the Control Center's default output name is `rulestripper_rules.rule`.

The output file contains:

1. Comment lines with generation time, BASE/TARGET filenames, depth, worker count, and mode/seed settings.
2. Summary counts for total rules, stem-derived rules, toggle seeds, and chain-depth distribution.
3. A `:` no-op rule.
4. The sorted, unique rule chains (one chain per line).

The terminal summary also reports the number of TARGET words scanned, the number of unique chains, chain-depth distribution, and a mode breakdown. The breakdown classifies a chain by its first operation; it is not a count of every operator appearing anywhere in every chain.

## 10. Running Rulestripper

### CLI

Run from the repository root:

```bash
python run_rulestripper.py BASE.txt TARGET.txt \
  --output extracted.rule \
  --max-depth 2 \
  --min-stem 4 \
  --leet-amb 3 \
  --workers 8
```

Useful variants:

```bash
# Only empirically extracted chains; do not append generic toggle/leet seeds.
python run_rulestripper.py BASE.txt TARGET.txt \
  --output extracted_only.rule --no-toggle-seeds

# Use only the five original extraction families.
python run_rulestripper.py BASE.txt TARGET.txt \
  --output core_modes.rule --no-new-modes
```

Check all supported arguments with:

```bash
python run_rulestripper.py --help
```

### Control Center

In the Rulestripper panel, select **BASE wordlist** and **TARGET wordlist**, configure the extraction settings, choose an output name, and start the extraction job. When it completes, download the generated rule file from the results panel. The UI uses the same shared-memory multiprocessing engine as the CLI.

## 11. How to interpret the result

Rulestripper is a **candidate-chain extractor**, not a coverage optimizer.

- A returned stem-derived chain has been constructed from a BASE membership candidate and replayed to the exact TARGET word during extraction.
- The output is the union of unique chains across all TARGET entries. It does not include per-target provenance.
- Toggle-chain seeds are separate predefined candidates and should not be confused with observed decompositions.
- The extraction families are bounded and implementation-specific. A missing chain does not prove that no Hashcat rule chain can transform a BASE entry into that TARGET entry.
- A large output file does not necessarily mean that the chains are useful for a particular password distribution. Use Rule Ranker/CELF to evaluate coverage on an authorized evaluation set, Rule Minimizer to compare behavior on a probe set, and Aether to measure GPU execution cost.

## 12. Implementation references

The behavior documented here is implemented primarily in:

- `rulest/rulestripper.py` — extraction modes, rule-chain construction, validation/replay, multiprocessing orchestration and CLI.
- `rulest/token_strip.py` — packed UTF-8 word buffers in shared memory.
- `rulest/tokenstrip_hashset.py` — compact shared BASE membership table.
- `rulest/shared_target_postings.py` — TARGET lookup and shared inverted postings.
- `run_rulestripper.py` — spawn-safe CLI entry point.
- `tests/test_rulestripper_hashcat8_extraction.py` — Hashcat 8 extraction and validation behavior.
- `tests/test_rulestripper_reverse_mode.py` — reverse-mode regression coverage.
- `tests/test_rulestripper_spawn.py` — shared-memory multiprocessing and spawn-mode coverage.
