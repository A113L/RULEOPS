# Rule Ranker

> [← Documentation index](../README.md)


The Rule Ranker package provides candidate scoring, CSV analysis and CELF-based
rule selection. Its `postprocess` stage uses GPU recomputation for exact
candidate coverage scoring; the greedy heap and control flow are coordinated on
the host. The current implementation does not build the former dense
`candidate × target` coverage matrix.

The `rule_ranker` package contains three workflows exposed through one
dispatcher CLI:

| Original script          | Package module                    | What it does                                              |
|---------------------------|------------------------------------|-------------------------------------------------------------|
| `ranker.py`                | `rule_ranker.ranker`               | GPU-accelerated Hashcat rule ranking (MAB or legacy exhaustive) |
| `ranker_handler.py`        | `rule_ranker.ranker_handler`       | Fast analysis/summarization of ranker output CSVs           |
| `ranker_postprocess.py`    | `rule_ranker.ranker_postprocess`   | GPU-recomputed CELF greedy max-coverage rule selection post-stage |

## Contents

- [Install](#install)
- [Usage](#usage)
- [Typical pipeline](#typical-pipeline)
- [Tests](#tests)
- [Unified web interface](#unified-web-interface)

## Install

```bash
python -m pip install -r requirements.txt
```

`numpy` and `tqdm` are required by all three tools. `pyopencl` (with a
working OpenCL ICD / GPU driver) is required by `rank` and by the GPU
coverage pass of `postprocess`. `handler` has no GPU dependency at all.
`postprocess` uses the recompute-GPU scoring path for exact marginal coverage.
The host manages CELF candidate priorities, heap operations and winner
coordination; the detailed GPU path is described in
[`../engineering/CELF_RANKER.md`](../engineering/CELF_RANKER.md).

## Usage

All three tools are reachable through one dispatcher:

```bash
python3 run_ranker.py rank -w wordlist.txt -r rules.rule -c cracked.txt -o out.csv
python3 run_ranker.py rank --legacy -w wordlist.txt -r rules.rule -c cracked.txt -o out.csv
python3 run_ranker.py rank --list-devices

python3 run_ranker.py handler -i out.csv -o summary.txt -r clean.rule -t 1000

python3 run_ranker.py postprocess -r out.csv -w wordlist.txt -k cracked.txt \
    -o celf_selected.rule --candidates 20000 --budget 5000
python3 run_ranker.py postprocess -r out.csv -w wordlist.txt -k cracked.txt \
    -o celf_selected.rule --budgets 64,250,5000 --in-ram
```

Every subcommand's own `--help` shows that tool's full (unchanged)
argument list:

```bash
python3 run_ranker.py rank --help
python3 run_ranker.py handler --help
python3 run_ranker.py postprocess --help
```

Each tool also remains runnable directly as a module, without the
dispatcher:

```bash
python3 -m rule_ranker.ranker ...
python3 -m rule_ranker.ranker_handler ...
python3 -m rule_ranker.ranker_postprocess ...
```

## Typical pipeline

```bash
# 1. Rank candidate rules against a wordlist + cracked list (GPU)
python3 run_ranker.py rank -w rockyou.txt -r hashcat_rules.rule -c cracked.txt -o ranking.csv

# 2. (Optional) Summarize/clean the ranking output
python3 run_ranker.py handler -i ranking.csv -o summary.txt -r top_rules.rule -t 5000

# 3. Run CELF greedy max-coverage selection on the top candidates (GPU exact scoring + host-side selection)
python3 run_ranker.py postprocess -r ranking.csv -w rockyou.txt -k cracked.txt \
    -o celf_final.rule --candidates 20000 --budget 5000
```

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

Tests cover the pure-Python/NumPy logic in each module -- rule
validation (including the documented bug fixes in `ranker.py`'s
changelog), CSV/rule-file parsing and analysis in `ranker_handler.py`,
and popcount/budget-parsing/CELF-greedy-selection logic in
`ranker_postprocess.py` -- plus the `run_ranker.py` dispatcher's
routing. GPU/OpenCL kernel code paths themselves are out of scope for
unit tests (they need a real GPU); `tests/conftest.py` installs a
minimal stub for `pyopencl` so the GPU-dependent modules can still be
*imported* (needed to reach their pure-Python code and their
`--help`/argument-parsing paths) in an environment without a real
OpenCL/GPU stack. If `pyopencl` is genuinely installed, the stub is
skipped and the real module is used.



## Unified web interface

This package is bundled into the RULEOPS toolchain. Start the shared web server with `start_gui.sh` (Linux/macOS) or `start_gui.bat` (Windows), sign in with the same application password, then select **Rule Ranker** from the sidebar. The web interface exposes the `rank`, `postprocess` (shown as **Optimize ruleset**) and `handler` (shown as **Analyze CSV**) workflows with file uploads, parameter validation, shared live logs and output downloads. Standalone CLI usage remains supported.
