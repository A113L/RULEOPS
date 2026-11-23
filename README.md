# RULEOPS — A GPU-Accelerated Toolchain for Hashcat Rule Generation, Ranking, and Optimization

<a href="https://a113l.github.io/RULEOPS/">
    <img src="web/favicon.svg" alt="RULEOPS" width="120">
</a>

RULEOPS is a cybersecurity research workbench for building, benchmarking, scoring, and compressing
password-cracking rulesets used with [Hashcat](https://hashcat.net/hashcat/).
It brings together seven complementary tools behind one authenticated local
web UI (plus standalone CLIs for each), aimed at studying how rule-based
password transformations can be generated and selected more efficiently than
hand-tuned rule lists.

> **Cybersecurity research use.** This project was built as a cybersecurity
> research toolchain for studying rule-based password guessing and
> set-coverage optimization (CELF / greedy max-coverage algorithms applied
> to rule selection). It is intended for authorized password-security
> research and password-strength auditing on data you are permitted to
> test.

## Table of contents

- [Motivation](#motivation)
- [Components](#components)
- [Architecture overview](#architecture-overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Typical pipeline](#typical-pipeline)
- [PCFG Corpus Profiling](#pcfg-corpus-profiling)
- [Project structure](#project-structure)
- [Documentation](#documentation)
- [Testing](#testing)
- [License](#license)

## Motivation

Hashcat rules transform guessed base words (e.g. `password`) into likely
password variants (e.g. `Passw0rd!`). Large public rule sets contain tens of
thousands of such transformations, many of which are redundant or
low-yield for a given target distribution. RULEOPS explores three related
questions:

1. **Generation** — can plausible rule chains be derived empirically from
   paired base/target wordlists rather than written by hand? (`rulest`,
   `rulestripper`)
2. **Ranking** — given a candidate rule set and a cracked-password sample,
   which rules contribute the most unique coverage, and can this be scored
   efficiently on a GPU? (`rule_ranker`)
3. **Compression** — once ranked, how small a rule subset can reproduce (or
   approximate) the same coverage, using greedy/CELF-style submodular
   selection, and how many rules are simply behaviorally redundant?
   (`rule_ranker` postprocessing, `minimizer.py`)

## Components

| Tool | Purpose |
|---|---|
| **RULEST** | Generates candidate rule sets from BASE/TARGET wordlist pairs (optional Stage 0 pass and genetic-algorithm refinement), GPU-accelerated. |
| **Rule Ranker** | Scores a candidate `.rule` file against a wordlist + cracked-password list; supports an adaptive multi-armed-bandit (MAB) mode and a legacy exhaustive mode. |
| **Ranker CELF optimizer** | Runs greedy/CELF max-coverage selection over ranked candidates (GPU coverage pass + CPU or GPU CELF) to produce a compact, high-coverage rule file. |
| **Concentrator** | Extracts, generates, and cleans rule collections from existing material. |
| **Aether** | Benchmarks Hashcat rule throughput on an OpenCL GPU, produces per-file dashboards, and can build a fastest-first ruleset under a cumulative execution-time budget. |
| **Rulestripper** | Empirically derives rule chains by decomposing TARGET words into BASE-word stems and transformations (14 extraction modes). |
| **PCFG Corpus Profiler** | Produces aggregate-only length and character-class statistics for password-security auditing; it does not emit candidate values or rules. |
| **Rule Minimizer** | Removes functionally/behaviorally equivalent rules by comparing their output over a probe word set. |
| **Email Rule Extractor** | Browser-only utility that derives candidate rules from email-address-style naming patterns. |

All server-side tools share one password-protected local web UI (live log,
job monitor, run-storage manager, download area); each is also runnable as a
standalone CLI.

## Architecture overview

- **`app.py`** — the authenticated Control Center web server (LAN-capable,
  single-job-at-a-time scheduler, run storage, security hardening).
- **`rulest/`** — RULEST core engine (OpenCL/GPU kernels, CPU fallback,
  genetic-algorithm stage, token-stripping, hashing/shared-memory utilities).
- **`rule_ranker/`** — installable package wrapping the ranking, CSV
  post-processing/handler, and CELF selection logic behind one dispatcher
  CLI (`run_ranker.py`).
- **`minimizer.py`**, **`run_rulestripper.py`**, **`concentrator.py`**, **`aether.py`** —
  standalone engines for minimization, rule-chain extraction, rule collection
  management, and GPU rule-performance benchmarking, all reachable from the web UI.
- **`web/`** — front-end assets for the Control Center and the browser-only
  Email Rule Extractor.
- **`tests/`** — unit and integration tests for every engine, the GUI
  control layer, and GPU code paths.

## Requirements

- Python 3.9+
- `numpy`, `pyopencl`, `tqdm`, `msgpack>=1.0` (see `requirements.txt`)
- A working OpenCL runtime and compatible GPU driver for GPU-accelerated
  stages of RULEST, Rule Ranker ranking, and CELF selection (CSV-only
  analysis is CPU-only)

## Installation

```bash
git clone https://github.com/A113L/RULEOPS.git
cd RULEOPS
python -m pip install -r requirements.txt
```

## Quick start

**Windows**

```bat
start_gui.bat
```

**Linux / macOS**

```bash
chmod +x start_gui.sh
./start_gui.sh
```

The terminal prints a local URL (and any detected LAN URL). On first visit,
set an application password (12+ characters) to complete one-time setup; see
the security notes in the full install docs for LAN-exposure guidance.

To run on a specific host/port instead of the default launcher:

```bash
python app.py --host 127.0.0.1 --port 8765
```

### Resetting the admin password

If you forget the application password, reset it from the command line
(run from the project root, with the same Python environment used to run
`app.py`):

```bash
python3 -c "import getpass, app; p=getpass.getpass('New admin password: '); assert len(p)>=12, 'Minimum 12 characters'; app.save_admin_password(p); print('Admin password updated successfully.')"
```

You'll be prompted to enter a new password (12+ characters, not echoed to
the terminal) which replaces the existing one immediately.

## Typical pipeline

```bash
# 1. Generate candidate rules from a base/target wordlist pair
python run_rulest.py BASE.txt TARGET.txt --output candidates.rule

# 2. Rank candidate rules against a wordlist + cracked-password sample (GPU)
python run_ranker.py rank -w wordlist.txt -r candidates.rule -c cracked.txt -o ranking.csv

# 3. Greedy/CELF max-coverage selection down to a target budget
python run_ranker.py postprocess -r ranking.csv -w wordlist.txt -k cracked.txt \
    -o celf_selected.rule --candidates 20000 --budget 5000

# 4. Remove any remaining behaviorally equivalent rules
python minimizer.py celf_selected.rule --output final.rule --workers 4
```

Each step is also available from the Control Center UI.

## PCFG Corpus Profiling

Create an aggregate-only profile of a target wordlist with weighted and
unweighted length and character-class statistics, input acceptance coverage,
class-combination diversity, and consistency checks. The profiler does not emit
password values, substrings, affixes, candidates, or rule suggestions.

```bash
python run_pcfg_profile.py TARGET.txt --output reports/target-profile.json
```

Compare a new input against a previously generated profile:

```bash
python run_pcfg_profile.py MEDIUM.txt --compare reports/small-profile.json \
  --output reports/medium-profile.json
```

See [`docs/PCFG_PROFILE.md`](docs/PCFG_PROFILE.md) for the report schema,
comparison behavior, and frequency-list handling details.

## Project structure

```
RULEOPS/
├── app.py                  # Control Center web server
├── run_rulest.py           # RULEST CLI entry point
├── run_ranker.py           # Rule Ranker dispatcher CLI
├── run_pcfg_profile.py     # Aggregate-only PCFG corpus profiler
├── run_rulestripper.py     # Rulestripper CLI entry point
├── minimizer.py            # Standalone rule minimizer
├── concentrator.py         # Rule collection extraction/cleaning
├── gpu_diagnostics.py      # OpenCL/GPU environment diagnostics
├── rulest/                 # RULEST engine package
├── rule_ranker/            # Ranking + CELF postprocessing package
├── web/                    # Front-end assets
├── docs/                   # Design notes, fixes, and performance logs
└── tests/                  # Unit and integration tests
```

## Documentation

Deeper design notes live under [`docs/`](docs/), including:

- [`docs/RANKER_README.md`](docs/RANKER_README.md) — Rule Ranker package/CLI reference
- [`docs/SECURITY_HARDENING.md`](docs/SECURITY_HARDENING.md) — web-server limits and hardening
- [`docs/SYSTEMD_SERVICE.md`](docs/SYSTEMD_SERVICE.md) — running as a Linux service
- [`docs/CELF_GPU_EXACT_SCORING_AND_PROGRESS_2026-11-14.md`](docs/CELF_GPU_EXACT_SCORING_AND_PROGRESS_2026-11-14.md) — CELF selection algorithm, correctness constraints, and benchmarks
- [`docs/INPUT_LIBRARY.md`](docs/INPUT_LIBRARY.md), [`docs/MEMORY_OPTIMIZATION.md`](docs/MEMORY_OPTIMIZATION.md) — supporting subsystems
- [`docs/PCFG_PROFILE.md`](docs/PCFG_PROFILE.md) — aggregate-only PCFG corpus profile CLI and report schema

## Testing

```bash
pytest
```

The test suite (`tests/`) covers the core engines, GPU-path parity checks
(where an OpenCL device is available), the ranking/CELF pipeline, and the
Control Center's web and authentication layers.

## License

See [`LICENSE`](LICENSE) for full terms.

## Support

For help, bug reports and feedback:

- Email: `nullpointer@i2pmail.org`
- Discord: `a_1_1_3_1`
