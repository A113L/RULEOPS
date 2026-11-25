# RULEOPS documentation

This folder contains the maintained guides, operational references and
engineering notes for RULEOPS. Use this page as the documentation entry point;
the project overview, installation and first-run instructions remain in the
repository [README](../README.md).

## Start here

| I want to… | Read |
|---|---|
| Understand the project, install it and run the tools | [Project README](../README.md) |
| Use all RULEOPS tools through the UI or CLI | [User guide — CLI + UI](guides/USER_GUIDE.md) |
| Import a curated Hashcat rule file into RULEST CELF | [RULEST CELF seed files](guides/RULEST_CELF_SEEDS.md) |
| Use the Rule Ranker CLI and web workflows | [Rule Ranker guide](guides/RANKER.md) |
| Understand CELF exact scoring in Rule Ranker | [Rule Ranker CELF internals](engineering/CELF_RANKER.md) |
| Profile Rule Ranker CELF runs | [CELF profiling](engineering/CELF_PROFILING.md) |
| Compare published RULEOPS ruleset results with other benchmark entries | [Ruleset quality benchmark](engineering/RULESET_QUALITY_BENCHMARK.md) |
| Deploy the web app as a Linux service | [systemd deployment](operations/SYSTEMD_SERVICE.md) |
| Configure limits and secure the web server | [Security hardening](operations/SECURITY_HARDENING.md) |

## User guides

| Document | What it covers |
|---|---|
| [User guide — CLI + UI](guides/USER_GUIDE.md) | End-to-end instructions for all UI tools, CLI commands, workflows, storage and troubleshooting |
| [Rule Ranker](guides/RANKER.md) | `rank`, `handler` and `postprocess` commands, common pipelines, test coverage and web integration |
| [RULEST CELF seed files](guides/RULEST_CELF_SEEDS.md) | CLI and UI steps for adding a curated rules file as CELF candidates; validation, limits and the difference from Stage S seeds |
| [Reusable input library](guides/INPUT_LIBRARY.md) | Persistent wordlist/rule storage, duplicate handling, selectors and cleanup behavior |
| [PCFG corpus profile](guides/PCFG_PROFILE.md) | Input formats, profile fields, weighted metrics and profile comparisons |
| [Screenshots](guides/SCREENSHOTS.md) | Selected Control Center and workflow screenshots |

## Engineering references

| Document | What it covers |
|---|---|
| [RULEST CELF](engineering/RULEST_CELF.md) | Exact greedy selection, stale zero-gain batching, GPU winner snapshots, compaction and experimental bitmap initialization |
| [Rule Ranker CELF](engineering/CELF_RANKER.md) | Exact scoring, GPU deduplication, winner caching, progress/ETA metrics, profiling fields and benchmark interpretation |
| [CELF profiling](engineering/CELF_PROFILING.md) | Profiling toggle, first-round candidate diagnostics and interpretation of upper bounds versus exact gains |
| [RULEST GA Verify](engineering/RULEST_GA_VERIFY.md) | GPU count-only verification, resident BASE buffers, batch sizing and fallback behavior |
| [Memory optimization](engineering/MEMORY_OPTIMIZATION.md) | Shared wordlists, Stage 0 membership, GPU host buffers and large-target GA behavior |
| [PCFG-guided optimization](engineering/PCFG_GUIDED_OPTIMIZATION.md) | How aggregate corpus profiles affect Top-N seed budgets and CELF cost-aware ranking |
| [Performance diagnostics](engineering/PERFORMANCE_DIAGNOSTICS.md) | Progress reporting for operations whose total work is not known in advance and safe performance comparisons |
| [Ruleset quality benchmark](engineering/RULESET_QUALITY_BENCHMARK.md) | Published recovery and efficiency comparison by ruleset size and RULEOPS tool family |

## Operations and maintenance

| Document | What it covers |
|---|---|
| [Security hardening](operations/SECURITY_HARDENING.md) | HTTP server limits, upload/storage quotas, browser security headers and login throttling |
| [systemd deployment](operations/SYSTEMD_SERVICE.md) | Linux installation, service setup, network restrictions, upgrades, logs and troubleshooting |
| [Tool status metrics](operations/TOOL_STATUS_METRICS.md) | Meaning and scope of the shared run-status cards and ETA |

## Release history

See the [changelog](CHANGELOG.md) for dated features, fixes and compatibility
changes. It is the chronological record; detailed guides above describe the
current supported behavior and relevant implementation constraints. Historical
benchmark values are tied to their stated workload and hardware and should not
be read as general performance guarantees.

## Documentation structure

```text
docs/
├── README.md                 # this index
├── CHANGELOG.md              # chronological project history
├── index.html                # project website / landing page
├── guides/                   # how-to and user-facing references
├── engineering/              # algorithm, GPU and performance details
└── operations/               # deployment, security and runtime behavior
```
