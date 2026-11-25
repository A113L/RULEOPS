# Aether GPU Rule Benchmarking

> [← Documentation index](../README.md) · [User Guide](../guides/USER_GUIDE.md)

## 1. Purpose and scope

Aether is RULEOPS' OpenCL GPU benchmark for measuring the execution cost of Hashcat rule commands. It runs RULEOPS' OpenCL implementation of the Hashcat rule interpreter against a controlled synthetic word corpus and records per-rule timing and throughput statistics.

Aether answers questions such as:

- Which supported rule commands or command chains execute fastest on a particular GPU?
- How consistent are measured execution times across repeated runs?
- How does GPU execution time compare with the host-side enqueue-and-wait duration?
- Which rules fit within a cumulative GPU-kernel-time budget?

Aether does **not** measure password recovery, hash cracking, rule effectiveness against a TARGET or CRACKED set, or the runtime of a complete Hashcat attack. It does not calculate guesses per second or hashes per second. Its results describe the current Aether OpenCL interpreter, test corpus, device and benchmark configuration—not universal Hashcat performance.

## 2. What is one measured operation?

Aether launches the OpenCL `rule_processor` kernel. For a single-rule measurement, each GPU work-item processes one input word with that rule. The rule is interpreted as a sequence of commands, so a multi-command rule line is measured as one complete chain.

The implementation sets the global work size to:

`work-items per kernel = number of test words × number of rules in the kernel batch`

Aether currently benchmarks one rule at a time, so `operations_per_kernel` is normally equal to the configured number of test words. A word/rule work-item is the unit used for Aether's throughput calculation; it is **not** a password guess, a hash computation, or a count of individual commands within a chain.

The implementation applies the rule transformation to the input data. It does not run a hash function or compare transformed words with a target set.

## 3. Controlled test corpus

Aether does not use a user-supplied WORDLIST as its benchmark corpus. It creates a deterministic corpus from 16 built-in seed words and uses exactly the requested number of entries.

The two corpus modes are:

| Mode | Behavior |
|---|---|
| **Diverse** (default) | Generates deterministic content variants from the 16 seeds. Letter case, digit positions, word length and punctuation positions are preserved; letter and digit values may change. |
| **Identical** (`--identical-dicts`) | Repeats the same 16 seed words until the requested corpus size is reached. |

In diverse mode, variants are generated with BLAKE2s from the seed word, seed index and cycle index. This makes the generated contents reproducible for a given implementation and corpus size. The modes use the same number of work-items and preserve the same word-length and per-position character-class profile; their actual word contents and repetition patterns differ.

The configured `--max-words` value is the exact number of GPU work-items per rule in either mode. The default is 1,000. The report records the actual and requested counts, corpus mode and generator, seed count, and word-length distribution.

### Buffer limits

The current tester reports these interpreter buffer limits:

- Maximum input word length: 64 bytes.
- Maximum packed rule buffer length: 256 bytes, including its terminator; validation therefore limits a rule line to 255 bytes.
- Maximum output buffer length per transformed word: 512 bytes.

These are implementation limits, not Hashcat-wide limits.

## 4. Rule validation before measurement

Every input rule file is validated before any rule is passed to the Aether kernel. Blank lines and comment lines are counted separately. Each remaining source line is treated as one rule, which may contain multiple sequential commands.

Aether reports four active-rule outcomes:

| Status | Meaning |
|---|---|
| **Benchmarkable** | Valid Hashcat rule-file syntax and every command in the chain is implemented by the current Aether OpenCL interpreter. |
| **Invalid** | Malformed or incomplete syntax, an unknown command, an empty rule, or a rule exceeding Hashcat's 31-operation limit. |
| **CLI-only** | A syntactically recognized Hashcat command that is intended for command-line `-j`/`-k` use rather than an ordinary `-r` rule-file entry. |
| **Unsupported** | Valid Hashcat syntax that Aether cannot safely execute yet—for example, an unimplemented operator, a non-ASCII or escaped-byte operand, or a rule line exceeding Aether's 255-byte packed limit. |

Only **benchmarkable** lines are measured. Unsupported rules are not silently treated as no-op commands. The validator also retains original source line numbers so that reports and issue lists can be traced back to the input file.

The supported command set is defined by `aether_validation.py` and the OpenCL interpreter in `aether.py`. It includes supported multi-command chains and supported Hashcat 8.0 byte-oriented operators. The set can evolve; the validation report generated by the installed version is authoritative for a given run.

For each input file Aether writes:

- `<name>_validation_report.json` — counts and per-rule validation issues.
- `<name>_invalid_rules.txt`, `<name>_cli_only_rules.txt`, and/or `<name>_unsupported_rules.txt` — line-numbered source entries, written only for categories that contain issues.

## 5. Timing methodology

OpenCL event profiling is always enabled. Aether creates its command queue with `PROFILING_ENABLE`; this is required for the primary metric and is not an optional profiling toggle.

For each rule and each test run, Aether:

1. Allocates the input, rule and output buffers and sets the kernel arguments.
2. Enqueues warm-up kernel launches and waits for them to finish. Warm-up events are excluded from both reported timing metrics. The warm-up count is `max(3, min(10, iterations // 10))`.
3. Starts a host wall-clock timer with `time.perf_counter_ns()`.
4. Enqueues the configured number of measured kernel launches, retaining their OpenCL events.
5. Calls `queue.finish()` to wait for the measured launches to complete, then stops the host timer.
6. Reads each event's device-side `START` and `END` timestamps.

Buffers and kernel argument setup are outside the measured end-to-end interval. The benchmark repeats this procedure for the configured number of test runs.

### 5.1 GPU Kernel Time — primary metric

For each OpenCL event:

`event GPU time = (event.profile.end − event.profile.start) / 1,000,000,000`

This is device-side kernel execution time in seconds. Aether adds the event durations from the measured iterations in one test run and divides by the number of iterations. It then summarizes the resulting per-run averages across `test_runs`.

This is the primary metric used to sort rules, rank them in reports and build an optimized ruleset. The JSON field `execution_time_seconds` is retained as a compatibility alias for `gpu_kernel_time_seconds`; both represent GPU-only kernel time.

### 5.2 End-to-End Time — diagnostic metric

End-to-End Time is the host elapsed time around the measured enqueue loop and the final queue-completion wait, divided by the number of iterations. It includes host-side kernel dispatch/enqueue overhead and the wait for GPU work to complete.

It excludes buffer allocation and kernel argument setup. It is a separate diagnostic measurement, not an additional duration to add to GPU Kernel Time. The two intervals overlap in the work they describe and must not be summed as independent cost categories.

Use GPU Kernel Time for Aether's rule-performance ranking. Use End-to-End Time to understand the observed host-plus-completion path for the same benchmark configuration.

## 6. Throughput and operation counts

For each rule:

`operations_per_kernel = test_words × rules_in_kernel_batch`

`GPU operations/second = operations_per_kernel / mean GPU Kernel Time`

`End-to-End operations/second = operations_per_kernel / mean End-to-End Time`

Since Aether currently measures one rule per kernel batch, the normal numerator is the number of test words. The report's `total_operations` is:

`test_words × rules_in_kernel_batch × iterations × test_runs`

These rates count Aether word/rule work-items per second. They must not be reported as Hashcat guesses per second, hashes per second, cracked passwords per second, or individual rule commands per second.

## 7. Statistical summary

Aether first calculates one average duration per test run. For each metric separately, it then:

1. Calculates the initial mean and population standard deviation of the per-run averages.
2. Retains samples whose absolute distance from the initial mean is no greater than two standard deviations.
3. Uses the original sample list if filtering would leave no samples.
4. Calculates summary statistics over the retained samples.

The JSON statistics include:

| Field | Meaning |
|---|---|
| `mean_time` | Mean per-run average after the outlier filter. |
| `median_time` | Median of the retained per-run averages. |
| `std_time` | Population standard deviation of the retained values. |
| `min_time` / `max_time` | Minimum and maximum retained per-run averages. |
| `cv_percent` | Coefficient of variation: `std_time / mean_time × 100`. |
| `sample_size` | Number of retained per-run averages. |
| `outliers_removed` | Number of samples excluded by the filter. |

A low CV indicates that the retained per-run averages varied less relative to their mean in this particular test. It is a descriptive consistency measure, not a confidence interval or a guarantee that the result will repeat on another device or software stack.

## 8. Isolated operator-cost measurements

For each validated rule file, Aether also performs a separate operator-profiling pass.

It extracts distinct operator-plus-argument signatures from the rules, measures the no-op rule `:` as a baseline, and benchmarks each sampled command as a one-command rule. For each operator symbol, the reported incremental cost is the mean of:

`(single-command GPU Kernel Time − no-op GPU Kernel Time) × 1,000,000`

The result is expressed in microseconds. The profiling pass records the raw single-command time, no-op baseline, number of sampled variants, number of successfully measured variants, total distinct variants found, and any measurement errors. To bound the extra work, at most four argument variants per operator are sampled, selected from the sorted set of variants.

The file `<name>_operator_costs.json` contains these measurements, and `<name>_heatmap.png` visualizes available incremental costs when visualization is enabled. This operator-profiling pass runs on all validated rules before `--max-test-rules` is applied to the main per-rule chain benchmark, so that cap does not bound the operator-signature discovery pass.

Interpret these costs as approximate isolated operator estimates—not as exact additive costs for arbitrary rule chains. They do not model interactions between commands, command position, or every possible argument variant. Because the baseline is subtracted from separate timing measurements, small or negative incremental values can occur when the difference is within measurement noise; they do not imply negative physical execution time.

## 9. Reports and visualizations

For each successfully benchmarked input file, Aether can write:

| Artifact | Contents |
|---|---|
| `<name>_performance_report.json` | Run metadata and per-rule GPU, end-to-end, throughput and statistical fields. Includes device name, device type, OpenCL timing method, timer resolution, corpus settings and validation counts. |
| `<name>_sorted.rule` | Original rule commands sorted from lowest to highest GPU Kernel Time. Diagnostic timing comments are placed on standalone comment lines before each rule. |
| `<name>_operator_costs.json` | Isolated, no-op-baseline-subtracted operator estimates, when measurements are available. |
| `<name>_interactive.html` | Standalone interactive report, when visualization is enabled. |
| `<name>_radar.png` | Radar chart of the fastest 20 rules, using normalized GPU time, GPU throughput and CV. |
| `<name>_heatmap.png` | Isolated operator-cost heatmap, when operator measurements are available. |
| `<name>_statistical.png` | Statistical summary: timing distribution, time-versus-CV view, fastest commands and relative tiers. |
| `<name>_distribution.png` | GPU Kernel Time distribution plots, including histogram, box plot, cumulative distribution and violin plot (with a histogram fallback). |

The interactive HTML report shows the number of benchmarked rules, mean and median GPU Kernel Time, and mean GPU throughput. Its table includes the exact Hashcat rule command, GPU Kernel Time, GPU operations/second, End-to-End Time and CV. It supports command search, pagination, downloading the selected category, and exporting a chosen number of the fastest measured rules.

### Relative performance tiers

The **Fastest**, **Middle** and **Slowest** categories are relative to the rules in the current input file—not fixed universal timing bands. Aether places boundaries near one-third and two-thirds of the sample, and only between distinct timing values. Rules with exactly equal GPU timings remain in the same category, even if that makes category sizes less evenly balanced.

Do not compare a category label from one report with the same label from another report as if it represented the same absolute time threshold.

## 10. Fastest-first optimization

When `--optimize` is enabled, Aether reads the generated per-file performance reports, revalidates the records, sorts candidate rules by ascending GPU Kernel Time, and selects rules while both limits remain satisfied:

- `--max-optimize-rules`: maximum number of selected rules (default 500).
- `--max-time`: maximum cumulative GPU Kernel Time in **seconds** (default 30 seconds).

The optimizer adds each selected rule's measured mean GPU Kernel Time to the cumulative budget. It writes `optimized_rules.rule` and `optimized_rules_optimization_report.json`, including the selected records, applied limits and validation rejections.

The cumulative budget is the sum of Aether's per-rule kernel-time measurements under the benchmark workload. It is **not** a prediction of complete Hashcat attack time. The optimizer does not evaluate hash recovery, target coverage, functional equivalence, or password-strength effectiveness. It does not establish that the selected rules reproduce the behavior or coverage of the original input set, and it does not deduplicate repeated rule records. It is a fastest-first timing-based selector, not a coverage-preserving ruleset minimizer.

The UI expresses the time budget in microseconds; the CLI `--max-time` argument is in seconds. For example, 30 seconds corresponds to 30,000,000 microseconds.

## 11. Running Aether

Aether requires PyOpenCL and a working OpenCL GPU device. It intentionally does not fall back to CPU timing: if no OpenCL GPU device is available at the selected platform/device indices, initialization fails.

Basic CLI run:

```bash
python aether.py --rules candidates.rule \
  --output benchmark_results \
  --visualize \
  --iterations 50 \
  --test-runs 3 \
  --max-words 1000
```

Benchmark multiple files:

```bash
python aether.py --rules set_a.rule set_b.rule \
  --output benchmark_results --visualize
```

Use the identical seed dictionary and build a fastest-first selection:

```bash
python aether.py --rules candidates.rule \
  --output benchmark_results \
  --identical-dicts \
  --optimize --max-optimize-rules 500 --max-time 30
```

### Main CLI parameters

| Parameter | Default | Meaning |
|---|---:|---|
| `--rules` / `-r` | Required | One or more rule files or directories. Supported extensions: `.rule`, `.rules`, `.hr`, `.hashcat`, `.txt`. Directory search is recursive. |
| `--output` / `-o` | `./benchmark_results` | Output directory. |
| `--iterations` / `-i` | 50 | Measured kernel launches per test run, per rule. |
| `--test-runs` | 3 | Repeated measurement runs per rule. |
| `--max-words` | 1,000 | Exact test-corpus size and GPU work-items per rule. |
| `--max-test-rules` | 1,000 | Maximum number of benchmarkable rules tested from each file. |
| `--identical-dicts` | Off | Repeat the 16-word seed dictionary instead of generating diverse variants. |
| `--visualize` | Off in CLI | Generate PNG charts and the interactive HTML report. The Control Center enables visualization by default. |
| `--dpi` | 300 | PNG chart resolution. |
| `--visualization-output` | `<output>/visualizations` | Optional separate visualization directory. |
| `--platform` / `--device` | 0 / 0 | OpenCL platform and GPU device indices. |
| `--optimize` | Off | Create the fastest-first timing-budget selection after benchmarking. |
| `--max-optimize-rules` | 500 | Maximum selected rules and default fastest-rule export count in the HTML report. |
| `--max-time` | 30 seconds | Cumulative GPU Kernel Time budget for the optimizer. |

For the full current option list, run `python aether.py --help`.

## 12. How to make meaningful comparisons

For a defensible comparison:

1. Use the same Aether version and the same input rule files.
2. Use the same corpus mode, `--max-words`, `--iterations`, `--test-runs` and `--max-test-rules`.
3. Use the same physical GPU, OpenCL platform/device, driver and runtime. Aether's report records the device name and profiling timer resolution, but not a complete driver/runtime manifest; record those details alongside the report.
4. Compare GPU Kernel Time with GPU Kernel Time. Do not substitute End-to-End Time or add the two values together.
5. Check validation counts first. Two reports that benchmark different subsets of an input file are not directly equivalent.
6. Examine CV, sample size and outlier count before treating small timing differences as meaningful.
7. Repeat measurements when results are close, noisy or important to a decision.

The identical and diverse corpus modes have matched work-item counts and length/character-class profiles, but not identical contents. Rules with data-dependent behavior can therefore perform differently across the modes. Treat mode changes as workload changes, not as a pure hardware comparison.

Aether measurements are specific to its OpenCL implementation. The interpreter's supported operator set, kernel implementation, compiler, OpenCL runtime, GPU architecture and benchmark settings all affect the result. A rule's lower Aether time means it is cheaper in this measured Aether workload; it does not imply that it recovers more passwords or will necessarily be faster in every real Hashcat attack.

## 13. Implementation references

The measurement and validation behavior described here is implemented primarily in:

- `aether.py` — OpenCL kernel, GPU timing, statistical aggregation, operator profiling, reports, charts and fastest-first selection.
- `aether_validation.py` — Hashcat rule syntax checks, Aether compatibility checks and validation artifacts.
- `tests/test_aether_rule_validation.py` — validation categories, source-line handling, supported chains and limits.
- `tests/test_aether_optimized_rule_validation.py` — final optimizer validation and rejected-rule reporting.
- `tests/test_aether_interactive_report_export.py` — interactive report data and fastest-rule export behavior.
