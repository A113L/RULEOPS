"""GPU target-table-backed memory-light CELF selection.

Fast batched GPU scans produce admissible upper bounds (one count per matching
base-word output, so duplicate outputs may overcount but never undercount
unique active targets). Singleton scans use a per-candidate bitmap and return
exact distinct target IDs. CELF only selects a candidate after exact scoring.
"""
from __future__ import annotations

import gc
import heapq
import math
import os
from collections import deque
from contextlib import nullcontext
import sys
import time

import numpy as np
# Keep the custom heartbeat-driven bar (not plain tqdm): CELF rounds can go
# many seconds between .update() calls (one exact GPU word-sweep per round),
# and this bar keeps elapsed/ETA live via a background refresh thread instead
# of looking stalled. Styling below is normalized to match the other phases'
# real-tqdm bars (green desc, cyan postfix, same bar glyphs/format).
from .progress import tqdm, ActivityHeartbeat  # CELF_PROGRESS_DIAGNOSTICS_PATCH_V2
from .profiling import stage_profiler

from .common import (
    MAX_CHAIN_STRING_LEN,
    MAX_HASHCAT_CHAIN,
    bold,
    cyan,
    green,
    log_info,
    log_section,
    log_warn,
    _kb,
)
# CELF_ADAPTIVE_BATCH_PATCH_V4
def _celf_auto_rescore_batch(requested, target_count, gpu_engine=None):
    """Conservative rescore batch: VRAM is not the only cost driver.

    `requested` is the available/preallocated ceiling. `target_count` captures
    per-rule workload; large target universes use smaller speculative batches to
    avoid rescoring hundreds of contenders that CELF may not need.
    """
    try:
        requested = max(1, min(1024, int(requested)))
    except (TypeError, ValueError):
        requested = 32
    try:
        target_count = max(1, int(target_count))
    except (TypeError, ValueError):
        target_count = 1_000_000  # conservative when the count isn't available

    device = getattr(gpu_engine, "device", None) if gpu_engine is not None else None
    if device is None and gpu_engine is not None:
        queue = getattr(gpu_engine, "queue", None)
        device = getattr(queue, "device", None)
    if device is None and gpu_engine is not None:
        context = getattr(gpu_engine, "context", None)
        try:
            devices = getattr(context, "devices", ())
            device = devices[0] if devices else None
        except Exception:
            device = None

    vram = 0
    if device is not None:
        try:
            vram = int(getattr(device, "global_mem_size", 0) or 0)
        except Exception:
            vram = 0
        if not vram and hasattr(device, "get_info"):
            try:
                vram = int(device.get_info(0x101F))  # CL_DEVICE_GLOBAL_MEM_SIZE
            except Exception:
                vram = 0

    gib = 1024 ** 3
    if not vram:
        vram_cap = 32
        vram_label = "unknown"
    elif vram < 4 * gib:
        vram_cap, vram_label = 16, f"{vram / gib:.1f} GiB"
    elif vram < 8 * gib:
        vram_cap, vram_label = 32, f"{vram / gib:.1f} GiB"
    elif vram < 16 * gib:
        vram_cap, vram_label = 64, f"{vram / gib:.1f} GiB"
    elif vram < 24 * gib:
        vram_cap, vram_label = 128, f"{vram / gib:.1f} GiB"
    else:
        vram_cap, vram_label = 256, f"{vram / gib:.1f} GiB"

    # Observed behaviour: on million-entry targets, huge speculative groups
    # (512) were slower than smaller CELF rescores. Keep the cap workload-aware.
    if target_count >= 1_000_000:
        work_cap = 32
    elif target_count >= 100_000:
        work_cap = 32
    elif target_count >= 25_000:
        work_cap = 64
    else:
        work_cap = 128

    chosen = max(1, min(requested, vram_cap, work_cap))
    override = os.environ.get("RULEST_CELF_RESCORE_BATCH_MAX")
    if override:
        try:
            chosen = max(1, min(chosen, int(override)))
        except ValueError:
            pass
    if not getattr(_celf_auto_rescore_batch, "_reported", False):
        print(
            f"[CELF AUTO] rescore batch={chosen} (workspace ceiling={requested}, "
            f"targets={target_count:,}, VRAM={vram_label}, "
            f"caps: VRAM={vram_cap}, workload={work_cap})",
            flush=True,
        )
        _celf_auto_rescore_batch._reported = True
    return chosen


_FNV1A64_OFFSET = 14695981039346656037
_FNV1A64_PRIME = 1099511628211
_UINT64_MASK = (1 << 64) - 1


class _CelfExactBatchMismatch(RuntimeError):
    """Signals that GPU batched exact gains failed winner-scan verification.

    The partially completed greedy run must be discarded and restarted from an
    empty active-target bitmap with batched exact rescoring disabled. Continuing
    with the suspect gains could violate CELF's admissible-bound invariant.
    """



def _fingerprint64(text: str) -> int:
    """Stable 64-bit FNV-1a fingerprint over Rulest's byte encoding (Latin-1)."""
    value = _FNV1A64_OFFSET
    for byte in text.encode("latin-1", errors="strict"):
        value = ((value ^ byte) * _FNV1A64_PRIME) & _UINT64_MASK
    return value


def _splitmix64(value: int) -> int:
    """SplitMix64 finalizer, matching the OpenCL slot mixer."""
    value = (value + 0x9E3779B97F4A7C15) & _UINT64_MASK
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & _UINT64_MASK
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & _UINT64_MASK
    return (value ^ (value >> 31)) & _UINT64_MASK


class _TargetFingerprintIndex:
    """Small CPU helper retained for collision-focused unit tests."""

    def __init__(self, targets, fingerprint_fn=_fingerprint64):
        self.targets = list(targets)
        self.fingerprint_fn = fingerprint_fn
        buckets = {}
        for target_id, target in enumerate(self.targets):
            buckets.setdefault(fingerprint_fn(target), []).append(target_id)
        self.buckets = buckets

    def lookup(self, candidate):
        for target_id in self.buckets.get(self.fingerprint_fn(candidate), ()):
            if self.targets[target_id] == candidate:
                return target_id
        return None


def _rule_cost(rule, cost_alpha, cost_weights=None):
    base = max(1, len(rule.split())) ** float(cost_alpha) if cost_alpha > 0 else 1.0
    if not cost_weights:
        return base
    return base * _rule_profile_multiplier(rule, cost_weights)


def _rule_literal_chars(rule):
    """Literal characters appended/prepended by a rule's `$c` / `^c` tokens --
    the only two-char operator+literal forms rulest.topn_seedgen emits.
    Structural ops (c, u, t, l, :, Tn, ...) contribute nothing and are
    skipped; they get no profile-based cost adjustment."""
    return [token[1] for token in rule.split() if len(token) == 2 and token[0] in "$^"]


def _char_class(ch):
    if ch.isdigit():
        return "digit"
    if ch.isalpha():
        return "letter"
    return "symbol"


def build_profile_cost_weights(profile_summary):
    """Derive a small {'digit'|'letter'|'symbol': multiplier} table from a
    pcfg-profile summary (rulest.topn_seedgen.summarize_pcfg_profile), using
    the same kind of baseline shares as topn_seedgen.profile_informed_priors.
    A class OVER-represented in the corpus relative to the generic baseline
    gets multiplier < 1 (cheaper, so CELF's cost-aware marginal-gain ranking
    favors rules built from it); an UNDER-represented class gets > 1
    (costlier). Clamped so one profile can't make a class free or, at the
    other extreme, effectively unselectable.
    """
    baseline = {"digit": 0.55, "symbol": 0.20, "letter": 0.60}
    observed = {
        "digit": profile_summary.get("digit_share", baseline["digit"]),
        "symbol": profile_summary.get("symbol_share", baseline["symbol"]),
        "letter": profile_summary.get("lowercase_share", baseline["letter"]),
    }
    return {
        cls: min(3.0, max(0.4, base / max(1e-6, observed.get(cls, base))))
        for cls, base in baseline.items()
    }


def _rule_profile_multiplier(rule, cost_weights):
    chars = _rule_literal_chars(rule)
    if not chars:
        return 1.0
    return sum(cost_weights.get(_char_class(ch), 1.0) for ch in chars) / len(chars)


class _ConstantCosts:
    """costs[index] == value for any index, without allocating a len(rules)
    list — used for the (default) cost_alpha<=0 case where every rule's
    cost is the same 1.0."""
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def __getitem__(self, _index):
        return self.value


def _celf_log_interval():
    """Return a bounded heartbeat interval for server and terminal logging."""
    try:
        value = float(os.environ.get("RULEST_CELF_LOG_INTERVAL", "0.5"))
    except (TypeError, ValueError):
        value = 0.5
    return min(10.0, max(0.25, value))


def _rolling_rules_rate_details(samples, count, now, window=30.0):
    """Return smoothed recent rate and its actual sample span."""
    count = int(count)
    if not samples or count > samples[-1][1]:
        samples.append((float(now), count))
    cutoff = float(now) - max(1.0, float(window))
    while len(samples) > 1 and samples[1][0] <= cutoff:
        samples.popleft()
    if len(samples) < 2 or samples[-1][0] < cutoff:
        return 0.0, 0.0
    first_time, first_count = samples[0]
    elapsed = float(now) - max(first_time, cutoff)
    if elapsed <= 1e-9:
        return 0.0, 0.0
    return max(0.0, (count - first_count) / elapsed), elapsed


def _rolling_rules_rate(samples, count, now, window=5.0):
    """Backward-compatible rate-only wrapper used by upper-bound progress."""
    rate, _span = _rolling_rules_rate_details(samples, count, now, window=window)
    return rate


def _format_progress_bar(done, total, width=24):
    """Render an exact fixed-width progress bar for newline-based web logs."""
    total = max(1, int(total))
    done = min(total, max(0, int(done)))
    fraction = done / total
    filled = min(width, int(fraction * width))
    return f"[{('█' * filled)}{('·' * (width - filled))}] {int(round(fraction * 100.0)):3d}%"


def _run_initial_upper_bound_pass(scorer, rules, rule_batch_size):
    """Score every candidate once and stream an exact progress/rate heartbeat.

    Terminal sessions get the normal tqdm bar. In the web server, stderr is a
    pipe, so a newline-based ActivityHeartbeat reports completed candidate
    batches, the exact scanned/total count, percentage, speed, average, recent
    throughput, batch number and ETA to the Live Activity log.
    """
    total = len(rules)
    upper_bounds = [0] * total
    if total == 0:
        return upper_bounds

    batch_size = max(1, int(rule_batch_size))
    is_tty = bool(sys.stderr.isatty())
    started = time.monotonic()
    samples = deque([(started, 0)])
    batch_total = (total + batch_size - 1) // batch_size
    heartbeat_context = (
        nullcontext(None) if is_tty else ActivityHeartbeat(
            "[CELF] Upper-bound pass | initializing",
            interval=_celf_log_interval(),
            line_mode=True,
        )
    )

    with heartbeat_context as heartbeat, tqdm(
        total=total,
        desc=green("[CELF] Upper-bound pass (GPU target-table scan)"),
        unit="rules",
        disable=not is_tty,
        mininterval=0.5,
    ) as progress:
        for start in range(0, total, batch_size):
            if _kb.poll():
                break
            chunk = rules[start:start + batch_size]
            batch_number = start // batch_size + 1
            batch_started = time.monotonic()
            index_scorer = getattr(scorer, "upper_bound_index_batch", None)
            bounds = (
                index_scorer(range(start, start + len(chunk)))
                if index_scorer is not None else scorer.upper_bound_batch(chunk)
            )
            if len(bounds) != len(chunk):
                raise RuntimeError(
                    "CELF upper-bound scorer returned the wrong number of candidates "
                    f"for batch {batch_number}/{batch_total}"
                )
            upper_bounds[start:start + len(chunk)] = [max(0, int(v)) for v in bounds]
            batch_elapsed = max(time.monotonic() - batch_started, 1e-9)
            processed = start + len(chunk)
            now = time.monotonic()
            batch_rate = len(chunk) / batch_elapsed
            avg_rate = processed / max(now - started, 1e-9)
            recent_rate = _rolling_rules_rate(samples, processed, now, window=5.0)
            eta = (total - processed) / avg_rate if avg_rate > 0 else float("inf")
            eta_text = f"{eta:.1f}s" if math.isfinite(eta) else "calculating"
            bar = _format_progress_bar(processed, total)
            status = (
                f"[CELF] Upper-bound pass | {bar} | scanned={processed:,}/{total:,} "
                f"| speed={batch_rate:,.2f} rules/s | avg={avg_rate:,.2f} rules/s "
                f"| recent={recent_rate:,.2f} rules/s | batch={batch_number:,}/{batch_total:,} "
                f"({len(chunk):,} rules) | ETA={eta_text} | elapsed={now - started:.1f}s"
            )
            if heartbeat is not None:
                heartbeat.set_desc(status)
            else:
                progress.update(len(chunk))
                progress.set_postfix(
                    {
                        "speed": f"{batch_rate:,.0f} rules/s",
                        "avg": f"{avg_rate:,.0f} rules/s",
                        "scanned": f"{processed:,}/{total:,}",
                    },
                    refresh=False,
                )

        finished = time.monotonic()
        avg_rate = total / max(finished - started, 1e-9)
        final_status = (
            f"[CELF] Upper-bound pass complete | {_format_progress_bar(total, total)} "
            f"| scanned={total:,}/{total:,} | avg={avg_rate:,.2f} rules/s "
            f"| elapsed={finished - started:.1f}s"
        )
        if heartbeat is not None:
            heartbeat.set_desc(final_status, force=True)
        log_info(final_status)

    return upper_bounds


def _celf_select_from_upper_bounds(
    rules, upper_bounds, target_count, score_fn, budget=None, cost_alpha=0.0,
    on_select=None, score_batch_fn=None, rescore_batch_size=32,
    on_scan_progress=None, score_exact_batch_fn=None,
    capture_exact_winner_fn=None, materialize_winner_ids_fn=None,
    gpu_dispatch_counts_fn=None, cost_weights=None,
):
    """Heap CELF with admissible bounds and optional batched exact rescoring.

    Fast batch scoring counts matching base-word outputs, so duplicates may inflate
    a bound but cannot undercount unique active targets. If `score_exact_batch_fn`
    is supplied, contenders whose tightened bound can still win are exact-rescored
    together using a per-candidate bitmap. GPU callers snapshot the current winner's
    bitmap and compact it to target IDs without another BASE scan. Legacy/CPU callers
    keep the verified singleton-rescore behaviour.
    """
    if len(rules) != len(upper_bounds):
        raise ValueError("rules and upper_bounds must have equal lengths")
    if target_count < 0:
        raise ValueError("target_count cannot be negative")

    limit = len(rules) if budget is None else min(len(rules), max(0, int(budget)))
    covered = np.zeros(int(target_count), dtype=bool)

    # Building `costs` and the heap used to be two plain-Python loops over
    # every candidate with zero progress feedback — on multi-million-rule
    # pools this is exactly the silent gap between the (fast, GPU) upper-bound
    # pass finishing and the first tick of the "CELF GPU recompute" bar.
    # Report it with the same heartbeat spinner used for GPU setup, and skip
    # the per-rule Python cost loop entirely in the common cost_alpha<=0 case
    # (cost is always 1.0, so priority == bound and no per-rule division or
    # function call is needed at all). A supplied cost_weights table (PCFG
    # composition-profile-informed, see build_profile_cost_weights) also
    # needs the per-rule loop even when cost_alpha<=0, since it reads each
    # rule's literal $/^ characters rather than just its chain depth.
    cpu_profile_started = time.perf_counter()
    heap_build_started = time.perf_counter()
    with ActivityHeartbeat(f"[CELF] Building heap ({len(rules):,} candidates)"):
        bounds_arr = np.maximum(0, np.asarray(upper_bounds, dtype=np.int64))
        positive = np.flatnonzero(bounds_arr)
        if cost_alpha <= 0 and not cost_weights:
            # costs[index] is still read later (priority()/push() index into
            # it by full rule index, including rules that start at bound=0
            # but get re-pushed with a tightened bound later), so this needs
            # to stay a full-length, O(1)-indexable sequence either way — it
            # just doesn't need per-rule Python work when cost is always 1.0.
            costs = _ConstantCosts(1.0)
        else:
            costs = []
            for position, rule in enumerate(rules):
                if position % 16384 == 0 and _kb.poll():
                    return [], covered
                costs.append(_rule_cost(rule, cost_alpha, cost_weights))
        if _kb.poll():
            return [], covered
        heap = []
        for position, raw_index in enumerate(positive):
            if position % 16384 == 0 and _kb.poll():
                break
            index = int(raw_index)
            heap.append((-float(bounds_arr[index]) / costs[index], index, int(bounds_arr[index])))
        heapq.heapify(heap)
        if _kb.poll():
            return [], covered
        # Every rule this round can ever select comes from a heap entry, and
        # the heap is only ever seeded from (and re-pushed among) these
        # `positive` indices -- a candidate with bound<=0 never enters it and
        # push() only re-adds indices that were already popped from it. So
        # len(positive) is a true, closed upper bound on how many rules this
        # run could possibly select, even with no --budget. It is normally a
        # loose one (saturation -- overlapping coverage -- almost always
        # stops the run well before every positive-bound candidate gets
        # picked), so an ETA based on it will run noticeably optimistic
        # relative to wall time, but it beats no ETA at all for an unbounded
        # run.
        approx_total_without_budget = int(len(positive)) or None
    heap_build_s = time.perf_counter() - heap_build_started

    batch_size = max(1, int(rescore_batch_size))
    selected = []
    exact_rescored = 0
    exact_gain_only = 0
    exact_batch_candidates = 0
    exact_batches = 0
    exact_scans = 0
    exact_record_scans = 0
    batch_rescored = 0
    upper_bound_candidates = 0
    upper_bound_batches = 0
    recovered = 0
    current_batch_size = 1
    progress_enabled = bool(sys.stderr.isatty())
    last_refresh = [0.0]
    t0 = time.monotonic()
    upper_rate_samples = deque([(t0, 0)])
    last_upper_rate = [0.0]
    post_first_winner_started_at = None
    post_first_winner_exact_baseline = 0
    post_first_winner_selected_samples = deque()
    post_first_winner_rescored_samples = deque()
    first_round_summary = None
    reset_progress_rate_after_update = False

    def _read_gpu_dispatch_counts():
        if gpu_dispatch_counts_fn is None:
            return {"total": 0, "score": 0, "winner_compaction": 0, "clear": 0}
        try:
            counts = gpu_dispatch_counts_fn()
        except Exception as exc:
            log_warn(f"[CELF] Could not read GPU kernel-dispatch counters: {exc}")
            return {"total": 0, "score": 0, "winner_compaction": 0, "clear": 0}
        if not isinstance(counts, dict):
            return {"total": 0, "score": 0, "winner_compaction": 0, "clear": 0}
        return {
            key: max(0, int(counts.get(key, 0)))
            for key in ("total", "score", "winner_compaction", "clear")
        }

    dispatch_counts_at_greedy_start = _read_gpu_dispatch_counts()

    def _steady_metrics(now):
        if post_first_winner_started_at is None:
            return {
                "recent_rule_rate": 0.0, "avg_rule_rate": 0.0,
                "rescored_rate": 0.0, "eta_rate": 0.0,
                "eta_seconds": None, "steady_elapsed": 0.0,
            }
        steady_elapsed = max(1e-9, float(now) - post_first_winner_started_at)
        selected_after_first = max(0, len(selected) - 1)
        recent_rule_rate, _rule_span = _rolling_rules_rate_details(
            post_first_winner_selected_samples, selected_after_first,
            now, window=30.0,
        )
        avg_rule_rate = selected_after_first / steady_elapsed
        rescored_after_first = max(0, exact_scans - post_first_winner_exact_baseline)
        recent_rescored_rate, _rescore_span = _rolling_rules_rate_details(
            post_first_winner_rescored_samples, rescored_after_first,
            now, window=30.0,
        )
        # The post-first-winner average is only a warm-up fallback. Once ten
        # seconds have elapsed, ETA follows the moving window strictly; if no
        # rules were selected in that window, report ETA as still calculating
        # rather than projecting stale cumulative throughput.
        eta_rate = avg_rule_rate if steady_elapsed < 10.0 else recent_rule_rate
        eta_total = limit if budget is not None else approx_total_without_budget
        eta_seconds = None
        if eta_total is not None and eta_rate > 0:
            eta_seconds = max(0, int(eta_total) - len(selected)) / eta_rate
        return {
            "recent_rule_rate": recent_rule_rate,
            "avg_rule_rate": avg_rule_rate,
            "rescored_rate": recent_rescored_rate,
            "eta_rate": eta_rate,
            "eta_seconds": eta_seconds,
            "steady_elapsed": steady_elapsed,
        }

    heap_operation_s = [0.0]
    score_callback_s = [0.0]
    winner_commit_s = [0.0]
    heap_pop_count = [0]
    heap_push_count = [0]

    def _heap_pop():
        started = time.perf_counter()
        try:
            return heapq.heappop(heap)
        finally:
            heap_operation_s[0] += time.perf_counter() - started
            heap_pop_count[0] += 1

    def _heap_push(item):
        started = time.perf_counter()
        try:
            heapq.heappush(heap, item)
        finally:
            heap_operation_s[0] += time.perf_counter() - started
            heap_push_count[0] += 1

    def _capture_winner_bitmap(index):
        if capture_exact_winner_fn is None or score_exact_batch_fn is None:
            return False
        try:
            return bool(capture_exact_winner_fn(int(index)))
        except Exception as exc:
            log_warn(f"[CELF] Could not snapshot exact winner bitmap for candidate {index}: {exc}")
            return False

    # RULEST_CELF_INDETERMINATE_PROGRESS_V1
    # leave/dynamic_ncols/ncols/bar_format used to be passed here as if this
    # were real tqdm, but rulest's own ProgressBar (see progress.py) builds
    # its line -- bar, counts, elapsed<ETA, rate -- and recomputes terminal
    # width itself on every render; it never reads those fields, so passing
    # them was dead weight. `disable` is the one that mattered: it silently
    # did nothing until progress.py was fixed to honor it, so a non-tty
    # stderr (redirected to a log, piped, cron) still got this bar's raw
    # \r/\x1b[K control bytes -- ETA included -- written straight into it.
    celf_bar_desc = "[CELF] GPU recompute" if budget else "[CELF] GPU recompute (approx)"
    heartbeat_context = (
        nullcontext(None) if progress_enabled else ActivityHeartbeat(
            "[CELF] Greedy selection | initializing",
            interval=_celf_log_interval(),
            line_mode=True,
        )
    )
    with heartbeat_context as heartbeat, tqdm(
        total=budget if budget else approx_total_without_budget,
        desc=green(celf_bar_desc), unit="rules",
        disable=not progress_enabled, mininterval=0.5,
    ) as progress:
        def _status_line():
            now = time.monotonic()
            elapsed = max(now - t0, 1e-9)
            selected_pct = 100.0 * len(selected) / max(1, limit)
            coverage_pct = 100.0 * recovered / max(1, target_count)
            last_upper_rate[0] = _rolling_rules_rate(
                upper_rate_samples, upper_bound_candidates, now, window=5.0
            )
            steady = _steady_metrics(now)
            if first_round_summary is None:
                first_round_text = "running"
            else:
                first_round_text = (
                    f"{first_round_summary['elapsed']:.1f}s/"
                    f"{first_round_summary['gpu_dispatches']:,} GPU launches"
                )
            eta_text = (
                f"{steady['eta_seconds']:.1f}s"
                if steady["eta_seconds"] is not None else "calculating"
            )
            return (
                f"[CELF] Greedy selection | selected={len(selected):,}/{limit:,} "
                f"({selected_pct:.1f}%) | rule/s={steady['recent_rule_rate']:,.2f} "
                f"| avg_rule/s={steady['avg_rule_rate']:,.2f} "
                f"| rescored/s={steady['rescored_rate']:,.2f} "
                f"| ETA={eta_text} | first_round={first_round_text} "
                f"| recovered={recovered:,}/{target_count:,} "
                f"({coverage_pct:.1f}%) | heap={len(heap):,} | exact_scans={exact_scans:,} "
                f"| exact_batches={exact_batches:,} | exact_record_scans={exact_record_scans:,} "
                f"| exact_gain_candidates={exact_gain_only + exact_batch_candidates:,} "
                f"| lazy_upper_bound_candidates={upper_bound_candidates:,} "
                f"| lazy_upper_bound_batches={upper_bound_batches:,} "
                f"| lazy_upper_bound_speed={last_upper_rate[0]:,.2f} rules/s "
                f"| batch={current_batch_size} | elapsed={elapsed:.1f}s"
            )

        def report_scan(done=None, total=None):
            if progress_enabled:
                steady = _steady_metrics(time.monotonic())
                postfix = {
                    "selected": cyan(str(len(selected))),
                    "recovered": cyan(f"{recovered:,}"),
                    "rule/s": cyan(f"{steady['recent_rule_rate']:,.1f}"),
                    "avg_rule/s": cyan(f"{steady['avg_rule_rate']:,.1f}"),
                    "rescored/s": cyan(f"{steady['rescored_rate']:,.1f}"),
                    "upper": cyan(f"{upper_bound_candidates:,}"),
                    "exact": cyan(f"{exact_scans:,}"),
                    "batch": cyan(str(current_batch_size)),
                }
                if done is not None and total is not None:
                    postfix["scan words"] = cyan(f"{int(done):,}/{int(total):,}")
                progress.set_postfix(postfix, refresh=False)
                now = time.monotonic()
                if now - last_refresh[0] >= 0.5:
                    progress.refresh()
                    last_refresh[0] = now
            elif heartbeat is not None:
                heartbeat.set_desc(_status_line())

        def exact_score(index):
            # Full exact scan WITH hit-slot recording -- the expensive path
            # (one GPU wordlist pass, synchronous readback of the matched
            # target IDs). This remains the verified compatibility fallback
            # when the GPU winner-bitmap snapshot/compaction path is absent
            # or fails validation; it is not used on the normal GPU path.
            nonlocal exact_rescored, exact_scans, exact_record_scans
            exact_rescored += 1
            exact_scans += 1
            exact_record_scans += 1
            _score_t0 = time.perf_counter()
            try:
                if on_scan_progress is None:
                    ids = score_fn(index, covered)
                else:
                    ids = score_fn(index, covered, report_scan)
            finally:
                score_callback_s[0] += time.perf_counter() - _score_t0
            ids = {
                int(target_id) for target_id in ids
                if 0 <= int(target_id) < target_count and not covered[int(target_id)]
            }
            report_scan()
            return len(ids), ids

        def exact_gain(index):
            """Exact marginal gain for ONE candidate, preferring the cheap
            batched-exact kernel (score_mode=1: deduplicates target IDs but
            never transfers/records them) over the expensive recording scan.

            Returns (gain, ids_or_None). `ids` is None whenever the cheap
            path was used, mirroring the batch-tightening branch below: the
            caller defers materializing target IDs until a candidate is
            confirmed to be the round's actual winner. GPU callers snapshot
            its bitmap and compact it to IDs; compatibility callers retain
            the verified recording-scan fallback.

            This keeps the seed-pop and fresh-contender checks on the cheap
            exact-gain path. Only the selected winner needs IDs, and the GPU
            path obtains them without rescanning BASE.
            """
            nonlocal exact_gain_only, exact_scans, exact_batches
            if score_exact_batch_fn is None:
                return exact_score(index)
            exact_gain_only += 1
            exact_scans += 1
            exact_batches += 1
            _score_t0 = time.perf_counter()
            try:
                if on_scan_progress is None:
                    gains = score_exact_batch_fn([index], covered)
                else:
                    gains = score_exact_batch_fn([index], covered, report_scan)
            finally:
                score_callback_s[0] += time.perf_counter() - _score_t0
            if len(gains) != 1:
                raise RuntimeError("CELF exact batch scorer returned the wrong number of gains")
            report_scan()
            return max(0, int(gains[0])), None

        def priority(bound, index):
            return max(0, int(bound)) / costs[int(index)]

        def can_beat(bound, index, best_gain, best_index):
            p = priority(bound, index)
            best_p = priority(best_gain, best_index)
            return p > best_p or (p == best_p and int(index) < int(best_index))

        def push(index, bound):
            bound = max(0, int(bound))
            if bound:
                _heap_push((-priority(bound, index), int(index), bound))

        while heap and len(selected) < limit:
            # A CELF round is the commit unit. If q arrives while resolving its
            # contenders, discard that unfinished round and keep only the
            # already-committed selection prefix.
            if _kb.poll():
                break
            round_interrupted = False
            # Start each round with the strongest outstanding bound, but never
            # assume that its upper bound is the exact gain.
            _neg_seed_priority, seed_index, _seed_bound = _heap_pop()
            seed_index = int(seed_index)
            # Cheap exact-gain-only check first (see exact_gain()): most
            # seeds popped off a duplicate-heavy raw-bound heap turn out to
            # have a losing or zero exact gain, so this avoids paying for a
            # full hit-recording scan on every single one of them.
            best_gain, best_ids = exact_gain(seed_index)
            best_snapshot_ready = (
                _capture_winner_bitmap(seed_index)
                if best_ids is None and best_gain > 0 else False
            )
            best_index = seed_index
            if best_gain <= 0 and score_exact_batch_fn is not None:
                # A zero-gain seed is common late in duplicate-heavy CELF runs:
                # millions of candidates can retain a positive raw-hit bound
                # after all of their targets have already been covered.  The
                # old loop popped and exact-scored those dead seeds one at a
                # time, paying a GPU enqueue + synchronization per candidate.
                # Once the first seed is proven dead, drain the next candidates
                # in bounded batches: refresh their cheap raw-hit bounds first,
                # then exact-score only the positive challengers together.
                # This is exact (all gains use the same `covered` snapshot), and
                # every surviving exact gain remains an admissible CELF bound.
                while best_gain <= 0 and heap:
                    if _kb.poll():
                        round_interrupted = True
                        break
                    dead_seed_entries = []
                    while heap and len(dead_seed_entries) < batch_size:
                        _neg_p, index, old_bound = _heap_pop()
                        dead_seed_entries.append((int(index), int(old_bound)))
                    if not dead_seed_entries:
                        break

                    dead_seed_indices = [index for index, _bound in dead_seed_entries]
                    current_batch_size = len(dead_seed_indices)
                    batch_rescored += len(dead_seed_indices)
                    if score_batch_fn is not None:
                        _score_t0 = time.perf_counter()
                        try:
                            if on_scan_progress is None:
                                raw_bounds = score_batch_fn(dead_seed_indices, covered)
                            else:
                                raw_bounds = score_batch_fn(dead_seed_indices, covered, report_scan)
                        finally:
                            score_callback_s[0] += time.perf_counter() - _score_t0
                        if len(raw_bounds) != len(dead_seed_entries):
                            raise RuntimeError("CELF batch scorer returned the wrong number of upper bounds")
                        upper_bound_candidates += len(dead_seed_entries)
                        upper_bound_batches += 1
                        upper_rate_samples.append((time.monotonic(), upper_bound_candidates))
                        while len(upper_rate_samples) > 2 and upper_rate_samples[1][0] <= time.monotonic() - 5.0:
                            upper_rate_samples.popleft()
                        dead_exact_entries = [
                            (index, min(old_bound, max(0, int(raw_bound))))
                            for (index, old_bound), raw_bound in zip(dead_seed_entries, raw_bounds)
                            if min(old_bound, max(0, int(raw_bound))) > 0
                        ]
                    else:
                        # Test/compatibility callers may provide only the exact
                        # batch scorer. Their queued bounds are still admissible.
                        dead_exact_entries = dead_seed_entries

                    if dead_exact_entries:
                        exact_indices = [index for index, _bound in dead_exact_entries]
                        _score_t0 = time.perf_counter()
                        try:
                            if on_scan_progress is None:
                                exact_gains = score_exact_batch_fn(exact_indices, covered)
                            else:
                                exact_gains = score_exact_batch_fn(exact_indices, covered, report_scan)
                        finally:
                            score_callback_s[0] += time.perf_counter() - _score_t0
                        if len(exact_gains) != len(dead_exact_entries):
                            raise RuntimeError("CELF exact batch scorer returned the wrong number of gains")
                        exact_batch_candidates += len(dead_exact_entries)
                        exact_scans += len(dead_exact_entries)
                        exact_batches += 1

                        for (index, _bound), raw_exact_gain in zip(dead_exact_entries, exact_gains):
                            gain = max(0, int(raw_exact_gain))
                            if gain <= 0:
                                continue
                            if can_beat(gain, index, best_gain, best_index):
                                if best_gain > 0:
                                    push(best_index, best_gain)
                                best_index, best_gain, best_ids = index, gain, None
                                best_snapshot_ready = _capture_winner_bitmap(index)
                            else:
                                push(index, gain)
                    report_scan()
                if round_interrupted:
                    break

            if best_gain <= 0:
                # The initial seed and every queued candidate in the rescue
                # batches had zero exact marginal gain; all are now safely dead.
                continue
            fresh_this_round = set()

            while heap:
                if _kb.poll():
                    round_interrupted = True
                    break
                _neg_top, top_index, top_bound = heap[0]
                top_index = int(top_index)
                if not can_beat(top_bound, top_index, best_gain, best_index):
                    break

                # A freshly batch-scored contender still has an upper bound, not
                # an exact gain. Evaluate it singly before it can replace winner.
                if top_index in fresh_this_round:
                    _heap_pop()
                    fresh_this_round.remove(top_index)
                    gain, ids = exact_gain(top_index)
                    if gain > best_gain or (gain == best_gain and top_index < best_index):
                        push(best_index, best_gain)  # previous exact winner remains a bound
                        best_index, best_gain, best_ids = top_index, gain, ids
                        best_snapshot_ready = (
                            _capture_winner_bitmap(top_index) if ids is None else False
                        )
                    else:
                        push(top_index, gain)
                    continue

                # Refresh only stale bounds that might still beat the exact best.
                batch_entries = []
                while heap and len(batch_entries) < batch_size:
                    _neg_p, index, old_bound = heap[0]
                    index = int(index)
                    if not can_beat(old_bound, index, best_gain, best_index):
                        break
                    if index in fresh_this_round:
                        break
                    _heap_pop()
                    batch_entries.append((index, int(old_bound)))
                if not batch_entries:
                    # The top should now be a fresh contender; next loop exact-scores it.
                    continue

                batch_indices = [index for index, _ in batch_entries]
                current_batch_size = len(batch_indices)
                batch_rescored += len(batch_indices)
                if score_batch_fn is None:
                    # CPU-only/test fallback has exact scores; keep IDs so it does
                    # not re-run the same candidate as a speculative singleton.
                    for index, _old_bound in batch_entries:
                        gain, ids = exact_score(index)
                        if gain > best_gain or (gain == best_gain and index < best_index):
                            push(best_index, best_gain)
                            best_index, best_gain, best_ids = index, gain, ids
                        else:
                            push(index, gain)
                else:
                    _score_t0 = time.perf_counter()
                    try:
                        if on_scan_progress is None:
                            raw_bounds = score_batch_fn(batch_indices, covered)
                        else:
                            raw_bounds = score_batch_fn(batch_indices, covered, report_scan)
                    finally:
                        score_callback_s[0] += time.perf_counter() - _score_t0
                    if len(raw_bounds) != len(batch_entries):
                        raise RuntimeError("CELF batch scorer returned the wrong number of upper bounds")
                    upper_bound_candidates += len(batch_entries)
                    upper_bound_batches += 1
                    upper_rate_samples.append((time.monotonic(), upper_bound_candidates))
                    while len(upper_rate_samples) > 2 and upper_rate_samples[1][0] <= time.monotonic() - 5.0:
                        upper_rate_samples.popleft()

                    if score_exact_batch_fn is None:
                        # Compatibility path for CPU/tests and callers whose batch
                        # scorer only provides admissible upper bounds.
                        for (index, old_bound), raw_bound in zip(batch_entries, raw_bounds):
                            tightened = min(old_bound, max(0, int(raw_bound)))
                            push(index, tightened)
                            if tightened and can_beat(tightened, index, best_gain, best_index):
                                fresh_this_round.add(index)
                    else:
                        # First tighten every bound cheaply. Only candidates that
                        # can still beat the current exact best pay for bitmap-based
                        # exact scoring. Score those contenders together to avoid
                        # hundreds of thousands of per-candidate GPU synchronizations.
                        exact_entries = []
                        for (index, old_bound), raw_bound in zip(batch_entries, raw_bounds):
                            tightened = min(old_bound, max(0, int(raw_bound)))
                            if tightened and can_beat(tightened, index, best_gain, best_index):
                                exact_entries.append((index, tightened))
                            else:
                                push(index, tightened)

                        if exact_entries:
                            exact_indices = [index for index, _bound in exact_entries]
                            _score_t0 = time.perf_counter()
                            try:
                                if on_scan_progress is None:
                                    exact_gains = score_exact_batch_fn(exact_indices, covered)
                                else:
                                    exact_gains = score_exact_batch_fn(exact_indices, covered, report_scan)
                            finally:
                                score_callback_s[0] += time.perf_counter() - _score_t0
                            if len(exact_gains) != len(exact_entries):
                                raise RuntimeError("CELF exact batch scorer returned the wrong number of gains")
                            exact_batch_candidates += len(exact_entries)
                            exact_scans += len(exact_entries)
                            exact_batches += 1

                            for (index, _bound), raw_exact_gain in zip(exact_entries, exact_gains):
                                tightened_exact_gain = max(0, int(raw_exact_gain))
                                if tightened_exact_gain and can_beat(tightened_exact_gain, index, best_gain, best_index):
                                    # The batch result has an exact gain but not target
                                    # IDs. Preserve the old best as a valid future bound;
                                    # materialize only the final winner's IDs below.
                                    push(best_index, best_gain)
                                    best_index, best_gain, best_ids = index, tightened_exact_gain, None
                                    best_snapshot_ready = _capture_winner_bitmap(index)
                                else:
                                    # Exact current marginal gain remains an admissible
                                    # bound in every later round (coverage only shrinks).
                                    push(index, tightened_exact_gain)
                report_scan()

            if round_interrupted:
                break

            # A score callback may have completed a GPU batch while q arrived.
            # Do not start winner materialization for an interrupted CELF round.
            if _kb.poll():
                break

            # Prefer the preserved exact bitmap from the winning batch. It avoids
            # another full BASE scan and never mutates CELF ordering. Keep the
            # verified recording scan as a fail-safe for older GPU proxies or
            # any bitmap/gain consistency problem.
            if best_ids is None:
                materialized = False
                if best_snapshot_ready and materialize_winner_ids_fn is not None:
                    try:
                        candidate_ids = materialize_winner_ids_fn()
                        if len(candidate_ids) == best_gain:
                            best_ids = candidate_ids
                            materialized = True
                        else:
                            log_warn(
                                "[CELF] Winner bitmap/gain mismatch for candidate "
                                f"{best_index}: bitmap={len(candidate_ids)}, gain={best_gain}; "
                                "using verified recording fallback."
                            )
                    except Exception as exc:
                        log_warn(
                            f"[CELF] Winner bitmap materialization failed for candidate {best_index}: {exc}; "
                            "using verified recording fallback."
                        )
                if not materialized:
                    recorded_gain, best_ids = exact_score(best_index)
                    if recorded_gain != best_gain:
                        raise _CelfExactBatchMismatch(
                            "CELF exact-batch/recording score mismatch for "
                            f"candidate {best_index}: batch={best_gain}, recorded={recorded_gain}"
                        )

            # Materialization/recording can itself take a full GPU scan. Check
            # once more before mutating coverage so q never commits a half-round.
            if _kb.poll():
                break

            # Clear by the winner's exact target IDs, never by a transient buffer.
            _commit_t0 = time.perf_counter()
            covered[np.fromiter(best_ids, dtype=np.int64)] = True
            recovered += len(best_ids)
            if on_select is not None:
                on_select(best_ids)
            selected.append((rules[best_index], len(best_ids)))
            winner_commit_s[0] += time.perf_counter() - _commit_t0
            selection_now = time.monotonic()
            if len(selected) == 1:
                dispatch_after_first = _read_gpu_dispatch_counts()
                first_round_summary = {
                    "elapsed": max(0.0, selection_now - t0),
                    "exact_candidates": int(exact_scans),
                    "exact_batches": int(exact_batches),
                    "exact_record_scans": int(exact_record_scans),
                    "lazy_upper_bound_candidates": int(upper_bound_candidates),
                    "lazy_upper_bound_batches": int(upper_bound_batches),
                    "gpu_dispatches": max(
                        0, dispatch_after_first["total"] - dispatch_counts_at_greedy_start["total"]
                    ),
                    "gpu_score_dispatches": max(
                        0, dispatch_after_first["score"] - dispatch_counts_at_greedy_start["score"]
                    ),
                    "gpu_compaction_dispatches": max(
                        0, dispatch_after_first["winner_compaction"] - dispatch_counts_at_greedy_start["winner_compaction"]
                    ),
                    "gpu_clear_dispatches": max(
                        0, dispatch_after_first["clear"] - dispatch_counts_at_greedy_start["clear"]
                    ),
                }
                log_info(
                    "[CELF] First round complete | "
                    f"winner={rules[best_index]!r} | exact_gain={best_gain:,} | "
                    f"elapsed={first_round_summary['elapsed']:.2f}s | "
                    f"exact_candidates={first_round_summary['exact_candidates']:,} "
                    f"(batches={first_round_summary['exact_batches']:,}, "
                    f"record_scans={first_round_summary['exact_record_scans']:,}) | "
                    f"lazy_upper_bound_candidates={first_round_summary['lazy_upper_bound_candidates']:,} "
                    f"(batches={first_round_summary['lazy_upper_bound_batches']:,}) | "
                    f"gpu_kernel_dispatches={first_round_summary['gpu_dispatches']:,} "
                    f"(score={first_round_summary['gpu_score_dispatches']:,}, "
                    f"winner_compaction={first_round_summary['gpu_compaction_dispatches']:,}, "
                    f"clear={first_round_summary['gpu_clear_dispatches']:,})"
                )
                post_first_winner_started_at = selection_now
                post_first_winner_exact_baseline = int(exact_scans)
                post_first_winner_selected_samples = deque([(selection_now, 0)])
                post_first_winner_rescored_samples = deque([(selection_now, 0)])
                reset_progress_rate_after_update = True
            else:
                steady_selected = max(0, len(selected) - 1)
                if (not post_first_winner_selected_samples or
                        steady_selected > post_first_winner_selected_samples[-1][1]):
                    post_first_winner_selected_samples.append((selection_now, steady_selected))
            if post_first_winner_started_at is not None:
                post_first_winner_rescored = max(
                    0, exact_scans - post_first_winner_exact_baseline
                )
                if (not post_first_winner_rescored_samples or
                        post_first_winner_rescored > post_first_winner_rescored_samples[-1][1]):
                    post_first_winner_rescored_samples.append((selection_now, post_first_winner_rescored))
            progress.update(1)
            if reset_progress_rate_after_update:
                reset_rate_window = getattr(progress, "reset_rate_window", None)
                if callable(reset_rate_window):
                    reset_rate_window()
                    progress.refresh(force=True)
                reset_progress_rate_after_update = False
            report_scan()

    if sum(gain for _, gain in selected) != int(covered.sum()):
        raise RuntimeError("CELF gain accounting disagrees with covered bitmap")
    if os.environ.get("RULEST_CELF_PROFILE") == "1":
        cpu_wall_s = max(0.0, time.perf_counter() - cpu_profile_started)
        controller_other_s = max(
            0.0,
            cpu_wall_s - heap_build_s - heap_operation_s[0]
            - score_callback_s[0] - winner_commit_s[0],
        )
        log_info(
            "[CELF CPU PROFILE] "
            f"wall={cpu_wall_s:.3f}s; heap build={heap_build_s:.3f}s; "
            f"heap push/pop={heap_operation_s[0]:.3f}s "
            f"({heap_push_count[0]:,}/{heap_pop_count[0]:,}); "
            f"score callback wall={score_callback_s[0]:.3f}s; "
            f"winner commit={winner_commit_s[0]:.3f}s; "
            f"controller/progress/other={controller_other_s:.3f}s"
        )
    return selected, covered

def _resolve_single_engine(gpu_engine):
    """CELF selection runs on exactly ONE GPU -- unlike Stage 1/2/Seed
    extraction, it never fans a round's work out across several engines
    (there is only one active hash table / target bitmap, and CELF's
    round-to-round state has to live in one place). A MultiGPUEngine from
    `--device all`/an explicit multi-device list is accepted transparently
    by using its first surviving engine, rather than requiring the caller
    to know to unwrap it -- and if every device became unresponsive during
    an earlier stage (so MultiGPUEngine.engines is empty), this raises a
    clear, actionable RuntimeError here instead of letting a MultiGPUEngine
    fall through to .set_base_words()/.celf_*() calls it never implements,
    which previously surfaced as a confusing
    `AttributeError: 'MultiGPUEngine' object has no attribute 'set_base_words'`
    three frames below the real cause.
    """
    engines = getattr(gpu_engine, 'engines', None)
    if engines is None:
        return gpu_engine  # already a single GPUEngine/ProcessEngineProxy
    if not engines:
        raise RuntimeError(
            "[CELF]  No GPU device is available for selection -- every GPU "
            "became unresponsive during an earlier stage. Re-run with a "
            "single, healthy --device."
        )
    if len(engines) > 1:
        primary = engines[0]
        name = primary.device.name.strip() if getattr(primary, 'device', None) else "device 0"
        log_warn(
            f"[CELF]  Selection runs on a single GPU ({name}); the other "
            f"{len(engines) - 1} device(s) stay idle for this stage."
        )
    return engines[0]


class _GpuExactScorer:
    """Thin adapter around the GPU-resident target table and exact-match kernels."""

    def __init__(self, gpu_engine, base_words, target_words, pair_batch_size, candidate_rules):
        self.gpu_engine = _resolve_single_engine(gpu_engine)
        self.base_words = base_words
        # Keep SharedWordList/other sequence inputs lazy. CELF's target-table
        # builder can consume the shared byte payload and offsets directly; a
        # list() here would decode millions of Python strings and duplicate RAM.
        self.targets = target_words
        self.candidate_rules = candidate_rules if isinstance(candidate_rules, list) else list(candidate_rules)
        self.pair_batch_size = max(1, int(pair_batch_size))
        self.gpu_engine.set_base_words(base_words)
        self.gpu_engine.celf_initialize_target_table(self.targets)
        # Upload the atomic rule pool and every candidate's sequence once.
        self.gpu_engine.celf_prepare_candidate_pool(self.candidate_rules)

    def upper_bound_index_batch(self, candidate_indices):
        """Score a batch by pool index to minimize worker-process IPC payloads."""
        indices = [int(index) for index in candidate_indices]
        if not indices:
            return []
        method = getattr(self.gpu_engine, "celf_score_candidate_indices_gpu", None)
        if method is None:
            return self.upper_bound_batch([self.candidate_rules[index] for index in indices])
        gains, _slots = method(indices, record_hits=False)
        return [int(gain) for gain in gains]

    def upper_bound_batch(self, rules):
        """Return fast admissible upper bounds (raw matching base-word outputs)."""
        if not rules:
            return []
        gains, _slots = self.gpu_engine.celf_score_chains_gpu(rules, record_hits=False)
        return [int(gain) for gain in gains]

    def score_gains_batch(self, rules, progress_callback=None):
        """Return fast admissible upper bounds; duplicates may overcount by design."""
        if not rules:
            return []
        gains, _slots = self.gpu_engine.celf_score_chains_gpu(
            rules, record_hits=False, progress_callback=progress_callback
        )
        return [int(gain) for gain in gains]

    def score_gains_index_batch(self, candidate_indices, progress_callback=None):
        indices = [int(index) for index in candidate_indices]
        if not indices:
            return []
        method = getattr(self.gpu_engine, "celf_score_candidate_indices_gpu", None)
        if method is None:
            return self.score_gains_batch(
                [self.candidate_rules[index] for index in indices], progress_callback
            )
        gains, _slots = method(indices, record_hits=False)
        return [int(gain) for gain in gains]

    def score_exact_gains_batch(self, rules, progress_callback=None):
        """Return exact distinct-target marginal gains for a small candidate batch.

        Unlike the raw-hit upper-bound scan, this mode uses one compact seen
        bitmap per candidate but does not transfer/record target slots. It is
        reserved for candidates whose upper bounds still threaten the winner.
        """
        if not rules:
            return []
        gains, _slots = self.gpu_engine.celf_score_chains_gpu(
            rules, record_hits=False, exact_counts=True,
            progress_callback=progress_callback,
        )
        return [int(gain) for gain in gains]

    def score_exact_gains_index_batch(self, candidate_indices, progress_callback=None):
        indices = [int(index) for index in candidate_indices]
        if not indices:
            return []
        method = getattr(self.gpu_engine, "celf_score_candidate_indices_gpu", None)
        if method is None:
            return self.score_exact_gains_batch(
                [self.candidate_rules[index] for index in indices], progress_callback
            )
        gains, _slots = method(indices, record_hits=False, exact_counts=True)
        return [int(gain) for gain in gains]

    def capture_exact_winner_bitmap(self, candidate_index):
        """Snapshot an exact candidate bitmap on the GPU without host readback."""
        method = getattr(self.gpu_engine, "celf_capture_exact_winner_bitmap", None)
        if method is None:
            return False
        return bool(method(int(candidate_index)))

    def materialize_exact_winner_target_ids(self):
        """Return target IDs from the GPU-compacted preserved winner bitmap."""
        method = getattr(self.gpu_engine, "celf_materialize_winner_target_ids", None)
        if method is None:
            raise RuntimeError("GPU engine does not support winner bitmap compaction")
        return method()

    def score_one_with_targets(self, rule, covered_mask=None, progress_callback=None):
        # If the heap popped the candidate just scored as a singleton, consume
        # its GPU-recorded slots instead of rescanning the complete wordlist.
        cached = self.gpu_engine.celf_take_cached_single_score(rule)
        if cached is None:
            gains, slots = self.gpu_engine.celf_score_chains_gpu(
                [rule], record_hits=True, progress_callback=progress_callback
            )
            gain = int(gains[0]) if len(gains) else 0
        else:
            gain, slots = cached
        target_ids = self.gpu_engine.celf_target_ids_for_slots(slots)
        if covered_mask is not None:
            target_ids = {target_id for target_id in target_ids if not covered_mask[target_id]}
        if len(target_ids) != gain:
            raise RuntimeError(
                f"GPU CELF hit-recording mismatch: gain={gain}, distinct target IDs={len(target_ids)}"
            )
        return gain, target_ids

    def gpu_dispatch_counts(self):
        method = getattr(self.gpu_engine, "celf_dispatch_counts", None)
        if not callable(method):
            return {}
        return method()

    def mark_selected(self, target_ids):
        # Clear the exact target IDs returned by the winner scan. Do not infer
        # the winner from the last scratch hit-slot buffer: later speculative
        # singleton scans may have overwritten it.
        self.gpu_engine.celf_clear_target_ids(target_ids)

    def close(self):
        self.gpu_engine.celf_release_target_table()


def _widen_depth(gpu_engine, rules, requested_depth):
    """Try widening the kernel depth; return (restore_depth, effective_depth)."""
    params = getattr(gpu_engine, "params", None)
    if not isinstance(params, dict):
        return None, max(1, int(requested_depth))
    original = params.get("MAX_CHAIN_DEPTH")
    if not isinstance(original, int) or original <= 0:
        return None, max(1, int(requested_depth))
    needed = max((len(rule.split()) for rule in rules), default=1)
    effective = min(max(int(requested_depth), needed), MAX_HASHCAT_CHAIN)
    if effective <= original:
        return None, original
    try:
        params["MAX_CHAIN_DEPTH"] = effective
        gpu_engine.params = params
        if gpu_engine.compile_kernel(force=True):
            return original, effective
    except Exception as exc:
        log_warn(f"[CELF] Could not widen GPU chain depth: {exc}")
    try:
        params["MAX_CHAIN_DEPTH"] = original
        gpu_engine.params = params
        gpu_engine.compile_kernel(force=True)
    except Exception as exc:
        log_warn(f"[CELF] Failed to restore original GPU depth: {exc}")
    return None, original


def _restore_depth(gpu_engine, restore_depth):
    if restore_depth is None:
        return
    try:
        gpu_engine.params["MAX_CHAIN_DEPTH"] = restore_depth
        gpu_engine.params = gpu_engine.params
        gpu_engine.compile_kernel(force=True)
    except Exception as exc:
        log_warn(f"[CELF] Could not restore GPU chain depth: {exc}")


def select_rules_by_marginal_coverage(
    gpu_engine, base_words, target_words, rules, max_depth, budget=None,
    cost_alpha=0.0, pair_batch_size=100_000, cost_profile=None,
):
    """One GPU upper-bound pass followed by exact batched lazy-greedy CELF recompute.

    `cost_profile`, if given, is a pcfg-profile summary (see
    rulest.topn_seedgen.summarize_pcfg_profile) or a raw ruleops.pcfg-profile.v1
    dict/path/JSON text (summarized here via the same function). It is turned
    into per-character-class cost weights (build_profile_cost_weights) that
    multiply each candidate's cost_alpha-based cost, so CELF's cost-aware
    marginal-gain ranking additionally favors rule literals (digits, letters,
    symbols) in proportion to how common they actually are in the corpus --
    unlike cost_alpha alone, which only looks at chain depth. This changes
    *ranking order*, so it affects which rules make a small cap, not just
    the overall candidate pool PCFG-Lite's seed generator produces.
    """
    cost_weights = None
    if cost_profile is not None:
        if isinstance(cost_profile, dict) and (
            "digit_share" in cost_profile or "symbol_share" in cost_profile
        ):
            profile_summary = cost_profile  # already summarized by the caller
        else:
            from .topn_seedgen import load_pcfg_profile, summarize_pcfg_profile
            profile_summary = summarize_pcfg_profile(load_pcfg_profile(cost_profile))
        cost_weights = build_profile_cost_weights(profile_summary)
    log_section("SELECTION — CELF (GPU hash table + exact batched lazy recompute)")
    if _kb.poll():
        log_warn("[CELF] Early exit before target preparation — skipping GPU selection")
        return [], np.zeros(0, dtype=bool)
    # Keep every target entry supplied by the wordlist, including repeats.
    # Dictionary deduplication is intentionally not part of CELF preparation.
    selection_targets = target_words
    target_count = len(selection_targets)
    empty_mask = np.zeros(target_count, dtype=bool)
    if _kb.poll():
        log_warn("[CELF] Early exit during target preparation — skipping GPU selection")
        return [], empty_mask
    if not rules or not selection_targets or not base_words:
        return [], empty_mask

    deduped_rules = []
    seen_rules = set()
    for position, rule in enumerate(rules):
        if position % 4096 == 0 and _kb.poll():
            log_warn("[CELF] Early exit during candidate preparation — skipping GPU selection")
            return [], empty_mask
        if rule and rule != ":" and rule.split() and rule not in seen_rules:
            seen_rules.add(rule)
            deduped_rules.append(rule)
    rules = []
    for position, rule in enumerate(deduped_rules):
        if position % 4096 == 0 and _kb.poll():
            log_warn("[CELF] Early exit during candidate validation — skipping GPU selection")
            return [], empty_mask
        tokens = rule.split()
        if (sum(len(token) for token in tokens) + max(0, len(tokens) - 1)
                <= MAX_CHAIN_STRING_LEN - 2 and len(tokens) <= MAX_HASHCAT_CHAIN):
            rules.append(rule)
    if not rules:
        log_warn("[CELF] No candidate rules fit the GPU chain limits")
        return [], empty_mask

    # CELF maintains one resident target table/bitmap, so select one engine
    # once and use it consistently for depth changes, scoring, and cleanup.
    # In multi-GPU mode this is a ProcessEngineProxy; it explicitly exposes
    # the CELF RPC surface rather than pretending to be a local GPUEngine.
    selection_engine = _resolve_single_engine(gpu_engine)
    restore_depth, effective_depth = _widen_depth(selection_engine, rules, max_depth)
    if _kb.poll():
        log_warn("[CELF] Early exit after GPU depth setup — skipping scoring")
        _restore_depth(selection_engine, restore_depth)
        return [], empty_mask
    rules = [rule for rule in rules if len(rule.split()) <= effective_depth]
    if not rules:
        _restore_depth(selection_engine, restore_depth)
        return [], empty_mask

    # deduped_rules/seen_rules were only scratch structures for the dedup +
    # chain-limit filtering above; `rules` is the only one still needed.
    # The greedy CELF loop below is the single longest stage in the whole
    # pipeline (can run for hours on millions of candidates), so these two
    # full-size copies -- up to 2x the candidate pool, just sitting idle --
    # must not ride along for the entire run.
    del deduped_rules, seen_rules
    gc.collect()

    scorer = None
    try:
        scorer = _GpuExactScorer(
            selection_engine, base_words, selection_targets, pair_batch_size, rules
        )
        if _kb.poll():
            log_warn("[CELF] Early exit after GPU scorer setup — skipping scoring")
            return [], empty_mask
        upper_bounds = [0] * len(rules)
        celf_engine = scorer.gpu_engine
        seen_words = int(celf_engine._celf_seen_words)
        scratch_limit = max(4, int(celf_engine.params.get("CELF_SEEN_SCRATCH_MB", 32))) * 1024 * 1024
        max_by_scratch = max(1, scratch_limit // max(4, seen_words * 4))
        configured_batch = max(1, int(celf_engine.params.get("CELF_RULE_BATCH_SIZE", 32)))
        rule_batch_size = min(
            configured_batch, max_by_scratch,
            max(1, int(getattr(celf_engine, "_celf_batch_capacity", configured_batch))),
        )

        # Restore the archived CELF selection flow while keeping an exact,
        # web-visible upper-bound progress bar with throughput and ETA.
        upper_bounds = _run_initial_upper_bound_pass(scorer, rules, rule_batch_size)
        if _kb.poll():
            log_warn("[CELF] Early exit after upper-bound scan — skipping greedy rounds")
            return [], empty_mask

        # The exact-rescore batch inside the CELF heap loop stays at a fixed
        # default of 32 — unlike the upper-bound pass's rule_batch_size (and
        # its scratch buffer), which are sized from VRAM in devices.py. The
        # rescore batch only groups candidates for one exact-match kernel
        # launch per heap round; it doesn't benefit from VRAM headroom the
        # way the upper-bound pass's much larger one-shot scan does, so we
        # don't scale it with rule_batch_size any more.
        # RULEST_GREEDY_RESCORE_BATCH still overrides explicitly.
        recompute_batch_size = max(1, int(os.environ.get("RULEST_GREEDY_RESCORE_BATCH", "32")))
        recompute_batch_size = min(recompute_batch_size, rule_batch_size)
        recompute_batch_size = _celf_auto_rescore_batch(recompute_batch_size, target_count, getattr(scorer, 'gpu_engine', None))  # CELF_ADAPTIVE_BATCH_PATCH_V4
        exact_batch_enabled = os.environ.get("RULEST_CELF_EXACT_BATCH", "1").strip().lower() not in {"0", "false", "no", "off"}
        log_info(
            f"[CELF] Candidates: {bold(str(len(rules)))}; targets: {bold(str(target_count))}; "
            f"fast raw-hit upper bounds (duplicates may overcount); lazy heap batch={recompute_batch_size}; "
            f"batched exact challenger rescoring={'enabled' if exact_batch_enabled else 'disabled'}; "
            f"candidate sequences cached on GPU; SplitMix64 table load <= 50%; coverage matrix: {green('none')}"
        )

        def scan_progress(done, total):
            # Updates the persistent CELF progress bar; no nested progress bars.
            return None

        def score_one(rule_index, covered_mask, progress_callback=None):
            _gain, target_ids = scorer.score_one_with_targets(
                rules[rule_index], covered_mask=covered_mask,
                progress_callback=progress_callback or scan_progress,
            )
            return target_ids

        def score_many(rule_indices, covered_mask, progress_callback=None):
            # Fast batched counter intentionally returns upper bounds, not exact gains.
            index_scorer = getattr(scorer, "score_gains_index_batch", None)
            if index_scorer is not None:
                return index_scorer(
                    rule_indices, progress_callback=progress_callback or scan_progress
                )
            return scorer.score_gains_batch(
                [rules[index] for index in rule_indices],
                progress_callback=progress_callback or scan_progress,
            )

        def score_exact_many(rule_indices, covered_mask, progress_callback=None):
            index_scorer = getattr(scorer, "score_exact_gains_index_batch", None)
            if index_scorer is not None:
                return index_scorer(
                    rule_indices, progress_callback=progress_callback or scan_progress
                )
            return scorer.score_exact_gains_batch(
                [rules[index] for index in rule_indices],
                progress_callback=progress_callback or scan_progress,
            )

        try:
            selected, covered = _celf_select_from_upper_bounds(
                rules, upper_bounds, target_count, score_one,
                budget=budget, cost_alpha=cost_alpha,
                on_select=scorer.mark_selected,
                score_batch_fn=score_many,
                rescore_batch_size=recompute_batch_size,
                on_scan_progress=scan_progress,
                score_exact_batch_fn=score_exact_many if exact_batch_enabled else None,
                capture_exact_winner_fn=(
                    getattr(scorer, "capture_exact_winner_bitmap", None)
                    if exact_batch_enabled else None
                ),
                materialize_winner_ids_fn=(
                    getattr(scorer, "materialize_exact_winner_target_ids", None)
                    if exact_batch_enabled else None
                ),
                gpu_dispatch_counts_fn=getattr(scorer, "gpu_dispatch_counts", None),
                cost_weights=cost_weights,
            )
        except _CelfExactBatchMismatch as exc:
            if not exact_batch_enabled:
                raise
            # Never continue with possibly undercounted/overcounted speculative
            # gains: that could silently alter the greedy ordering. Reset the
            # GPU active bitmap to the original universe and rerun the *entire*
            # selection with the older, verified singleton exact-rescore path.
            log_warn(
                f"[CELF] {exc}. Discarding this partial selection, resetting GPU "
                "coverage, and retrying with batched exact rescoring disabled."
            )
            try:
                celf_engine.celf_reset_active_targets()
            except Exception as reset_exc:
                raise RuntimeError(
                    "CELF batched exact scoring failed verification and the GPU "
                    "active-target bitmap could not be reset safely; refusing to "
                    f"continue with potentially incorrect coverage ({reset_exc}). "
                    "Retry with RULEST_CELF_EXACT_BATCH=0."
                ) from reset_exc
            # The epoch/first-touch bitmap path is experimental. A mismatch
            # between batch exact gain and the independently recorded Winner
            # scan means we must not reuse it for the fallback either. The
            # legacy full-buffer clear uses the same exact target-ID bitmap
            # kernel without epochs, so it is safe to retry on the same buffers.
            if bool(getattr(celf_engine, "_celf_lazy_bitmap_init", False)):
                celf_engine._celf_lazy_bitmap_init = False
                log_warn(
                    "[CELF] Disabling experimental lazy bitmap initialization; "
                    "retrying with standard full bitmap clears."
                )
            selected, covered = _celf_select_from_upper_bounds(
                rules, upper_bounds, target_count, score_one,
                budget=budget, cost_alpha=cost_alpha,
                on_select=scorer.mark_selected,
                score_batch_fn=score_many,
                rescore_batch_size=recompute_batch_size,
                on_scan_progress=scan_progress,
                score_exact_batch_fn=None,
                gpu_dispatch_counts_fn=getattr(scorer, "gpu_dispatch_counts", None),
                cost_weights=cost_weights,
            )
        log_info(
            f"[CELF] Selected {bold(str(len(selected)))} rules; exact recovery "
            f"{bold(cyan(f'{int(covered.sum()):,}/{target_count:,}'))}"
        )
        return selected, covered
    finally:
        if scorer is not None:
            try:
                dispatch_counts = scorer.gpu_dispatch_counts()
                if isinstance(dispatch_counts, dict):
                    log_info(
                        "[CELF GPU DISPATCH] Actual OpenCL kernel launches | "
                        f"total={int(dispatch_counts.get('total', 0)):,} | "
                        f"score={int(dispatch_counts.get('score', 0)):,} | "
                        f"winner_compaction={int(dispatch_counts.get('winner_compaction', 0)):,} | "
                        f"clear={int(dispatch_counts.get('clear', 0)):,}"
                    )
            except Exception as exc:
                log_warn(f"[CELF] Could not report GPU kernel-dispatch counters: {exc}")
            try:
                scorer.gpu_engine.celf_report_profile()
            except Exception as exc:
                log_warn(f"[CELF] Could not report GPU profile: {exc}")
            # Fold the same GPU-event breakdown into the unified per-stage
            # profiling table's "Selection (CELF greedy)" row (see cli.py,
            # which wraps this whole function in stage_profiler.track(...))
            # instead of only ever appearing in its own separate block above.
            # Gated on `detailed` since building/formatting this string costs
            # a little extra and is only useful when profiling was asked for.
            if stage_profiler.detailed:
                try:
                    summary = scorer.gpu_engine.celf_profile_summary()
                    if summary:
                        stage_profiler.note("Selection (CELF greedy)", extra=summary)
                except Exception as exc:
                    log_warn(f"[CELF] Could not fold GPU profile into stage table: {exc}")
            try:
                scorer.close()
            except Exception as exc:
                log_warn(f"[CELF] Could not release GPU target table: {exc}")
        _restore_depth(selection_engine, restore_depth)
