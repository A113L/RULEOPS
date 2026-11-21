"""
Command-line entry point: argument parsing and the Stage 0/1/S/2/3 pipeline
summary/report printing that wraps GPUExtractor.extract_rules().
"""
import os
import sys
import gc
import time
import shutil
import argparse
import atexit
import datetime
import multiprocessing as mp
from collections import defaultdict
from pathlib import Path

import numpy as np

from . import state
from .common import (
    print_banner, _print_controls, log_info, log_warn, log_error,
    bold, cyan, green, yellow, red, dim, _kb, safe_worker_count, set_global_seed,
    MAX_HASHCAT_CHAIN, BUILTIN_PROBES, EarlyExitRequested,
)
from .devices import list_devices
from .extractor import GPUExtractor
from .multi_gpu import MultiGPUEngine
from .minimize import minimize_by_signature
from .selection import select_rules_by_marginal_coverage
from .io_utils import load_wordlist
from .profiling import stage_profiler

def main():
    ap = argparse.ArgumentParser(prog='rulest', description='GPU-Compatible Hashcat Rules Engine (optimized)',
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    # Every option below takes a single-letter short form alongside its long
    # name (e.g. --select-budget / -b), normalized the same way -o/--output
    # already worked, so any flag can be used either way. A handful of rare/
    # dangerous switches (--bloom-no-shard, --allow-reject-rules) and the
    # numbered --depthN-chains family intentionally have no short form —
    # one letter per depth (2..10) would eat most of the alphabet for
    # options nobody runs from memory anyway.
    ap.add_argument('base_wordlist', nargs='?')
    ap.add_argument('target_wordlist', nargs='?')
    ap.add_argument('-o','--output', default='rulest_output.txt')
    ap.add_argument('-d', '--device', default=None, metavar='SPEC',
                    help='Device index, name substring, "all" to run every detected GPU in parallel, '
                         'or a comma-separated list of indices (e.g. "0,1") to run only those GPUs in parallel '
                         '(default: auto-select best single GPU)')
    ap.add_argument('-L', '--list-devices', action='store_true')
    ap.add_argument('-m', '--max-depth', type=int, default=2)
    ap.add_argument('-t', '--target-hours', type=float, default=0.5)
    ap.add_argument('-c', '--max-chains', type=int, default=0)
    ap.add_argument('-B', '--bloom-mb', type=int, default=0)
    ap.add_argument('--bloom-no-shard', action='store_true')
    ap.add_argument('-r', '--seed-rules', default=None)
    for i in range(2,11):
        ap.add_argument(f'--depth{i}-chains', type=int, default=None, dest=f'depth{i}_chains')
    ap.add_argument('--allow-reject-rules', action='store_true')
    ap.add_argument('-n', '--no-builtin-seeds', action='store_true')
    topn = ap.add_argument_group('Top-N Seed Injection (in-memory)')
    topn.add_argument('--topn-seeds', action='store_true',
                      help='Generate Top-N seeds from the target wordlist in memory and inject '
                           'them into Stage S / Stage 1 (no intermediate .rule file).')
    topn.add_argument('--topn-n', type=int, default=400000, metavar='N',
                      help='How many top target passwords to analyse (default 400000).')
    topn.add_argument('--topn-max-seeds', type=int, default=150000, metavar='N',
                      help='Max seeds to generate. 0 = unlimited (default 150000).')
    topn.add_argument('--topn-complementary', action='store_true',
                      help='Bias Top-N toward patterns Stage 0 rarely emits '
                           '(leet+year, reverse+digit, transform+year+special, …).')
    topn.add_argument('--topn-no-adaptive-budget', action='store_false', dest='topn_adaptive', default=True,
                      help='Disable data-driven family-budget reallocation for Top-N and use only '
                           'the static priors (adaptive budgeting is on by default).')
    topn.add_argument('--topn-profile', default=None, metavar='PATH',
                      help='Path to a ruleops.pcfg-profile.v1 JSON report (e.g. reports/pcfg.hashmob.medium.json). '
                           'Nudges Top-N family budgets using aggregate composition stats.')
    topn.add_argument('--topn-inject-cap', type=int, default=100000, metavar='N',
                      help='Max Top-N chain seeds injected into Stage S / Stage 2 after quality sort '
                           '(atomic seeds are always kept). 0 = no cap. Default 100000.')
    pt = ap.add_argument_group('STAGE 0 — Token-Strip')
    pt.add_argument('-T', '--token-strip', action='store_true')
    pt.add_argument('--token-strip-min-stem', type=int, default=4)
    pt.add_argument('--token-strip-max-prefix', type=int, default=4)
    pt.add_argument('--token-strip-max-suffix', type=int, default=4)
    pt.add_argument('--token-strip-min-leet-amb', type=int, default=3)
    pt.add_argument('--token-strip-workers', type=int, default=0)
    pt.add_argument('--token-strip-chunk-size', type=int, default=0)
    pt.add_argument('--token-strip-bloom-mb', type=int, default=0,
                    help='Stage 0 base membership: 0 = exact set[str] (default), '
                         '>0 = Bloom filter of this many MB, <0 = auto '
                         '(exact for small bases, ~8 bits/item Bloom for large). '
                         'False positives only cost CPU; every hit is still '
                         'verified by the rule chain.')
    ga = ap.add_argument_group('Genetic Algorithm')
    ga.add_argument('-g', '--genetic', action='store_true')
    ga.add_argument('-G', '--genetic-generations', type=int, default=50)
    ga.add_argument('-P', '--genetic-pop', type=int, default=200)
    ga.add_argument('-E', '--genetic-elite', type=float, default=0.15)
    sel = ap.add_argument_group('Rule Selection (post-processing)')
    sel.add_argument('-M', '--select-mode', choices=['frequency', 'greedy'], default='frequency',
                      help="frequency (default): sort by raw GPU hit count, as before. "
                           "greedy: lazy-greedy (CELF) marginal-coverage selection against "
                           "the real TARGET wordlist — maximizes |union of recovered words| "
                           "per rule budget instead of summed per-rule score.")
    sel.add_argument('-b', '--select-budget', type=int, default=0,
                      help="Max rules to keep with --select-mode greedy (0 = run to "
                           "saturation, i.e. until no remaining rule adds new coverage).")
    sel.add_argument('-s', '--select-budgets', default=None,
                      help="Comma-separated list of budgets (e.g. '100,1000,10000,150000') to "
                           "additionally emit as separate prefix files '<output>.<budget>.txt' "
                           "cut from the same greedy ordering — lets you compare recovery vs. "
                           "budget without rerunning coverage eval for each size.")
    sel.add_argument('-a', '--select-cost-alpha', type=float, default=0.0,
                      help="gain(r) = new_recovery(r) / depth(r)**alpha. 0 (default) = pure "
                           "marginal coverage. >0 favors shorter/cheaper chains among rules "
                           "with similar marginal gain.")
    sel.add_argument('--select-cost-profile', type=Path, default=None,
                      help="Optional ruleops.pcfg-profile.v1 JSON report (see run_pcfg_profile.py "
                           "/ --pcfg-profile on run_topn_seedgen.py). Multiplies each candidate's "
                           "cost by how over/under-represented its literal digit/letter/symbol "
                           "characters are in this corpus, so CELF's cost-aware ranking -- which "
                           "decides what actually lands in a small --select-budget, unlike the "
                           "seed pool's own family budgets once that pool is generated unlimited "
                           "-- favors characteristically common, cheap literals over rare ones. "
                           "Works with or without --select-cost-alpha (chain-depth cost).")
    sel.add_argument('-e', '--exact-recovery', action='store_true',
                      help="Explicitly report exact distinct target-word recovery after greedy "
                           "selection. Greedy coverage is already exact: bloom-positive GPU "
                           "hits are resolved through the exact verification kernel before CELF "
                           "selection, so this flag adds reporting only (no second GPU pass).")
    ap.add_argument('-S', '--seed', type=int, default=None, metavar='N',
                    help='RNG seed. With a fixed --seed, repeated runs on the same BASE/TARGET '
                         'wordlists and the same other flags produce identical output (same rules, '
                         'same order): the genetic algorithm, chain sampling and any other '
                         'randomized step become deterministic, and so does Python\'s string-hash-'
                         'dependent set ordering (this flag re-execs the process once, early, with '
                         'PYTHONHASHSEED fixed accordingly). Default: unset = a different, random '
                         'sequence every run, as before. Note GPU floating-point reduction order can '
                         'in rare cases still vary independently of this flag.')
    ap.add_argument('-D', '--debug', action='store_true')
    ap.add_argument('-p', '--profile', action='store_true',
                    help='Enable profiling: prints a per-stage wall-clock breakdown table '
                         '(STAGE 0-3, bloom build, minimization, selection/CELF) at the end '
                         'of the run, with GPU-level CELF detail folded into the Selection '
                         'row. Equivalent to setting RULEST_PROFILE=1 (and implies the finer '
                         'RULEST_CELF_PROFILE=1 GPU-event accounting); use for tuning, not '
                         'for normal runs, since the CELF side adds a little per-call overhead.')
    args = ap.parse_args()

    if args.select_cost_profile is not None and not args.select_cost_profile.is_file():
        log_error(f"--select-cost-profile not found: {args.select_cost_profile}")
        sys.exit(1)

    if args.seed is not None:
        # Python randomizes str/bytes hashing per-process (PYTHONHASHSEED),
        # which changes the iteration order of plain set()s (rule chains are
        # frequently deduped/collected into a set() before being consumed) —
        # dicts are insertion-ordered and unaffected, but sets aren't. That
        # can't be fixed by calling random.seed()/np.random.seed() after the
        # fact; the interpreter has to start with PYTHONHASHSEED already set.
        # So: re-exec ourselves, once, with it pinned to a value derived from
        # --seed, before doing anything else. The guard on os.environ avoids
        # re-execing forever if it's already set correctly (e.g. the user set
        # it in their shell, or this *is* the re-exec).
        _wanted_hashseed = str(args.seed % (2**32))
        if os.environ.get('PYTHONHASHSEED') != _wanted_hashseed:
            os.environ['PYTHONHASHSEED'] = _wanted_hashseed
            os.execv(sys.executable, [sys.executable] + sys.argv)
        set_global_seed(args.seed)

    state.RNG_SEED = args.seed
    state.ALLOW_REJECT_RULES = args.allow_reject_rules
    state.VERBOSE = args.debug
    # Single switch for every profiling signal in the pipeline: the always-cheap
    # per-stage wall-clock table (STAGE 0-3, bloom build, minimize, selection) and
    # the heavier per-call GPU-event CELF accounting inside gpu_engine.py, which is
    # itself gated on this same env var so it stays off unless asked for. Either the
    # flag (-p/--profile) or the env var (for scripted/GUI launches that don't go
    # through argparse) turns both on together -- no more needing to know there
    # were two switches.
    profiling_on = args.profile or os.environ.get("RULEST_PROFILE") == "1" or \
                   os.environ.get("RULEST_CELF_PROFILE") == "1"
    if profiling_on:
        os.environ["RULEST_CELF_PROFILE"] = "1"
    stage_profiler.configure(profiling_on)
    print_banner()
    _print_controls()
    if args.list_devices: list_devices(); sys.exit(0)
    if not args.base_wordlist or not args.target_wordlist:
        ap.print_help(); print(); log_error("Both BASE and TARGET wordlists required"); sys.exit(1)
    if args.max_depth > MAX_HASHCAT_CHAIN:
        log_warn(f"Depth capped to {MAX_HASHCAT_CHAIN}"); args.max_depth=MAX_HASHCAT_CHAIN
    elif args.max_depth<1: log_error("--max-depth >=1"); sys.exit(1)

    log_info(f"  base      : {bold(args.base_wordlist)}")
    log_info(f"  target    : {bold(args.target_wordlist)}")
    shard_note = yellow('[sharding forced off]') if args.bloom_no_shard else dim('(auto: shard if >512MB)')
    log_info(f"  depth     : {bold(str(args.max_depth))}  |  hours: {bold(str(args.target_hours))}  |  bloom: {bold(str(args.bloom_mb or 'auto'))}MB  {dim('(GPU-only)')}  {shard_note}")
    if args.seed_rules: log_info(f"  seeds     : {bold(args.seed_rules)}")
    if getattr(args, "topn_seeds", False):
        mode = "complementary" if getattr(args, "topn_complementary", False) else "standard"
        prof = getattr(args, "topn_profile", None)
        prof_note = f"  profile={prof}" if prof else ""
        cap = getattr(args, "topn_inject_cap", 100000)
        cap_note = f", inject_cap={cap:,}" if cap and cap > 0 else ", inject_cap=none"
        log_info(f"  topn      : {green('enabled')} [{mode}] — in-memory injection "
                 f"(top_n={getattr(args,'topn_n',400000):,}, max_seeds={getattr(args,'topn_max_seeds',150000):,}{cap_note}){prof_note}")
    if args.seed is not None:
        log_info(f"  rng seed  : {bold(str(args.seed))}  {dim('(deterministic — reruns on the same data will match)')}")
    print()

    _EXCL = dim('[time budget: excluded]')
    _INCL = dim('[time budget: included]')

    if args.token_strip:
        _inj = green('→ STAGE S sbd → STAGE 2') if not args.no_builtin_seeds else yellow('→ STAGE 1 only → STAGE 2')
        bloom_desc = args.token_strip_bloom_mb
        if bloom_desc == 0:
            bloom_desc = 'exact'
        elif bloom_desc < 0:
            bloom_desc = 'auto'
        else:
            bloom_desc = f'{bloom_desc}MB'
        log_info(f"  {bold(cyan('STAGE 0'))}  : {green('enabled')} — CPU exact-match (core+insert)  min-stem={args.token_strip_min_stem}  prefix={args.token_strip_max_prefix}  suffix={args.token_strip_max_suffix}  leet-amb={args.token_strip_min_leet_amb}  workers={safe_worker_count(args.token_strip_workers or mp.cpu_count())}  bloom={bloom_desc}  {_inj}  {_EXCL}")
    else:
        log_info(f"  {bold(dim('STAGE 0'))}  : {red('disabled')}")

    log_info(f"  {bold(cyan('STAGE 1'))}  : {green('enabled')} — single-rule GPU sweep  {_INCL}")

    if not args.no_builtin_seeds:
        log_info(f"  {bold(cyan('STAGE S'))}  : {green('enabled')} — numeric/pattern seed families A-Q  {_EXCL}")
    else:
        log_info(f"  {bold(dim('STAGE S'))}  : {red('disabled')}  (--no-builtin-seeds)")

    log_info(f"  {bold(cyan('STAGE 2'))}  : {green('enabled')} — rule-chain GPU search  depth 2-{args.max_depth}  {_INCL}")

    if args.genetic:
        if not 0.0<args.genetic_elite<1.0: log_error("--genetic-elite must be between 0 and 1"); sys.exit(1)
        log_info(f"  {bold(cyan('STAGE 3'))}  : {green('enabled')} — genetic algorithm  pop={args.genetic_pop}  gen={args.genetic_generations}  elite={args.genetic_elite:.0%}  {_INCL}")
    else:
        log_info(f"  {bold(dim('STAGE 3'))}  : {red('disabled')}  (--genetic to enable)")

    if args.select_mode == 'greedy':
        budget_note = 'unbounded (saturation)' if args.select_budget <= 0 else f'{args.select_budget:,}'
        log_info(f"  {bold(cyan('SELECT'))}  : {green('greedy')} — CELF marginal-coverage over real TARGET  "
                 f"budget={budget_note}  cost_alpha={args.select_cost_alpha}")
        if args.select_cost_profile:
            log_info(f"            cost profile: {args.select_cost_profile} "
                     f"(digit/letter/symbol literals cost-weighted by corpus composition)")
        if args.select_budgets:
            log_info(f"            budget sweep: {args.select_budgets}")
    else:
        log_info(f"  {bold(dim('SELECT'))}  : {dim('frequency')} — sort by raw GPU hit count (--select-mode greedy to enable)")
    print()

    # Start the one run-wide controller before reading either corpus. The
    # same control stream is inherited by Stage 0, minimizer and GPU workers.
    _kb.start()
    atexit.register(_kb.stop)

    # Keep both corpora resident in Shared Memory. The loader also checks the
    # shared controller between file blocks, so q can stop this phase cleanly.
    base_words = None
    target_words = None
    try:
        base_words = load_wordlist(
            args.base_wordlist,
            retain_membership_index=bool(args.token_strip and args.token_strip_bloom_mb == 0),
        )
        target_words = load_wordlist(args.target_wordlist)
    except EarlyExitRequested:
        log_warn("[QUIT] Early exit during wordlist loading — no rules had been generated")
        for _wordlist in (base_words, target_words):
            close_wordlist = getattr(_wordlist, "close", None)
            if callable(close_wordlist):
                try:
                    close_wordlist()
                except Exception:
                    pass
        _kb.stop()
        return
    print()
    if _kb.poll():
        log_warn("[QUIT] Early exit after wordlist loading — GPU initialization skipped")
        for _wordlist in (base_words, target_words):
            close_wordlist = getattr(_wordlist, "close", None)
            if callable(close_wordlist):
                try:
                    close_wordlist()
                except Exception:
                    pass
        _kb.stop()
        return

    t_start = time.time()
    stage_profiler.begin_run()
    extractor = GPUExtractor(
        len(base_words), len(target_words), args.max_depth, args.device,
        args.target_hours, args.max_chains, args.seed_rules, args.bloom_mb,
        builtin_seeds=not args.no_builtin_seeds,
        bloom_no_shard=args.bloom_no_shard, genetic=args.genetic,
        genetic_generations=args.genetic_generations, genetic_pop=args.genetic_pop,
        genetic_elite=args.genetic_elite, token_strip=args.token_strip,
        token_strip_min_stem=args.token_strip_min_stem,
        token_strip_max_prefix=args.token_strip_max_prefix,
        token_strip_max_suffix=args.token_strip_max_suffix,
        token_strip_min_leet_amb=args.token_strip_min_leet_amb,
        token_strip_workers=args.token_strip_workers,
        token_strip_chunk_size=args.token_strip_chunk_size,
        token_strip_bloom_mb=args.token_strip_bloom_mb,
        rng_seed=args.seed,
        topn_seeds=args.topn_seeds,
        topn_n=args.topn_n,
        topn_max_seeds=args.topn_max_seeds,
        topn_complementary=args.topn_complementary,
        topn_adaptive=args.topn_adaptive,
        topn_profile=getattr(args, "topn_profile", None),
        topn_inject_cap=getattr(args, "topn_inject_cap", 100000),
    )
    depth_overrides = {f'depth{i}_override': getattr(args, f'depth{i}_chains') for i in range(2,11)}
    # Greedy CELF selection (below) still needs one live GPU from this same
    # pool: it runs after extract_rules() returns, on extractor.gpu_engine
    # directly (CELF is single-GPU only -- see _resolve_single_engine in
    # selection.py -- but it reuses whichever device survived extraction
    # rather than opening a second one). So a MultiGPUEngine must NOT be
    # shut down here when selection is still going to use it: doing so
    # used to terminate every worker process right after Stage 0-3 and
    # leave Selection holding a dead engine, surfacing later as either a
    # hang or an unrelated-looking AttributeError deep in _GpuExactScorer.
    # Non-greedy ('frequency') mode never touches the GPU again, so it's
    # still safe -- and good practice -- to free the pool immediately.
    try:
        raw_counts = extractor.extract_rules(base_words, target_words, **depth_overrides)
    finally:
        if isinstance(extractor.gpu_engine, MultiGPUEngine) and (args.select_mode != 'greedy' or _kb.quit_requested):
            extractor.gpu_engine.shutdown()
    # Keep keyboard listener alive through minimize + coverage + CELF +
    # local-search so [p]/[r]/[q] work on every stage, not only STAGE 0–3.

    if args.select_mode != 'greedy' or _kb.quit_requested:
        # Frequency mode / an early-quit greedy run no longer touches either corpus after extraction/minimize
        # input collection. Release engine caches/callbacks before closing the
        # shared segments, then free both wordlists before the expensive
        # minimization pass (important for 400MB+ TARGET files).
        gpu_engine = getattr(extractor, "gpu_engine", None)
        if gpu_engine is not None:
            try:
                release = getattr(gpu_engine, "release_run_references", None)
                if callable(release):
                    release()
            except Exception as exc:
                log_warn(f"[RAM] Could not release GPU word references: {exc}")
        for _wordlist_name, _wordlist in (("base_words", base_words), ("target_words", target_words)):
            close_wordlist = getattr(_wordlist, "close", None)
            if callable(close_wordlist):
                try:
                    close_wordlist()
                except Exception as exc:
                    log_warn(f"[RAM] Could not close {_wordlist_name}: {exc}")
        del target_words
        gc.collect()
    if _kb.quit_requested: log_warn("[QUIT]  Early exit — saving partial results")
    raw_candidate_count = len(raw_counts)
    log_info(f"\n[GPU]  Raw bloom-filter candidates: {bold(cyan(str(raw_candidate_count)))}"); print()

    if _kb.quit_requested:
        log_warn("[MIN] Skipped — early exit requested; preserving discovered candidates without deduplication")
        final_counts = raw_counts
        stage_profiler.note("Minimization (dedup)", extra="skipped: early exit")
    else:
        with stage_profiler.track("Minimization (dedup)", unit="rule") as _mint:
            final_counts = minimize_by_signature(raw_counts, BUILTIN_PROBES)
            _mint.set_count(raw_candidate_count)
    if ':' not in final_counts: final_counts[':'] = 0

    # The raw Counter can contain millions of Python dict entries.  It is no
    # longer needed once minimization has returned; keeping it alive through
    # CELF unnecessarily doubles a large part of the rule-count memory.
    del raw_counts
    gc.collect()

    if args.select_mode == 'greedy' and _kb.quit_requested:
        # A quit can arrive during minimization, after the extraction cleanup
        # branch above. CELF will be skipped, so release its retained inputs now.
        gpu_engine = getattr(extractor, "gpu_engine", None)
        if isinstance(gpu_engine, MultiGPUEngine):
            gpu_engine.shutdown()
        if gpu_engine is not None:
            try:
                release = getattr(gpu_engine, "release_run_references", None)
                if callable(release):
                    release()
            except Exception as exc:
                log_warn(f"[RAM] Could not release GPU references after early quit: {exc}")
        for _wordlist_name, _wordlist in (("base_words", base_words), ("target_words", target_words)):
            close_wordlist = getattr(_wordlist, "close", None)
            if callable(close_wordlist):
                try:
                    close_wordlist()
                except Exception as exc:
                    log_warn(f"[RAM] Could not close {_wordlist_name} after early quit: {exc}")
        target_words = None
        gc.collect()

    depth_dist = defaultdict(int)
    for index, r in enumerate(final_counts):
        if index % 16384 == 0 and _kb.poll():
            break
        if r != ':': depth_dist[len(r.split())] += 1
    ds = '  '.join(f"d{d}:{depth_dist[d]:,}" for d in sorted(depth_dist))
    final_rules = len(final_counts) - (1 if ':' in final_counts else 0)
    removed = raw_candidate_count - len(final_counts)

    # Greedy CELF consumes the rule pool directly; sorting millions of rules
    # by frequency here was unused work and an avoidable large temporary list.
    si = None
    if args.select_mode != 'greedy' or _kb.quit_requested:
        si = (
            list(final_counts.items())
            if _kb.quit_requested else
            sorted(final_counts.items(), key=lambda kv: (-kv[1], len(kv[0].split()), kv[0]))
        )
        if _kb.quit_requested and si:
            # Sorting is a single C/Python sort operation, so it cannot be
            # interrupted mid-flight. Switch back to discovery order as soon
            # as it returns, then skip every later expensive selection phase.
            si = None
            si = list(final_counts.items())
    def _write_ruleset_file(path, ordered_rules, sort_desc, extra_header=None):
        quit_at_write_start = _kb.quit_requested
        with open(path, 'w', encoding='utf-8') as f:
            f.write("# rulest — GPU-Compatible Hashcat Rules Engine (optimized)\n")
            f.write(f"# Generated      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Base           : {os.path.basename(args.base_wordlist)}\n")
            f.write(f"# Target         : {os.path.basename(args.target_wordlist)}\n")
            f.write(f"# Depth          : 1-{args.max_depth}\n")
            bloom_mb = args.bloom_mb if args.bloom_mb>0 else "auto"
            f.write(f"# Bloom          : {bloom_mb} MB  (sharding: {'disabled' if args.bloom_no_shard else 'auto'})\n")
            f.write(f"# STAGE 0        : core + insert mode  GPU-verified candidates\n")
            if args.genetic:
                f.write(f"# STAGE 3 GA     : pop={args.genetic_pop}  gen={args.genetic_generations}  elite={args.genetic_elite:.0%}\n")
            f.write("#\n")
            f.write(f"# GPU raw candidates      : {raw_candidate_count:,}\n")
            f.write("# Minimization            : in-memory offset index (compact records)\n")
            f.write(f"#   Probe words           : {len(BUILTIN_PROBES)}  (built-in)\n")
            f.write(f"#   Equiv. rules removed  : {removed:,}\n")
            f.write("#\n")
            f.write(f"# Rules kept     : {len(ordered_rules):,}\n")
            f.write(f"# Sorted by      : {sort_desc}\n")
            if extra_header:
                for line in extra_header:
                    f.write(f"# {line}\n")
            if _kb.quit_requested:
                f.write("# EARLY EXIT: partial run; remaining work was skipped.\n")
            f.write(":\n")
            written = 0
            for index, r in enumerate(ordered_rules):
                if not quit_at_write_start and index % 8192 == 0 and _kb.poll():
                    break
                if r != ':':
                    f.write(f"{r}\n")
                    written += 1
            if written < len(ordered_rules) and _kb.quit_requested:
                f.write(f"# EARLY EXIT: wrote {written:,} of {len(ordered_rules):,} requested rules.\n")
            return written

    if args.select_mode == 'greedy' and not _kb.quit_requested:
        if isinstance(extractor.gpu_engine, MultiGPUEngine) and not extractor.gpu_engine.engines:
            log_error("[GPU]  No GPU device is available for selection -- every GPU "
                      "became unresponsive during extraction. Re-run with a single, "
                      "healthy --device.")
            sys.exit(1)
        candidate_rules = [r for r in final_counts if r != ':']
        # load_wordlist preserves every valid wordlist entry, including repeats.
        n_target = len(target_words)
        budget = args.select_budget if args.select_budget > 0 else None

        try:
            with stage_profiler.track("Selection (CELF greedy)", unit="candidate") as _selt:
                selected, covered_mask = select_rules_by_marginal_coverage(
                    extractor.gpu_engine,
                    base_words,
                    target_words,
                    candidate_rules,
                    args.max_depth,
                    budget=budget,
                    cost_alpha=args.select_cost_alpha,
                    cost_profile=args.select_cost_profile,
                )
                _selt.set_count(len(candidate_rules))
        finally:
            if isinstance(extractor.gpu_engine, MultiGPUEngine):
                extractor.gpu_engine.shutdown()

        if _kb.quit_requested and not selected:
            log_warn("[CELF] Early exit before the first winner — saving discovered candidates in discovery order")
            ordered_rules = [rule for rule in final_counts if rule != ':']
            top_selected = None
            sort_desc = "discovery order (early quit before greedy winner)"
        else:
            ordered_rules = [rule for rule, _gain in selected]
            top_selected = list(selected)
            sort_desc = (
                f"greedy marginal coverage (CELF upper-bound + GPU recompute, "
                f"cost_alpha={args.select_cost_alpha})"
            )
        # candidate_rules was only needed to build the CELF input above;
        # both branches have now resolved ordered_rules from it (or from
        # final_counts directly, on an early quit). final_counts itself is
        # still read by the end-of-run summary below, but this duplicate
        # multi-million-entry list is pure dead weight for the rest of the
        # run (output writing + any --select-budgets sweep below).
        del candidate_rules
        gc.collect()
        n_covered = int(covered_mask.sum())
        recovery_pct = n_covered / max(1, n_target)
        extra_header = [
            f"SELECT mode     : greedy (budget="
            f"{'unbounded/saturation' if budget is None else budget})",
            f"Target recovery : {n_covered:,}/{n_target:,} "
            f"({recovery_pct:.2%}) (exact distinct target coverage)",
        ]
        if _kb.quit_requested:
            extra_header.append("EARLY EXIT       : partial greedy selection stopped at a safe batch boundary")
        if args.exact_recovery:
            extra_header.append(
                f"Exact recovery  : {n_covered:,}/{n_target:,} "
                f"({recovery_pct:.2%}) (GPU exact verification; no coverage matrix)"
            )

        output_rules_written = _write_ruleset_file(args.output, ordered_rules, sort_desc, extra_header)
        log_info(
            f"[OUT] Greedy ruleset written to: {bold(args.output)} "
            f"({bold(str(output_rules_written))} rules written, recovery {bold(f'{recovery_pct:.2%}')})"
        )

        if args.select_budgets and not _kb.quit_requested:
            budgets = sorted({
                int(value) for value in args.select_budgets.split(',')
                if value.strip() and int(value) > 0
            })
            base, ext = os.path.splitext(args.output)
            ext = ext or '.txt'
            print()
            log_info(
                f"[OUT] Budget sweep — cutting the same greedy ordering at {len(budgets)} sizes:"
            )
            for size in budgets:
                sub = ordered_rules[:size]
                # CELF marginal gains are disjoint increments, so their sum
                # yields exact union recovery for each prefix.
                n_sub_covered = sum(gain for _rule, gain in selected[:size])
                sub_pct = n_sub_covered / max(1, n_target)
                sub_path = f"{base}.{size}{ext}"
                sub_extra = [
                    f"SELECT mode     : greedy (budget={size}, prefix of full greedy ordering)",
                    f"Target recovery : {n_sub_covered:,}/{n_target:,} ({sub_pct:.2%})",
                ]
                _write_ruleset_file(
                    sub_path, sub,
                    f"greedy marginal coverage (CELF GPU recompute), budget={size}",
                    sub_extra,
                )
                log_info(
                    f"       budget={size:>9,} rules={len(sub):>9,} "
                    f"recovery={sub_pct:.2%} -> {sub_path}"
                )

        del target_words
        gc.collect()
    else:
        ordered_rules = [r for r, _ in si if r != ':']
        # si is fully superseded by ordered_rules now (final_counts is
        # still needed below for the end-of-run frequency summary) --
        # drop this duplicate multi-million-entry (rule, count) list.
        del si
        gc.collect()
        top_selected = None  # frequency mode: final summary uses GPU hit counts
        if _kb.quit_requested:
            sort_desc = "discovery order (frequency sort / greedy selection skipped by early quit)"
            extra_header = ["EARLY EXIT       : remaining selection and sorting skipped; discovered candidates saved"]
        else:
            sort_desc = "GPU frequency (descending, UTF-8)"
            extra_header = None
        output_rules_written = _write_ruleset_file(args.output, ordered_rules, sort_desc, extra_header)
        log_info(f"[OUT]  Rules written to: {bold(args.output)} ({output_rules_written:,} rules)")

        if args.select_budgets and not _kb.quit_requested:
            # Cut the SAME frequency-descending ordering at the same sizes
            # used for the greedy budget sweep, so benchmark runs compare
            # like-for-like rule-COUNT (not "whatever frequency mode felt
            # like keeping"). No coverage/recovery % here — frequency mode
            # never builds the coverage matrix (that's greedy-only, and
            # expensive); if you need recovery numbers for frequency-mode
            # prefixes too, run them through evaluate_full_coverage
            # separately (or just diff actual hashcat/john crack counts
            # between the two rulesets, which is presumably the point of
            # the benchmark anyway).
            budgets = sorted({int(b) for b in args.select_budgets.split(',') if b.strip()})
            base, ext = os.path.splitext(args.output)
            ext = ext or '.txt'
            print()
            log_info(f"[OUT]  Budget sweep — cutting the same frequency ordering at {len(budgets)} sizes:")
            for b in budgets:
                sub = ordered_rules[:b]
                sub_path = f"{base}.{b}{ext}"
                sub_extra = [
                    f"SELECT mode     : frequency (budget={b}, prefix of full frequency ordering)",
                ]
                _write_ruleset_file(sub_path, sub, f"GPU frequency (descending, UTF-8), budget={b}", sub_extra)
                log_info(f"       budget={b:>9,}  rules={len(sub):>9,}  -> {sub_path}")

    elapsed = time.time()-t_start
    stage_profiler.report()
    sep = '─' * shutil.get_terminal_size((80,24)).columns
    print()
    log_info(cyan(sep))
    log_info(f"  {bold('DONE')}  rulest finished in {bold(f'{elapsed:.1f}s')}")
    log_info(cyan(sep))
    log_info(f"  GPU raw candidates : {bold(str(raw_candidate_count))}")
    log_info(f"  Rules kept         : {bold(green(str(final_rules)))}  {dim('('+ds+')')}")
    log_info(f"  Rules removed      : {bold(red(str(removed)))}")
    log_info(f"  Output file        : {bold(args.output)}")
    log_info(cyan(sep))
    if args.select_mode == 'greedy' and top_selected:
        # Show the greedy (or greedy+local-search) selection order — the
        # rules that actually made it into the output ruleset, ranked by
        # the order CELF picked them (plain greedy) or by each rule's final
        # since swaps happen in place and no longer leave position
        # meaningful — see local_search_improve()'s docstring). Gain is the
        # CELF marginal coverage at selection time for plain greedy, or
        # that same final exclusive-contribution count after local search.
        top = top_selected[:20]
        label = "greedy selection order"
        print(); log_info(f"  Top {len(top)} rules by {label}:")
        for i, (r, gain) in enumerate(top, 1):
            if isinstance(gain, (int, float)) and gain > 0:
                gain_s = f"{gain:.2f}" if isinstance(gain, float) else str(int(gain))
            else:
                gain_s = "—"
            freq = final_counts.get(r, 0)
            log_info(
                f"  {dim(str(i).rjust(3)+'.')}  {dim(f'd={len(r.split())}')}  "
                f"{r:<42s}  gain={cyan(gain_s)}  {dim(f'freq={freq}')}"
            )
    else:
        if _kb.quit_requested:
            top = [(r, c) for r, c in final_counts.items() if r != ':'][:20]
        else:
            top = sorted(
                [(r, c) for r, c in final_counts.items() if r != ':'],
                key=lambda kv: (-kv[1], len(kv[0].split()), kv[0]),
            )[:20]
        if top:
            print(); log_info(f"  Top {len(top)} rules by GPU frequency:")
            for i, (r, c) in enumerate(top, 1):
                log_info(
                    f"  {dim(str(i).rjust(3)+'.')}  {dim(f'd={len(r.split())}')}  "
                    f"{r:<42s}  {cyan(str(c))}"
                )
    print()

    # Explicitly release GPU-side NumPy views before closing the shared
    # wordlist mappings. Stage 2/3 and CELF can cache a zero-copy flattened
    # BASE view in GPUEngine._base_words_precomputed.
    gpu_engine = getattr(extractor, "gpu_engine", None)
    if isinstance(gpu_engine, MultiGPUEngine):
        try:
            gpu_engine.shutdown()
        except Exception as exc:
            log_warn(f"[RAM] Could not shut down GPU workers: {exc}")
    if gpu_engine is not None:
        try:
            release_run_references = getattr(gpu_engine, "release_run_references", None)
            if release_run_references is not None:
                release_run_references()
            else:
                release_word_cache = getattr(gpu_engine, "release_word_cache", None)
                if release_word_cache is not None:
                    release_word_cache()
        except Exception as exc:
            log_warn(f"[RAM] Could not release cached GPU word views: {exc}")

    # Both wordlists are no longer needed. Close them deterministically
    # instead of relying on interpreter-shutdown destructors. target_words
    # may already have been deleted in frequency mode / after CELF selection.
    for _name in ("base_words", "target_words"):
        _wordlist = locals().get(_name)
        if _wordlist is not None:
            close_wordlist = getattr(_wordlist, "close", None)
            if close_wordlist is not None:
                try:
                    close_wordlist()
                except Exception as exc:
                    log_warn(f"[RAM] Could not close {_name}: {exc}")

    _kb.stop()
