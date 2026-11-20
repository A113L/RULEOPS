"""
Lightweight Top-N Seed Generator for RULEOPS / rulest.

Modes:
  - standard: mix of frequent affixes + short chains (default)
  - complementary: bias toward patterns Stage 0 token-strip rarely emits
    (leet+year, transform+year+special, reverse+digit, capitalize+special, …)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from multiprocessing import get_context
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

try:
    from .common import (
        SPECIAL_CHARS_TOP,
        SPECIAL_CHARS_CORE,
        LEET_OPS,
        HashcatRuleValidator,
    )
except Exception:  # pragma: no cover
    SPECIAL_CHARS_TOP = list("!@#$%^&*? .-_+()")
    SPECIAL_CHARS_CORE = list("!@#$%*?")
    LEET_OPS = ["sa@", "se3", "so0", "si1", "sl1", "ss5", "ss$", "st7", "sa4", "si!"]

    class HashcatRuleValidator:  # type: ignore
        @staticmethod
        def validate_rule_for_gpu(rule_str: str) -> bool:
            return bool(rule_str) and len(rule_str) <= 64


try:
    from .progress import ProgressBar
except Exception:  # pragma: no cover
    ProgressBar = None  # type: ignore


DEFAULT_TOP_N = 400_000
DEFAULT_MAX_SEEDS = 15_000
DEFAULT_MIN_SEEDS = 0
DEFAULT_HARD_CAP = None  # no upper limit

MAX_AFFIX_LEN = 4
# All-digit suffixes/prefixes are scanned over a wider window than special-char
# or year affixes: real-world leaks are full of long numeric tails (dates like
# ddmmyyyy/yyyymmdd, phone-number fragments, PINs) that a 4-char cap silently
# drops entirely, no matter how common they are in the sample.
MAX_DIGIT_AFFIX_LEN = 8
MIN_SUFFIX_COUNT = 3
# Affixes longer than MAX_AFFIX_LEN carry more entropy (more distinct possible
# values), so a hit count that would be meaningful at length 4 is much more
# likely to be coincidental at length 8 -- require more repeats before trusting it.
MIN_LONG_DIGIT_SUFFIX_COUNT = 5
# A length-L digit suffix is always at least as frequent as the length-(L-1)
# suffix it contains (every password ending in "15061995" also ends in
# "1995", "995", "95", ...), so a single count-sorted list, truncated by
# budget, silently starves longer/more-specific digit affixes (full dates,
# phone-number tails) in favor of shorter/more-generic ones every time.
# Reserve this fraction of the suffix_digit/prefix_digit budgets for affixes
# longer than MAX_AFFIX_LEN specifically, so they always get a guaranteed
# share instead of only the leftovers after short ones take everything.
LONG_DIGIT_BUDGET_RESERVE = 0.30
MIN_YEAR_COUNT = 2
# How much weight the hand-tuned FAMILY_BUDGET_* priors keep once real
# per-family evidence has been observed in THIS sample, for the five
# directly-measurable "primary" affix families (see _adaptive_primary_budgets).
# 0.0 = fully data-driven, 1.0 = ignore the data and use only the static table.
ADAPTIVE_BUDGET_SHRINKAGE = 0.35
_PRIMARY_BUDGET_FAMILIES = (
    "suffix_digit", "prefix_digit", "suffix_special", "prefix_special", "year",
)

FAMILY_BUDGET_STANDARD = {
    "suffix_digit": 0.18,
    "prefix_digit": 0.06,
    "suffix_special": 0.08,
    "prefix_special": 0.04,
    "year": 0.10,
    "leet_basic": 0.08,
    "depth2_digit_special": 0.12,
    "depth2_transform": 0.08,
    "leet_year": 0.08,
    "transform_year_special": 0.08,
    "reverse_digit": 0.05,
    "cap_special_digit": 0.05,
}

FAMILY_BUDGET_COMPLEMENTARY = {
    "suffix_digit": 0.04,
    "prefix_digit": 0.02,
    "suffix_special": 0.03,
    "prefix_special": 0.02,
    "year": 0.06,
    "leet_basic": 0.10,
    "depth2_digit_special": 0.08,
    "depth2_transform": 0.08,
    "leet_year": 0.18,
    "transform_year_special": 0.16,
    "reverse_digit": 0.12,
    "cap_special_digit": 0.11,
}


def _is_digit_str(s: str) -> bool:
    # s.isdigit() alone is True for Unicode "digit" characters (e.g. the
    # superscript '\u00b2') that int() cannot parse, which used to crash
    # _looks_like_year() below with ValueError on real-world wordlists.
    # Hashcat rule families only care about plain ASCII 0-9 anyway.
    return bool(s) and s.isascii() and s.isdigit()


def _is_special_str(s: str) -> bool:
    return bool(s) and all(c in SPECIAL_CHARS_TOP for c in s)


def _looks_like_year(s: str) -> bool:
    if not s.isascii():
        return False
    if len(s) == 2 and s.isdigit():
        v = int(s)
        return 0 <= v <= 40 or 60 <= v <= 99
    if len(s) == 4 and s.isdigit():
        v = int(s)
        return 1950 <= v <= 2035
    return False


def stream_top_n(path: Path, top_n: int, encoding: str = "latin-1") -> List[str]:
    # top_n <= 0 means "unlimited": no early-break cap, no slicing of the result.
    unlimited = top_n is None or top_n <= 0

    freq: Counter = Counter()
    plain: List[str] = []
    has_counts = False

    with path.open("r", encoding=encoding, errors="ignore") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^(\d+)[\t ]+(.+)$", line)
            if m and len(m.group(2)) >= 2:
                has_counts = True
                cnt = int(m.group(1))
                pw = m.group(2).strip()
                if 2 <= len(pw) <= 64:
                    freq[pw] += cnt
            else:
                if 2 <= len(line) <= 64:
                    plain.append(line)
            if not unlimited:
                if not has_counts and len(plain) >= top_n * 2:
                    break
                if has_counts and i > top_n * 8:
                    break

    if has_counts and freq:
        if unlimited:
            return [pw for pw, _ in freq.most_common()]
        return [pw for pw, _ in freq.most_common(top_n)]

    seen = set()
    out = []
    for w in plain:
        if w not in seen:
            seen.add(w)
            out.append(w)
            if not unlimited and len(out) >= top_n:
                break
    return out


def _scan_password_affixes(pw: str, suffixes: Counter, prefixes: Counter, years: Counter) -> None:
    """Accumulate one password's suffix/prefix/year affix hits in place.

    Lengths up to MAX_AFFIX_LEN are checked for digit, special-char and
    year-shaped affixes (unchanged behavior). Lengths beyond that, up to
    MAX_DIGIT_AFFIX_LEN, are checked for all-digit affixes only -- covers
    long numeric tails (dates, phone fragments, PINs) without blowing up
    the special-char/year combinatorics, which don't benefit from it.
    """
    n = len(pw)
    if n < 3:
        return
    max_len = min(MAX_DIGIT_AFFIX_LEN, n - 1)
    for L in range(1, max_len + 1):
        suf = pw[-L:]
        pre = pw[:L]
        if L <= MAX_AFFIX_LEN:
            if _is_digit_str(suf) or _is_special_str(suf) or _looks_like_year(suf):
                suffixes[suf] += 1
            if _is_digit_str(pre) or _is_special_str(pre):
                prefixes[pre] += 1
            if _looks_like_year(suf):
                years[suf] += 1
        else:
            if _is_digit_str(suf):
                suffixes[suf] += 1
            if _is_digit_str(pre):
                prefixes[pre] += 1


def extract_affixes(passwords: Iterable[str]) -> Tuple[Counter, Counter, Counter]:
    suffixes: Counter = Counter()
    prefixes: Counter = Counter()
    years: Counter = Counter()
    for pw in passwords:
        _scan_password_affixes(pw, suffixes, prefixes, years)
    return suffixes, prefixes, years


# Below this many passwords, splitting into worker chunks and paying
# process start-up/IPC cost is a net loss vs. just scanning in-process.
MIN_PASSWORDS_FOR_PARALLEL_SCAN = 50_000


def default_worker_count() -> int:
    """All logical CPUs by default; falls back to 1 if undetectable."""
    try:
        n = os.cpu_count()
    except Exception:
        n = None
    return n if n else 1


def _extract_affixes_chunk(passwords_chunk: List[str]) -> Tuple[Counter, Counter, Counter]:
    """Worker-process entry point: scan one chunk, return its partial counters.

    Must stay a module-level function (not a closure/lambda) so it can be
    pickled and sent to worker processes by multiprocessing.
    """
    return extract_affixes(passwords_chunk)


def extract_affixes_parallel(
    passwords: List[str], workers: Optional[int] = None
) -> Tuple[Counter, Counter, Counter]:
    """Same result as extract_affixes(), computed across multiple CPU cores.

    Splits `passwords` into `workers` contiguous chunks, scans each chunk in
    its own process, then merges the per-chunk Counters. Falls back to the
    single-process path for small inputs or when only one worker is usable,
    since process start-up cost would dominate a short scan.
    """
    n_pw = len(passwords)
    if workers is None:
        workers = default_worker_count()
    workers = max(1, int(workers))

    if workers <= 1 or n_pw < MIN_PASSWORDS_FOR_PARALLEL_SCAN:
        return extract_affixes(passwords)

    # Cap workers to the number of chunks that actually makes sense so we
    # don't spin up processes with nothing to do on small-but-not-tiny inputs.
    workers = min(workers, max(1, n_pw // (MIN_PASSWORDS_FOR_PARALLEL_SCAN // 5)))
    if workers <= 1:
        return extract_affixes(passwords)

    chunk_size = max(1, -(-n_pw // workers))  # ceil division
    chunks = [passwords[i:i + chunk_size] for i in range(0, n_pw, chunk_size)]

    suffixes: Counter = Counter()
    prefixes: Counter = Counter()
    years: Counter = Counter()

    # "fork" avoids re-pickling module globals on Linux/macOS and is faster
    # to spawn; multiprocessing falls back sanely wherever fork isn't
    # available (e.g. Windows uses "spawn" automatically via get_context).
    ctx_name = "fork" if "fork" in __import__("multiprocessing").get_all_start_methods() else "spawn"
    ctx = get_context(ctx_name)
    with ctx.Pool(processes=workers) as pool:
        for s_part, p_part, y_part in pool.map(_extract_affixes_chunk, chunks):
            suffixes.update(s_part)
            prefixes.update(p_part)
            years.update(y_part)

    return suffixes, prefixes, years


def _split_long_short(items: list, max_len: int = MAX_AFFIX_LEN) -> Tuple[list, list]:
    """Split a count-sorted (affix, count) list into (long, short) by length,
    each still sorted by descending count within its own group."""
    long_items = [x for x in items if len(x[0]) > max_len]
    short_items = [x for x in items if len(x[0]) <= max_len]
    return long_items, short_items


def _budgeted_affixes(items: list, budget: int, reserve_frac: float = LONG_DIGIT_BUDGET_RESERVE) -> list:
    """Pick up to `budget` affixes from a count-sorted (affix, count) list,
    guaranteeing a reserved *minimum* share to affixes longer than
    MAX_AFFIX_LEN first (see LONG_DIGIT_BUDGET_RESERVE) so they are never
    entirely crowded out by the inherently-more-frequent shorter affixes
    they're substrings of. The reserve is a floor, not a ceiling: if the
    shorter pool runs out before the budget is spent, the remainder is
    backfilled with more long affixes rather than left unused.
    """
    long_items, short_items = _split_long_short(items)
    if not long_items:
        return [s for s, _ in short_items[:budget]]
    if not short_items:
        return [s for s, _ in long_items[:budget]]

    n_long_min = min(len(long_items), int(budget * reserve_frac))
    picked_long = long_items[:n_long_min]
    remaining = max(0, budget - len(picked_long))
    picked_short = short_items[:remaining]

    used = len(picked_long) + len(picked_short)
    if used < budget and len(long_items) > n_long_min:
        picked_long = picked_long + long_items[n_long_min: n_long_min + (budget - used)]

    return [s for s, _ in picked_long] + [s for s, _ in picked_short]


def _min_count_for(affix: str) -> int:
    """Longer affixes carry more entropy, so demand more repeats before trusting one."""
    return MIN_SUFFIX_COUNT if len(affix) <= MAX_AFFIX_LEN else MIN_LONG_DIGIT_SUFFIX_COUNT


def _adaptive_primary_budgets(suffixes: Counter, prefixes: Counter, years: Counter,
                               budgets_src: dict, budget_base: int,
                               shrinkage: float = ADAPTIVE_BUDGET_SHRINKAGE) -> dict:
    """Reallocate the five directly-observable affix families' combined budget
    share by how much of THIS sample's evidence mass each one actually holds,
    instead of a fixed prior -- this is the actual "probabilistic" half of
    PCFG (grammar probabilities estimated from the corpus, not hand-tuned).

    The seven synthetic depth-2/combo families (leet_year, reverse_digit, ...)
    have no direct per-family evidence from this lightweight scan, so they are
    left exactly as the static table set them; only the mass that the static
    table itself allocated to the five primary families is redistributed
    *among* those five, never taken from or given to the combo families.
    """
    static_sub = {k: budgets_src.get(k, 0.0) for k in _PRIMARY_BUDGET_FAMILIES}
    static_sum = sum(static_sub.values())
    if static_sum <= 0:
        return {}
    static_share = {k: v / static_sum for k, v in static_sub.items()}

    data_mass = {
        "suffix_digit": sum(c for s, c in suffixes.items() if _is_digit_str(s)),
        "prefix_digit": sum(c for s, c in prefixes.items() if _is_digit_str(s)),
        "suffix_special": sum(c for s, c in suffixes.items() if _is_special_str(s)),
        "prefix_special": sum(c for s, c in prefixes.items() if _is_special_str(s)),
        "year": sum(years.values()),
    }
    total_mass = sum(data_mass.values())
    data_share = (
        {k: v / total_mass for k, v in data_mass.items()}
        if total_mass > 0 else static_share
    )

    shrinkage = min(1.0, max(0.0, float(shrinkage)))
    blended = {
        k: shrinkage * static_share[k] + (1.0 - shrinkage) * data_share[k]
        for k in _PRIMARY_BUDGET_FAMILIES
    }
    bsum = sum(blended.values()) or 1.0
    blended = {k: v / bsum for k, v in blended.items()}

    return {
        k: max(40, int(budget_base * static_sum * blended[k]))
        for k in _PRIMARY_BUDGET_FAMILIES
    }


def _rule_append(s: str) -> str:
    return " ".join(f"${c}" for c in s)


def _rule_prepend(s: str) -> str:
    return " ".join(f"^{c}" for c in reversed(s))


def _valid(rule: str) -> bool:
    try:
        return HashcatRuleValidator.validate_rule_for_gpu(rule)
    except Exception:
        return False


def generate_seeds(
    passwords: List[str],
    max_seeds: int = DEFAULT_MAX_SEEDS,
    complementary: bool = False,
    show_progress: bool = True,
    adaptive: bool = True,
    workers: Optional[int] = None,
) -> List[str]:
    max_seeds = max(0, int(max_seeds)) if max_seeds else 0
    # 0 / negative => unlimited (still practical soft stop via family budgets)
    unlimited = max_seeds <= 0
    if unlimited:
        max_seeds = 10**9  # practical unbounded
    budgets_src = FAMILY_BUDGET_COMPLEMENTARY if complementary else FAMILY_BUDGET_STANDARD
    # Scale family budgets; when unlimited, use a large nominal target so families expand
    budget_base = 25_000 if unlimited else max_seeds
    # A static baseline is always available immediately (used as-is for the
    # seven synthetic combo families, and as the pre-adaptive fallback for
    # the five primary ones until the affix scan below has real evidence).
    budgets = {k: max(40, int(budget_base * v)) for k, v in budgets_src.items()}

    # Unified progress: 0-30% affix scan, 30-100% family generation
    try:
        n_pw = max(1, len(passwords))
        bar = None
        if show_progress and ProgressBar is not None:
            bar = ProgressBar(total=100, desc="TOP-N", unit="%", min_interval=0.25)
            bar.update(0)

        # Affix pass. Defaults to using every CPU core: this scan is the one
        # genuinely CPU-bound, embarrassingly-parallel part of seed
        # generation (each password's affixes are independent of every
        # other's), so for large inputs it's split across worker processes
        # instead of running on a single core.
        effective_workers = default_worker_count() if workers is None else max(1, int(workers))
        use_parallel = effective_workers > 1 and n_pw >= MIN_PASSWORDS_FOR_PARALLEL_SCAN

        if use_parallel:
            # Multiprocessing can't report fine-grained progress from inside
            # worker processes without extra IPC, so just show the pass as
            # a single 0 -> 30 jump once every worker is done.
            suffixes, prefixes, years = extract_affixes_parallel(passwords, workers=effective_workers)
            if bar is not None:
                bar.n = 30
                bar.refresh()
        elif bar is not None and n_pw > 5000:
            suffixes = __import__("collections").Counter()
            prefixes = __import__("collections").Counter()
            years = __import__("collections").Counter()
            step = max(1, n_pw // 20)
            for i, pw in enumerate(passwords):
                _scan_password_affixes(pw, suffixes, prefixes, years)
                if i % step == 0:
                    bar.n = int(30 * (i + 1) / n_pw)
                    bar.refresh()
            bar.n = 30
            bar.refresh()
        else:
            suffixes, prefixes, years = extract_affixes(passwords)
            if bar is not None:
                bar.n = 30
                bar.refresh()

        # Data-driven reallocation of the five directly-observable families'
        # combined budget share, now that the scan above has real evidence
        # from THIS sample to work with (see _adaptive_primary_budgets).
        if adaptive:
            adaptive_budgets = _adaptive_primary_budgets(suffixes, prefixes, years, budgets_src, budget_base)
            budgets.update(adaptive_budgets)

        dig_suf = sorted(
            [(s, c) for s, c in suffixes.items() if _is_digit_str(s) and c >= _min_count_for(s)],
            key=lambda x: (-x[1], x[0]),
        )
        sp_suf = sorted(
            [(s, c) for s, c in suffixes.items() if _is_special_str(s) and c >= MIN_SUFFIX_COUNT],
            key=lambda x: (-x[1], x[0]),
        )
        dig_pre = sorted(
            [(s, c) for s, c in prefixes.items() if _is_digit_str(s) and c >= _min_count_for(s)],
            key=lambda x: (-x[1], x[0]),
        )
        sp_pre = sorted(
            [(s, c) for s, c in prefixes.items() if _is_special_str(s) and c >= MIN_SUFFIX_COUNT],
            key=lambda x: (-x[1], x[0]),
        )
        year_items = sorted(
            [(s, c) for s, c in years.items() if c >= MIN_YEAR_COUNT],
            key=lambda x: (-x[1], x[0]),
        )

        if len(dig_suf) < 50:
            have = {x[0] for x in dig_suf}
            dig_suf = dig_suf + [(str(i), 1) for i in range(10) if str(i) not in have]
        if len(year_items) < 30:
            have = {x[0] for x in year_items}
            for y in [str(y) for y in range(2015, 2027)] + [f"{y:02d}" for y in list(range(0, 30)) + list(range(90, 100))]:
                if y not in have:
                    year_items.append((y, 1))

        seeds: List[str] = []
        seen: Set[str] = set()
        _add_count = [0]
        _target_for_bar = max(1, min(max_seeds, budget_base) if not unlimited else budget_base)

        def add(rule: str) -> bool:
            if rule and rule not in seen and _valid(rule):
                seen.add(rule)
                seeds.append(rule)
                _add_count[0] += 1
                if bar is not None and _add_count[0] % 64 == 0:
                    # map generated count into 30..99
                    frac = min(1.0, len(seeds) / _target_for_bar)
                    bar.n = 30 + int(69 * frac)
                    bar.refresh()
                return True
            return False

        for s in _budgeted_affixes(dig_suf, budgets["suffix_digit"]):
            add(_rule_append(s))
        for s in _budgeted_affixes(dig_pre, budgets["prefix_digit"]):
            add(_rule_prepend(s))
        for s, _ in sp_suf[: budgets["suffix_special"]]:
            add(_rule_append(s))
        for ch in SPECIAL_CHARS_CORE:
            add(f"${ch}")
        for s, _ in sp_pre[: budgets["prefix_special"]]:
            add(_rule_prepend(s))
        for ch in SPECIAL_CHARS_CORE:
            add(f"^{ch}")
        for s, _ in year_items[: budgets["year"]]:
            add(_rule_append(s))
            add(_rule_prepend(s))

        for op in LEET_OPS:
            add(op)
            for d in "1234567890":
                add(f"{op} ${d}")
                if len(seeds) > max_seeds * 0.55:
                    break

        n = 0
        for s, _ in dig_suf[:1200]:
            if len(s) > 3:
                continue
            for ch in SPECIAL_CHARS_CORE:
                add(f"{_rule_append(s)} ${ch}")
                add(f"${ch} {_rule_append(s)}")
                n += 2
                if n >= budgets["depth2_digit_special"]:
                    break
            if n >= budgets["depth2_digit_special"]:
                break

        transforms = ["c", "u", "l", "C", "t", "r"]
        n = 0
        popular = [s for s, _ in dig_suf[:300] if len(s) <= 3] + [s for s, _ in year_items[:120]]
        for t in transforms:
            for s in popular:
                add(f"{t} {_rule_append(s)}")
                n += 1
                if n >= budgets["depth2_transform"]:
                    break
            if n >= budgets["depth2_transform"]:
                break

        n = 0
        for op in LEET_OPS:
            for s, _ in year_items[:80]:
                add(f"{op} {_rule_append(s)}")
                add(f"{_rule_append(s)} {op}")
                n += 2
                if n >= budgets["leet_year"]:
                    break
            if n >= budgets["leet_year"]:
                break

        n = 0
        for t in ("c", "u", "l", "C", "r"):
            for s, _ in year_items[:60]:
                for ch in SPECIAL_CHARS_CORE[:5]:
                    add(f"{t} {_rule_append(s)} ${ch}")
                    add(f"{t} ${ch} {_rule_append(s)}")
                    n += 2
                    if n >= budgets["transform_year_special"]:
                        break
                if n >= budgets["transform_year_special"]:
                    break
            if n >= budgets["transform_year_special"]:
                break

        n = 0
        for s, _ in dig_suf[:400]:
            if len(s) > 3:
                continue
            add(f"r {_rule_append(s)}")
            add(f"{_rule_append(s)} r")
            n += 2
            if n >= budgets["reverse_digit"]:
                break
        for s, _ in year_items[:40]:
            add(f"r {_rule_append(s)}")
            n += 1
            if n >= budgets["reverse_digit"]:
                break

        n = 0
        for t in ("c", "C", "u"):
            for ch in SPECIAL_CHARS_CORE:
                for d in "1234567890":
                    add(f"{t} ${ch} ${d}")
                    add(f"{t} ${d} ${ch}")
                    n += 2
                    if n >= budgets["cap_special_digit"]:
                        break
                if n >= budgets["cap_special_digit"]:
                    break
            if n >= budgets["cap_special_digit"]:
                break

        if len(seeds) < max_seeds:
            for s, _ in year_items:
                for t in transforms:
                    for ch in SPECIAL_CHARS_CORE:
                        add(f"{t} {_rule_append(s)} ${ch}")
                        if len(seeds) >= max_seeds:
                            break
                    if len(seeds) >= max_seeds:
                        break
                if len(seeds) >= max_seeds:
                    break

        if len(seeds) < max_seeds:
            for s, _ in dig_suf:
                if len(s) > 4:
                    continue
                for t in transforms:
                    add(f"{t} {_rule_append(s)}")
                    if len(seeds) >= max_seeds:
                        break
                if len(seeds) >= max_seeds:
                    break

        if not unlimited and len(seeds) > max_seeds:
            seeds = seeds[:max_seeds]
    except Exception:
        # Always stop the background heartbeat thread on failure too --
        # otherwise it keeps writing stray 'TOP-N: NN%' lines into the
        # log forever (it's a daemon thread with its own refresh loop),
        # long after the failure itself was already logged.
        if bar is not None:
            bar.close()
        raise
    if bar is not None:
        bar.n = 100
        bar.refresh()
        bar.close()
    return seeds


def write_seeds(seeds: List[str], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write("# Top-N seed rules generated by rulest.topn_seedgen\n")
        fh.write(f"# count={len(seeds)}\n")
        for r in seeds:
            fh.write(r + "\n")


def run(
    target_path: Path,
    output_path: Path,
    top_n: int = DEFAULT_TOP_N,
    max_seeds: int = DEFAULT_MAX_SEEDS,
    encoding: str = "latin-1",
    complementary: bool = False,
    adaptive: bool = True,
    workers: Optional[int] = None,
) -> dict:
    passwords = stream_top_n(target_path, top_n, encoding=encoding)
    seeds = generate_seeds(
        passwords, max_seeds=max_seeds, complementary=complementary, adaptive=adaptive,
        workers=workers,
    )
    write_seeds(seeds, output_path)
    return {
        "target": str(target_path),
        "top_n_requested": top_n,
        "passwords_loaded": len(passwords),
        "seeds_generated": len(seeds),
        "output": str(output_path),
        "complementary": complementary,
        "adaptive": adaptive,
        "workers": workers if workers is not None else default_worker_count(),
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="topn-seedgen")
    p.add_argument("target", type=Path)
    p.add_argument("-o", "--output", type=Path, default=Path("topn_seeds.rule"))
    p.add_argument("-n", "--top-n", type=int, default=DEFAULT_TOP_N,
                    help="How many top TARGET entries to analyze. 0 (or negative) = unlimited (scan the whole file).")
    p.add_argument("-m", "--max-seeds", type=int, default=DEFAULT_MAX_SEEDS)
    p.add_argument("--encoding", default="latin-1")
    p.add_argument("--complementary", action="store_true")
    p.add_argument("--no-adaptive-budget", action="store_false", dest="adaptive", default=True,
                    help="Disable data-driven family-budget reallocation and use only the static priors.")
    p.add_argument("-w", "--workers", type=int, default=default_worker_count(),
                    help="CPU worker processes for the affix scan. Defaults to all detected "
                         "logical cores (%(default)s on this machine). Use 1 to force single-core.")
    args = p.parse_args(argv)
    if not args.target.is_file():
        print(f"error: target not found: {args.target}", file=sys.stderr)
        return 1
    stats = run(
        args.target, args.output,
        top_n=args.top_n, max_seeds=args.max_seeds,
        encoding=args.encoding, complementary=args.complementary, adaptive=args.adaptive,
        workers=args.workers,
    )
    mode = "complementary" if stats["complementary"] else "standard"
    print(f"[topn-seedgen] mode={mode} loaded {stats['passwords_loaded']:,} → {stats['seeds_generated']:,} seeds → {stats['output']} (workers={stats['workers']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
