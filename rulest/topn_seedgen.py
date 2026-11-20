"""
Lightweight Top-N Seed Generator for RULEOPS / rulest.

Modes:
  - standard: mix of frequent affixes + short chains (default)
  - complementary: bias toward patterns Stage 0 token-strip rarely emits
    (leet+year, transform+year+special, reverse+digit, capitalize+special, …)
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
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
MIN_SUFFIX_COUNT = 3
MIN_YEAR_COUNT = 2

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


def extract_affixes(passwords: Iterable[str]) -> Tuple[Counter, Counter, Counter]:
    suffixes: Counter = Counter()
    prefixes: Counter = Counter()
    years: Counter = Counter()
    for pw in passwords:
        n = len(pw)
        if n < 3:
            continue
        for L in range(1, min(MAX_AFFIX_LEN, n - 1) + 1):
            suf = pw[-L:]
            pre = pw[:L]
            if _is_digit_str(suf) or _is_special_str(suf) or _looks_like_year(suf):
                suffixes[suf] += 1
            if _is_digit_str(pre) or _is_special_str(pre):
                prefixes[pre] += 1
            if _looks_like_year(suf):
                years[suf] += 1
    return suffixes, prefixes, years


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
) -> List[str]:
    max_seeds = max(0, int(max_seeds)) if max_seeds else 0
    # 0 / negative => unlimited (still practical soft stop via family budgets)
    unlimited = max_seeds <= 0
    if unlimited:
        max_seeds = 10**9  # practical unbounded
    budgets_src = FAMILY_BUDGET_COMPLEMENTARY if complementary else FAMILY_BUDGET_STANDARD
    # Scale family budgets; when unlimited, use a large nominal target so families expand
    budget_base = 25_000 if unlimited else max_seeds
    budgets = {k: max(40, int(budget_base * v)) for k, v in budgets_src.items()}

    # Unified progress: 0-30% affix scan, 30-100% family generation
    try:
        n_pw = max(1, len(passwords))
        bar = None
        if show_progress and ProgressBar is not None:
            bar = ProgressBar(total=100, desc="TOP-N", unit="%", min_interval=0.25)
            bar.update(0)

        # Affix pass with chunked progress updates
        if bar is not None and n_pw > 5000:
            suffixes = __import__("collections").Counter()
            prefixes = __import__("collections").Counter()
            years = __import__("collections").Counter()
            step = max(1, n_pw // 20)
            for i, pw in enumerate(passwords):
                n = len(pw)
                if n >= 3:
                    for L in range(1, min(MAX_AFFIX_LEN, n - 1) + 1):
                        suf = pw[-L:]
                        pre = pw[:L]
                        if _is_digit_str(suf) or _is_special_str(suf) or _looks_like_year(suf):
                            suffixes[suf] += 1
                        if _is_digit_str(pre) or _is_special_str(pre):
                            prefixes[pre] += 1
                        if _looks_like_year(suf):
                            years[suf] += 1
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

        dig_suf = sorted(
            [(s, c) for s, c in suffixes.items() if _is_digit_str(s) and c >= MIN_SUFFIX_COUNT],
            key=lambda x: (-x[1], x[0]),
        )
        sp_suf = sorted(
            [(s, c) for s, c in suffixes.items() if _is_special_str(s) and c >= MIN_SUFFIX_COUNT],
            key=lambda x: (-x[1], x[0]),
        )
        dig_pre = sorted(
            [(s, c) for s, c in prefixes.items() if _is_digit_str(s) and c >= MIN_SUFFIX_COUNT],
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

        for s, _ in dig_suf[: budgets["suffix_digit"]]:
            add(_rule_append(s))
        for s, _ in dig_pre[: budgets["prefix_digit"]]:
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
) -> dict:
    passwords = stream_top_n(target_path, top_n, encoding=encoding)
    seeds = generate_seeds(passwords, max_seeds=max_seeds, complementary=complementary)
    write_seeds(seeds, output_path)
    return {
        "target": str(target_path),
        "top_n_requested": top_n,
        "passwords_loaded": len(passwords),
        "seeds_generated": len(seeds),
        "output": str(output_path),
        "complementary": complementary,
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
    args = p.parse_args(argv)
    if not args.target.is_file():
        print(f"error: target not found: {args.target}", file=sys.stderr)
        return 1
    stats = run(
        args.target, args.output,
        top_n=args.top_n, max_seeds=args.max_seeds,
        encoding=args.encoding, complementary=args.complementary,
    )
    mode = "complementary" if stats["complementary"] else "standard"
    print(f"[topn-seedgen] mode={mode} loaded {stats['passwords_loaded']:,} → {stats['seeds_generated']:,} seeds → {stats['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
