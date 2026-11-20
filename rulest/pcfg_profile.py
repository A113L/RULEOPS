"""Aggregate-only password composition profiling for RULEOPS PCFG audits.

The profiler reports weighted and unweighted length and character-class
statistics, distribution diversity, input acceptance coverage, and internal
consistency checks. It never emits password values, affixes, candidate strings,
or Hashcat rules, and it does not feed its output into a guessing pipeline.
"""

from __future__ import annotations

import argparse
import heapq
import json
import math
import re
import sys
from collections import Counter
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

MIN_PROFILE_LENGTH = 2
MAX_PROFILE_LENGTH = 64
MAX_SIGNED_INT64 = (1 << 63) - 1
MAX_SAFE_JSON_INTEGER = (1 << 53) - 1
TOP_WEIGHT_TRACK_LIMIT = 100
PROFILE_SCHEMA = "ruleops.pcfg-profile.v1"
COMPARISON_SCHEMA = "ruleops.pcfg-profile-comparison.v1"
_LENGTH_BUCKETS: Tuple[Tuple[str, int, int], ...] = (
    ("2-7", 2, 7),
    ("8-11", 8, 11),
    ("12-15", 12, 15),
    ("16-20", 16, 20),
    ("21-32", 21, 32),
    ("33-64", 33, 64),
)
_CLASS_ORDER = ("lowercase", "uppercase", "digits", "symbols", "non_ascii")
_OTHER_ONLY = "other_only"
_FREQUENCY_LINE = re.compile(r"^(\d+)[\t ]+(.+)$")


def _profile_record(
    password: str,
    weight: int,
    weighted: Dict[str, Counter],
    unweighted: Dict[str, Counter],
    totals: Counter,
) -> None:
    """Add aggregate contributions without retaining the input value."""
    length = len(password)
    totals["profiled_entries"] += 1
    totals["weighted_observations"] += weight
    totals["weighted_length_sum"] += length * weight
    totals["unweighted_length_sum"] += length
    totals["min_length"] = min(totals.get("min_length", length), length)
    totals["max_length"] = max(totals.get("max_length", length), length)

    for bucket, lower, upper in _LENGTH_BUCKETS:
        if lower <= length <= upper:
            weighted["length_buckets"][bucket] += weight
            unweighted["length_buckets"][bucket] += 1
            break

    flags = {
        "lowercase": any(char.islower() for char in password),
        "uppercase": any(char.isupper() for char in password),
        "digits": any(char.isascii() and char.isdigit() for char in password),
        "symbols": any(not char.isalnum() for char in password),
        "non_ascii": any(not char.isascii() for char in password),
    }
    present = [name for name in _CLASS_ORDER if flags[name]]
    combination = "+".join(present) if present else _OTHER_ONLY
    weighted["class_combinations"][combination] += weight
    unweighted["class_combinations"][combination] += 1

    for name, present_flag in flags.items():
        if present_flag:
            weighted["class_presence"][name] += weight
            unweighted["class_presence"][name] += 1

    if len(present) <= 1:
        totals["weighted_single_class_only"] += weight
        totals["unweighted_single_class_only"] += 1
    else:
        totals["weighted_multi_class"] += weight
        totals["unweighted_multi_class"] += 1

    if length < 8:
        totals["weighted_under_8"] += weight
        totals["unweighted_under_8"] += 1
    if length < 12:
        totals["weighted_under_12"] += weight
        totals["unweighted_under_12"] += 1
    if length >= 12:
        totals["weighted_at_least_12"] += weight
        totals["unweighted_at_least_12"] += 1


def _fixed_counts(counter: Counter, names: Iterable[str]) -> dict:
    return {name: int(counter.get(name, 0)) for name in names}


def _ratio(numerator: int, denominator: int) -> float:
    """Divide arbitrary-size integers without overflowing binary float conversion."""
    if not denominator:
        return 0.0
    with localcontext() as context:
        context.prec = 32
        return float(Decimal(numerator) / Decimal(denominator))


def _distribution(counter: dict, total: int) -> dict:
    if not total:
        return {key: 0.0 for key in counter}
    return {key: 100.0 * _ratio(value, total) for key, value in counter.items()}


def _weight_bucket_bounds(exponent: int) -> Tuple[int, int]:
    lower = 1 << exponent
    upper = 1 if exponent == 0 else (1 << (exponent + 1)) - 1
    return lower, upper


def _weight_quantile_bounds(histogram: Counter, count: int, percentile: int) -> Optional[dict]:
    """Return an order-of-magnitude bound for a percentile using log2 buckets."""
    if count <= 0:
        return None
    rank = (count * percentile + 99) // 100
    cumulative = 0
    for exponent in sorted(histogram):
        cumulative += histogram[exponent]
        if cumulative >= rank:
            lower, upper = _weight_bucket_bounds(exponent)
            return {
                "lower_bound": lower,
                "upper_bound": upper,
                "bucket": str(lower) if lower == upper else f"{lower}-{upper}",
                "method": "power_of_two_bucket_approximation",
            }
    return None


def _build_weight_diagnostics(
    weight_histogram: Counter,
    top_weights: list,
    count: int,
    weight_sum: int,
    minimum: Optional[int],
    maximum: Optional[int],
    unit_weight_count: int,
    frequency_weighted_count: int,
    int64_exceeding_entries: int,
    safe_json_exceeding_entries: int,
) -> dict:
    ordered_top = sorted(top_weights, reverse=True)

    def top_group(limit: int) -> dict:
        total = sum(ordered_top[:limit])
        return {
            "entries": min(limit, count),
            "weight_sum": total,
            "share_of_total_percent": round(100.0 * _ratio(total, weight_sum), 9) if weight_sum else 0.0,
        }

    histogram_output = {}
    for exponent in sorted(weight_histogram):
        lower, upper = _weight_bucket_bounds(exponent)
        key = str(lower) if lower == upper else f"{lower}-{upper}"
        histogram_output[key] = int(weight_histogram[exponent])

    return {
        "profiled_weight_entries": count,
        "unit_weight_entries": unit_weight_count,
        "entries_with_weight_above_one": frequency_weighted_count,
        "weight_min": minimum,
        "weight_median_approx": _weight_quantile_bounds(weight_histogram, count, 50),
        "weight_p95_approx": _weight_quantile_bounds(weight_histogram, count, 95),
        "weight_p99_approx": _weight_quantile_bounds(weight_histogram, count, 99),
        "weight_max": maximum,
        "mean_weight_per_entry": round(_ratio(weight_sum, count), 6) if count else 0.0,
        "weight_magnitude_histogram": histogram_output,
        "top_weight_concentration": {
            "top_1": top_group(1),
            "top_10": top_group(10),
            "top_100": top_group(100),
        },
        "integer_safety": {
            "signed_int64_limit": MAX_SIGNED_INT64,
            "safe_json_integer_limit": MAX_SAFE_JSON_INTEGER,
            "weighted_total_exceeds_signed_int64": weight_sum > MAX_SIGNED_INT64,
            "max_single_weight_exceeds_signed_int64": (maximum or 0) > MAX_SIGNED_INT64,
            "entries_exceeding_signed_int64": int(int64_exceeding_entries),
            "entries_exceeding_safe_json_integer": int(safe_json_exceeding_entries),
            "weighted_total_exceeds_safe_json_integer": weight_sum > MAX_SAFE_JSON_INTEGER,
            "max_single_weight_exceeds_safe_json_integer": (maximum or 0) > MAX_SAFE_JSON_INTEGER,
            "accumulator": "Python arbitrary-precision integers",
            "warning": (
                "Keep weighted counts in arbitrary-precision integers. Do not store or sum them "
                "in signed int64 or JavaScript Number when the corresponding limit is exceeded."
            ),
        },
    }


def _entropy_metrics(counts: dict) -> dict:
    total = sum(counts.values())
    nonzero = [value for value in counts.values() if value > 0]
    if not total or not nonzero:
        return {
            "shannon_entropy_bits": 0.0,
            "normalized_entropy": 0.0,
            "effective_categories": 0.0,
            "observed_categories": 0,
        }
    probabilities = [_ratio(value, total) for value in nonzero]
    entropy = -sum(probability * math.log2(probability) for probability in probabilities)
    if abs(entropy) < 1e-12:
        entropy = 0.0
    category_count = len(nonzero)
    normalized = entropy / math.log2(category_count) if category_count > 1 else 0.0
    return {
        "shannon_entropy_bits": round(entropy, 6),
        "normalized_entropy": round(normalized, 6),
        "effective_categories": round(2 ** entropy, 6),
        "observed_categories": category_count,
    }


def _consistency_checks(profile: dict) -> dict:
    source = profile["input"]
    length = profile["length"]
    composition = profile["composition"]
    policy = profile["policy_indicators"]
    coverage = profile["input_coverage"]
    total_weighted = source["weighted_observations"]
    total_unweighted = source["profiled_entries"]
    skipped_total = (source["empty_lines"] + source["out_of_range_entries"]
                     + source["zero_weight_entries"] + source.get("malformed_frequency_entries", 0))

    weighted_histogram_sum = sum(length["weighted_histogram"].values())
    unweighted_histogram_sum = sum(length["unweighted_histogram"].values())
    weighted_combinations_sum = sum(composition["weighted_class_combinations"].values())
    unweighted_combinations_sum = sum(composition["unweighted_class_combinations"].values())

    checks = {
        "input_lines_accounted_for": source["lines_seen"] == skipped_total + total_unweighted,
        "weighted_length_histogram_matches_total": weighted_histogram_sum == total_weighted,
        "unweighted_length_histogram_matches_entries": unweighted_histogram_sum == total_unweighted,
        "weighted_class_combinations_match_total": weighted_combinations_sum == total_weighted,
        "unweighted_class_combinations_match_entries": unweighted_combinations_sum == total_unweighted,
        "weighted_single_and_multi_class_match_total": (
            composition["weighted_single_class_only"] + composition["weighted_multi_class"] == total_weighted
        ),
        "unweighted_single_and_multi_class_match_entries": (
            composition["unweighted_single_class_only"] + composition["unweighted_multi_class"] == total_unweighted
        ),
        "input_coverage_matches_entries": (
            coverage["profiled_entries"] + coverage["excluded_nonempty_entries"]
            == coverage["nonempty_lines"]
            and coverage["profiled_entries"] == total_unweighted
        ),
        "weighted_class_presence_counts_within_total": all(
            0 <= count <= total_weighted
            for count in composition["weighted_class_presence"].values()
        ),
        "unweighted_class_presence_counts_within_entries": all(
            0 <= count <= total_unweighted
            for count in composition["unweighted_class_presence"].values()
        ),
        "weighted_policy_indicators_match_total": (
            policy["weighted_under_12_characters"] + policy["weighted_at_least_12_characters"]
            == total_weighted
        ),
        "unweighted_policy_indicators_match_entries": (
            policy["unweighted_under_12_characters"] + policy["unweighted_at_least_12_characters"]
            == total_unweighted
        ),
        "length_range_is_valid": (
            total_unweighted == 0
            or 2 <= length["minimum"] <= length["maximum"] <= MAX_PROFILE_LENGTH
        ),
    }
    weight_diagnostics = profile.get("weight_diagnostics")
    if weight_diagnostics is not None:
        safety = weight_diagnostics["integer_safety"]
        checks.update({
            "weight_records_match_profiled_entries": (
                weight_diagnostics["profiled_weight_entries"] == total_unweighted
            ),
            "weight_min_max_are_valid": (
                total_unweighted == 0
                or 1 <= weight_diagnostics["weight_min"] <= weight_diagnostics["weight_max"]
            ),
            "weight_histogram_matches_entries": (
                sum(weight_diagnostics["weight_magnitude_histogram"].values()) == total_unweighted
            ),
            "int64_overflow_flags_are_consistent": (
                safety["weighted_total_exceeds_signed_int64"] == (total_weighted > MAX_SIGNED_INT64)
                and safety["max_single_weight_exceeds_signed_int64"]
                == (weight_diagnostics["weight_max"] is not None
                    and weight_diagnostics["weight_max"] > MAX_SIGNED_INT64)
                and 0 <= safety["entries_exceeding_signed_int64"] <= total_unweighted
            ),
            "top_weight_sums_are_bounded": (
                weight_diagnostics["top_weight_concentration"]["top_1"]["weight_sum"]
                <= weight_diagnostics["top_weight_concentration"]["top_10"]["weight_sum"]
                <= weight_diagnostics["top_weight_concentration"]["top_100"]["weight_sum"]
                <= total_weighted
            ),
            "weight_type_counts_match_entries": (
                weight_diagnostics["unit_weight_entries"]
                + weight_diagnostics["entries_with_weight_above_one"] == total_unweighted
            ),
        })
    return {"valid": all(checks.values()), "checks": checks}


def profile_wordlist(
    path: Path, encoding: str = "latin-1", input_format: str = "auto"
) -> dict:
    """Stream a wordlist into weighted and unweighted aggregate statistics.

    Plain wordlists count each valid non-empty line once. Frequency-formatted
    files (``COUNT<space-or-tab>VALUE``) contribute COUNT weighted observations
    and one unweighted entry. ``input_format`` may be ``auto`` (legacy behavior),
    ``plain`` (never parse a numeric prefix), or ``count-value`` (require the prefix).
    Repeated lines remain separate entries.
    """
    weighted: Dict[str, Counter] = {
        "length_buckets": Counter(),
        "class_presence": Counter(),
        "class_combinations": Counter(),
    }
    unweighted: Dict[str, Counter] = {
        "length_buckets": Counter(),
        "class_presence": Counter(),
        "class_combinations": Counter(),
    }
    totals: Counter = Counter()
    weight_histogram: Counter = Counter()
    top_weights = []
    minimum_weight = None
    maximum_weight = None
    int64_exceeding_entries = 0
    safe_json_exceeding_entries = 0

    if input_format not in {"auto", "plain", "count-value"}:
        raise ValueError("input_format must be auto, plain, or count-value")

    with path.open("r", encoding=encoding, errors="ignore") as handle:
        for raw_line in handle:
            totals["lines_seen"] += 1
            line = raw_line.strip()
            if not line:
                totals["empty_lines"] += 1
                continue

            # ``auto`` preserves legacy COUNT VALUE detection. Use ``plain``
            # when leading numbers are part of the value, or ``count-value``
            # when the input format is known and must be validated strictly.
            match = _FREQUENCY_LINE.match(line) if input_format != "plain" else None
            if match:
                weight = int(match.group(1))
                password = match.group(2).strip()
                totals["frequency_records"] += 1
            elif input_format == "count-value":
                totals["malformed_frequency_entries"] += 1
                continue
            else:
                weight = 1
                password = line
                totals["plain_records"] += 1

            if not password or not MIN_PROFILE_LENGTH <= len(password) <= MAX_PROFILE_LENGTH:
                totals["out_of_range_entries"] += 1
                continue
            if weight <= 0:
                totals["zero_weight_entries"] += 1
                continue

            _profile_record(password, weight, weighted, unweighted, totals)
            weight_histogram[weight.bit_length() - 1] += 1
            minimum_weight = weight if minimum_weight is None else min(minimum_weight, weight)
            maximum_weight = weight if maximum_weight is None else max(maximum_weight, weight)
            if weight == 1:
                totals["unit_weight_entries"] += 1
            else:
                totals["frequency_weighted_entries"] += 1
            if weight > MAX_SIGNED_INT64:
                int64_exceeding_entries += 1
            if weight > MAX_SAFE_JSON_INTEGER:
                safe_json_exceeding_entries += 1
            if len(top_weights) < TOP_WEIGHT_TRACK_LIMIT:
                heapq.heappush(top_weights, weight)
            elif weight > top_weights[0]:
                heapq.heapreplace(top_weights, weight)

    weighted_total = int(totals["weighted_observations"])
    unweighted_total = int(totals["profiled_entries"])
    weighted_mean = _ratio(totals["weighted_length_sum"], weighted_total) if weighted_total else 0.0
    unweighted_mean = _ratio(totals["unweighted_length_sum"], unweighted_total) if unweighted_total else 0.0

    length_weighted = _fixed_counts(weighted["length_buckets"], (x[0] for x in _LENGTH_BUCKETS))
    length_unweighted = _fixed_counts(unweighted["length_buckets"], (x[0] for x in _LENGTH_BUCKETS))
    presence_weighted = _fixed_counts(weighted["class_presence"], _CLASS_ORDER)
    presence_unweighted = _fixed_counts(unweighted["class_presence"], _CLASS_ORDER)
    combinations_weighted = {name: int(count) for name, count in sorted(weighted["class_combinations"].items())}
    combinations_unweighted = {name: int(count) for name, count in sorted(unweighted["class_combinations"].items())}

    nonempty_lines = int(totals["lines_seen"] - totals["empty_lines"])
    excluded_nonempty_lines = int(totals["out_of_range_entries"] + totals["zero_weight_entries"] + totals["malformed_frequency_entries"])

    profile = {
        "schema": PROFILE_SCHEMA,
        "profile_type": "aggregate_password_composition",
        "input": {
            "file_name": path.name,
            "lines_seen": int(totals["lines_seen"]),
            "profiled_entries": unweighted_total,
            "weighted_observations": weighted_total,
            "empty_lines": int(totals["empty_lines"]),
            "out_of_range_entries": int(totals["out_of_range_entries"]),
            "zero_weight_entries": int(totals["zero_weight_entries"]),
            "malformed_frequency_entries": int(totals["malformed_frequency_entries"]),
            "plain_records": int(totals["plain_records"]),
            "frequency_records": int(totals["frequency_records"]),
            "input_format": input_format,
        },
        "length": {
            "minimum": int(totals["min_length"]) if unweighted_total else None,
            "maximum": int(totals["max_length"]) if unweighted_total else None,
            "weighted_mean": round(weighted_mean, 3),
            "unweighted_mean": round(unweighted_mean, 3),
            "weighted_histogram": length_weighted,
            "unweighted_histogram": length_unweighted,
        },
        "composition": {
            "weighted_class_presence": presence_weighted,
            "unweighted_class_presence": presence_unweighted,
            "weighted_class_combinations": combinations_weighted,
            "unweighted_class_combinations": combinations_unweighted,
            "weighted_single_class_only": int(totals["weighted_single_class_only"]),
            "weighted_multi_class": int(totals["weighted_multi_class"]),
            "unweighted_single_class_only": int(totals["unweighted_single_class_only"]),
            "unweighted_multi_class": int(totals["unweighted_multi_class"]),
        },
        "input_coverage": {
            "nonempty_lines": nonempty_lines,
            "profiled_entries": unweighted_total,
            "excluded_nonempty_entries": excluded_nonempty_lines,
            "entry_acceptance_rate": round(100.0 * unweighted_total / nonempty_lines, 6) if nonempty_lines else 0.0,
        },
        "diversity": {
            "weighted_class_combinations": _entropy_metrics(combinations_weighted),
            "unweighted_class_combinations": _entropy_metrics(combinations_unweighted),
        },
        "weighted_vs_unweighted": {
            "length_distribution_delta_percentage_points": {
                key: round(_distribution(length_weighted, weighted_total)[key] - _distribution(length_unweighted, unweighted_total)[key], 6)
                for key in length_weighted
            },
            "class_combination_distribution_delta_percentage_points": {
                key: round(
                    _distribution(combinations_weighted, weighted_total).get(key, 0.0)
                    - _distribution(combinations_unweighted, unweighted_total).get(key, 0.0),
                    6,
                )
                for key in sorted(set(combinations_weighted) | set(combinations_unweighted))
            },
            "class_presence_delta_percentage_points": {
                key: round(
                    _distribution(presence_weighted, weighted_total)[key]
                    - _distribution(presence_unweighted, unweighted_total)[key],
                    6,
                )
                for key in _CLASS_ORDER
            },
            "mean_length_delta": round(weighted_mean - unweighted_mean, 6),
        },
        "policy_indicators": {
            "weighted_under_8_characters": int(totals["weighted_under_8"]),
            "weighted_under_12_characters": int(totals["weighted_under_12"]),
            "weighted_at_least_12_characters": int(totals["weighted_at_least_12"]),
            "unweighted_under_8_characters": int(totals["unweighted_under_8"]),
            "unweighted_under_12_characters": int(totals["unweighted_under_12"]),
            "unweighted_at_least_12_characters": int(totals["unweighted_at_least_12"]),
        },
        "weight_diagnostics": _build_weight_diagnostics(
            weight_histogram=weight_histogram,
            top_weights=top_weights,
            count=unweighted_total,
            weight_sum=weighted_total,
            minimum=minimum_weight,
            maximum=maximum_weight,
            unit_weight_count=int(totals["unit_weight_entries"]),
            frequency_weighted_count=int(totals["frequency_weighted_entries"]),
            int64_exceeding_entries=int64_exceeding_entries,
            safe_json_exceeding_entries=safe_json_exceeding_entries,
        ),
        "privacy": {
            "raw_values_retained": False,
            "raw_values_emitted": False,
            "duplicate_lines_deduplicated": False,
            "frequency_lines_weighted_by_leading_count": input_format != "plain",
            "note": (
                "Aggregate composition metrics only. No passwords, substrings, affixes, "
                "candidate values, or rule suggestions are included."
            ),
        },
    }
    profile["profile_consistency"] = _consistency_checks(profile)
    return profile


def compare_profiles(reference: dict, candidate: dict) -> dict:
    """Compare two aggregate profiles using percentage-point deltas only."""
    for label, profile in (("reference", reference), ("candidate", candidate)):
        if profile.get("schema") != PROFILE_SCHEMA:
            raise ValueError(f"{label} profile has an unsupported schema")
        if profile.get("profile_type") != "aggregate_password_composition":
            raise ValueError(f"{label} profile has an unsupported profile type")

    def delta_distribution(
        section: str,
        field_weighted: str,
        field_unweighted: str,
    ) -> dict:
        output = {"weighted": {}, "unweighted": {}}
        for mode, field, total_key in (
            ("weighted", field_weighted, "weighted_observations"),
            ("unweighted", field_unweighted, "profiled_entries"),
        ):
            left = reference.get(section, {}).get(field)
            right = candidate.get(section, {}).get(field)
            if left is None or right is None:
                output[mode] = None
                continue
            left_total = reference["input"][total_key]
            right_total = candidate["input"][total_key]
            for key in sorted(set(left) | set(right)):
                left_pct = 100.0 * _ratio(left.get(key, 0), left_total) if left_total else 0.0
                right_pct = 100.0 * _ratio(right.get(key, 0), right_total) if right_total else 0.0
                output[mode][key] = round(right_pct - left_pct, 6)
        return output

    reference_diversity = reference.get("diversity")
    candidate_diversity = candidate.get("diversity")
    diversity_delta = {}
    for mode in ("weighted_class_combinations", "unweighted_class_combinations"):
        if reference_diversity is None or candidate_diversity is None or mode not in reference_diversity:
            diversity_delta[mode] = None
        else:
            diversity_delta[mode] = {
                key: round(
                    candidate_diversity[mode][key] - reference_diversity[mode][key], 6
                )
                for key in ("shannon_entropy_bits", "normalized_entropy", "effective_categories")
            }

    return {
        "schema": COMPARISON_SCHEMA,
        "reference": {
            "file_name": reference["input"].get("file_name"),
            "profiled_entries": reference["input"]["profiled_entries"],
            "weighted_observations": reference["input"]["weighted_observations"],
        },
        "candidate": {
            "file_name": candidate["input"].get("file_name"),
            "profiled_entries": candidate["input"]["profiled_entries"],
            "weighted_observations": candidate["input"]["weighted_observations"],
        },
        "size_delta": {
            "profiled_entries": candidate["input"]["profiled_entries"] - reference["input"]["profiled_entries"],
            "weighted_observations": candidate["input"]["weighted_observations"] - reference["input"]["weighted_observations"],
            "weighted_mean_length": round(candidate["length"]["weighted_mean"] - reference["length"]["weighted_mean"], 6),
            "unweighted_mean_length": (
                round(candidate["length"]["unweighted_mean"] - reference["length"]["unweighted_mean"], 6)
                if "unweighted_mean" in reference["length"] else None
            ),
        },
        "length_distribution_delta_percentage_points": delta_distribution(
            "length", "weighted_histogram", "unweighted_histogram"
        ),
        "class_combination_distribution_delta_percentage_points": delta_distribution(
            "composition", "weighted_class_combinations", "unweighted_class_combinations"
        ),
        "class_presence_delta_percentage_points": delta_distribution(
            "composition", "weighted_class_presence", "unweighted_class_presence"
        ),
        "class_diversity_delta": diversity_delta,
        "input_coverage_delta_percentage_points": (
            round(
                candidate["input_coverage"]["entry_acceptance_rate"]
                - reference["input_coverage"]["entry_acceptance_rate"], 6
            ) if "input_coverage" in reference else None
        ),
        "profile_consistency": {
            "reference_valid": reference.get("profile_consistency", {}).get("valid"),
            "candidate_valid": candidate.get("profile_consistency", {}).get("valid"),
        },
    }


def write_profile(profile: dict, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(profile, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def _percent(part: int, total: int) -> str:
    return f"{(100.0 * _ratio(part, total)):5.1f}%" if total else "  0.0%"


def print_summary(profile: dict, output_path: Optional[Path] = None) -> None:
    source = profile["input"]
    total = source["weighted_observations"]
    print("[pcfg-profile] aggregate composition profile")
    print(
        f"  entries={source['profiled_entries']:,} "
        f"weighted_observations={total:,} "
        f"skipped={source['empty_lines'] + source['out_of_range_entries'] + source['zero_weight_entries'] + source.get('malformed_frequency_entries', 0):,}"
    )
    length = profile["length"]
    print(
        f"  length: min={length['minimum']} max={length['maximum']} "
        f"weighted_mean={length['weighted_mean']:.2f} unweighted_mean={length['unweighted_mean']:.2f}"
    )
    for bucket, count in length["weighted_histogram"].items():
        print(f"    {bucket:>5}: {count:>12,} ({_percent(count, total)})")
    coverage = profile["input_coverage"]
    print(
        f"  input coverage: accepted={coverage['entry_acceptance_rate']:.2f}% "
        f"({coverage['profiled_entries']:,}/{coverage['nonempty_lines']:,} non-empty lines)"
    )
    diversity = profile["diversity"]["weighted_class_combinations"]
    print(
        f"  diversity: entropy={diversity['shannon_entropy_bits']:.3f} bits "
        f"effective_categories={diversity['effective_categories']:.2f}"
    )
    weights = profile["weight_diagnostics"]
    top1_share = weights["top_weight_concentration"]["top_1"]["share_of_total_percent"]
    p95 = weights["weight_p95_approx"]
    p95_bucket = p95["bucket"] if p95 is not None else "n/a"
    print(
        f"  weights: min={weights['weight_min']} max={weights['weight_max']} "
        f"mean={weights['mean_weight_per_entry']:.3f} p95~={p95_bucket} "
        f"top1_share={top1_share:.3f}% "
        f"entries>1={weights['entries_with_weight_above_one']:,}"
    )
    print(
        f"  input format: mode={source.get('input_format', 'legacy')} "
        f"plain={source.get('plain_records', 'n/a'):,} "
        f"frequency={source.get('frequency_records', 'n/a'):,} "
        f"malformed={source.get('malformed_frequency_entries', 0):,}"
    )
    safety = weights["integer_safety"]
    if safety["weighted_total_exceeds_signed_int64"] or safety["max_single_weight_exceeds_signed_int64"]:
        print("  WARNING: weights exceed signed int64; retain arbitrary-precision integers")
    if source.get("input_format") == "auto" and source["frequency_records"]:
        print("  note: auto format interprets leading digits + whitespace as COUNT VALUE; use --input-format plain to disable this")
    consistency = profile["profile_consistency"]
    print(f"  consistency: {'PASS' if consistency['valid'] else 'FAIL'}")
    if output_path is not None:
        print(f"  report={output_path}")


def run_profile(
    target_path: Path,
    output_path: Path,
    encoding: str = "latin-1",
    compare_path: Optional[Path] = None,
    input_format: str = "auto",
) -> dict:
    profile = profile_wordlist(target_path, encoding=encoding, input_format=input_format)
    if compare_path is not None:
        with compare_path.open("r", encoding="utf-8") as handle:
            reference = json.load(handle)
        profile["comparison"] = compare_profiles(reference, profile)
    write_profile(profile, output_path)
    return profile


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pcfg-profile",
        description="Create an aggregate-only PCFG corpus composition profile (no rule generation).",
    )
    parser.add_argument("target", type=Path, help="Input wordlist or frequency-formatted wordlist")
    parser.add_argument("-o", "--output", type=Path, default=Path("pcfg_profile.json"))
    parser.add_argument("--encoding", default="latin-1")
    parser.add_argument(
        "--input-format", choices=("auto", "plain", "count-value"), default="auto",
        help="auto=legacy detection; plain=never parse leading counts; count-value=require COUNT VALUE rows",
    )
    parser.add_argument("--compare", type=Path, help="Compare against an earlier aggregate profile JSON")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not args.target.is_file():
        print(f"error: target not found: {args.target}", file=sys.stderr)
        return 1
    if args.compare is not None and not args.compare.is_file():
        print(f"error: comparison profile not found: {args.compare}", file=sys.stderr)
        return 1

    try:
        profile = run_profile(
            args.target, args.output, encoding=args.encoding, compare_path=args.compare,
            input_format=args.input_format,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: unable to profile target: {exc}", file=sys.stderr)
        return 1
    print_summary(profile, args.output)
    if "comparison" in profile:
        print("  comparison: included in report")
    return 0 if profile["profile_consistency"]["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
