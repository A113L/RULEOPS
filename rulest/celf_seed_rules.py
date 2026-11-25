"""Load small, curated rule files as additional CELF candidates.

These rules are not preselected. They pass the same GPU compatibility and
chain-depth checks as generated candidates, then CELF evaluates their exact
marginal target coverage alongside the rest of the candidate pool.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .common import HashcatRuleValidator, MAX_CHAIN_STRING_LEN, MAX_HASHCAT_CHAIN, _kb


@dataclass
class CelfSeedLoadStats:
    files: int = 0
    lines: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    already_present: int = 0
    over_depth: int = 0
    capped: bool = False


def load_celf_seed_rules(
    paths: Iterable[str | Path],
    *,
    max_rules: int = 1000,
    max_depth: int = MAX_HASHCAT_CHAIN,
    existing_rules: Iterable[str] = (),
) -> tuple[list[str], CelfSeedLoadStats]:
    """Read up to ``max_rules`` unique, valid rules from one or more files.

    File order is preserved, so users can put their most trusted rules first.
    ``existing_rules`` prevents a file candidate from duplicating a rule that
    the normal extraction pipeline has already produced.  A value of zero for
    ``max_rules`` disables the import and negative limits are rejected.
    """
    limit = int(max_rules)
    if limit < 0:
        raise ValueError("CELF seed rule limit must be 0 or greater")
    depth_limit = max(1, min(MAX_HASHCAT_CHAIN, int(max_depth)))
    stats = CelfSeedLoadStats()
    if limit == 0:
        return [], stats

    known = set(existing_rules)
    loaded: list[str] = []
    loaded_set: set[str] = set()

    for raw_path in paths:
        if _kb.poll():
            break
        path = Path(raw_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"CELF seed rules file not found: {path}")
        stats.files += 1
        with path.open("r", encoding="latin-1", newline=None) as handle:
            for line_number, line in enumerate(handle, 1):
                if line_number % 2048 == 0 and _kb.poll():
                    return loaded, stats
                stats.lines += 1
                rule = line.strip()
                if not rule or rule.startswith("#"):
                    continue
                if rule == ":" or not rule.isascii() or not HashcatRuleValidator.validate_rule_for_gpu(rule):
                    stats.invalid += 1
                    continue
                tokens = rule.split()
                if len(tokens) > depth_limit:
                    stats.over_depth += 1
                    continue
                encoded_len = sum(len(token) for token in tokens) + max(0, len(tokens) - 1)
                if (not tokens or len(tokens) > MAX_HASHCAT_CHAIN
                        or encoded_len > MAX_CHAIN_STRING_LEN - 2):
                    stats.invalid += 1
                    continue
                if rule in known:
                    stats.already_present += 1
                    continue
                if rule in loaded_set:
                    stats.duplicates += 1
                    continue
                loaded.append(rule)
                loaded_set.add(rule)
                stats.valid += 1
                if len(loaded) >= limit:
                    stats.capped = True
                    return loaded, stats

    return loaded, stats
