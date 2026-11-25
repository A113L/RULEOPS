"""Shared Hashcat rule tokenization and readable output formatting.

The ``expanded`` representation is the same operator+argument token layout
used by Concentrator's Expanded output mode. It is intended for readable
RULEOPS rule files; use ``line`` format when a compact Hashcat rules file is
required by downstream tools that expect concatenated operators.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set

PRINTABLE_ASCII = set(chr(i) for i in range(32, 127))

# Operator -> argument kinds. Keep this definition shared by Concentrator and
# RULEST so both tools emit and parse the same Expanded representation.
OPERATOR_ARGS: Dict[str, List[str]] = {
    ':': [], 'l': [], 'u': [], 'c': [], 'C': [], 't': [], 'r': [], 'd': [], 'f': [],
    'h': [], 'H': [], 'S': [],
    '{': [], '}': [], '[': [], ']': [], 'q': [], 'M': [], '4': [], '6': [], 'k': [], 'K': [],
    'Q': [], 'E': [],
    'T': ['num'], 'p': ['num'], 'D': ['num'], 'z': ['num'], 'Z': ['num'], "'": ['num'],
    '+': ['num'], '-': ['num'], '.': ['num'], ',': ['num'], 'L': ['num'], 'R': ['num'],
    'y': ['num'], 'Y': ['num'], '<': ['num'], '>': ['num'], '_': ['num'],
    'x': ['num', 'num'], 'O': ['num', 'num'], '*': ['num', 'num'],
    '$': ['char'], '^': ['char'], '@': ['char'], '!': ['char'], '/': ['char'],
    '(': ['char'], ')': ['char'],
    's': ['char', 'char'],
    'i': ['num', 'char'], 'o': ['num', 'char'], '=': ['num', 'char'], '%': ['num', 'char'],
    '3': ['num', 'char'], 'v': ['num', 'char'], 'B': ['num', 'char'],
    'X': ['num', 'num', 'num'],
    'e': ['char'],
}
ALL_OPERATORS = list(OPERATOR_ARGS.keys())
ALL_RULE_CHARS: Set[str] = PRINTABLE_ASCII - {' '}


def _build_token_regex() -> re.Pattern:
    patterns = []
    for op, args in OPERATOR_ARGS.items():
        escaped = re.escape(op)
        arg_pat = ''.join('[0-9A-Z]' if arg == 'num' else '[ -~]' for arg in args)
        patterns.append(escaped + arg_pat)
    patterns.sort(key=len, reverse=True)
    return re.compile('|'.join(patterns))


def _build_count_regex() -> re.Pattern:
    patterns = [re.escape(op) for op in ALL_OPERATORS]
    patterns.sort(key=len, reverse=True)
    return re.compile('|'.join(patterns))


TOKEN_REGEX = _build_token_regex()
OPERATOR_REGEX = _build_count_regex()
OPERATORS_REQUIRING_ARGS = {op: len(args) for op, args in OPERATOR_ARGS.items() if args}


def expand_hashcat_rule(rule: str) -> str:
    """Separate every Hashcat operator+argument token with one space.

    Existing spaces are treated as Expanded-format separators, so the helper
    is idempotent for already-expanded rules.
    """
    return ' '.join(TOKEN_REGEX.findall(str(rule)))


def format_hashcat_rule(rule: str, output_format: str = 'line') -> str:
    """Format one rule as compact ``line`` or token-spaced ``expanded``."""
    if output_format == 'line':
        return str(rule)
    if output_format == 'expanded':
        return expand_hashcat_rule(str(rule))
    raise ValueError(f"Unsupported Hashcat rule output format: {output_format}")
