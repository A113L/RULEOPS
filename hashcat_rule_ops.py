"""Hashcat 8.0 byte-level helpers shared by RULEOPS rule interpreters.

The shift-case mapping mirrors Hashcat's ``cshift_lookup`` table from
``src/rp_cpu.c``. All transformations operate on raw bytes, not Unicode
code points, matching Hashcat's rule engine semantics.
"""
from __future__ import annotations

from typing import Iterable, Optional


# XOR masks for printable ASCII characters in Hashcat's US keyboard layout.
_SHIFT_CASE_MASK = {
    33: 16, 34: 5, 35: 16, 36: 16, 37: 16, 38: 17, 39: 5, 40: 17,
    41: 25, 42: 18, 43: 22, 44: 16, 45: 114, 46: 16, 47: 16,
    48: 25, 49: 16, 50: 114, 51: 16, 52: 16, 53: 16, 54: 104,
    55: 17, 56: 18, 57: 17, 58: 1, 59: 1, 60: 16, 61: 22,
    62: 16, 63: 16, 64: 114,
    94: 104, 95: 114, 96: 30, 126: 30,
}


def hashcat_shift_case_byte(value: int) -> int:
    """Apply Hashcat's ``S`` keyboard shift mapping to one byte."""
    value &= 0xFF
    mask = _SHIFT_CASE_MASK.get(value)
    if mask is None:
        if 65 <= value <= 93 or 97 <= value <= 125:
            mask = 32
        else:
            mask = 0
    return value ^ mask


def apply_hashcat8_operator(
    operator: str,
    data: Iterable[int],
    position: Optional[int] = None,
    argument: Optional[int] = None,
) -> list[int]:
    """Apply one of Hashcat 8's new operators to a byte sequence.

    ``h``/``H`` turn each input byte into two ASCII hex digits;
    ``S`` applies the keyboard shift map; ``vNX`` inserts X after every N
    bytes (including the end when the input length is divisible by N);
    ``BNX`` adds byte X modulo 256 at zero-based position N.

    Positions/counts are supplied already decoded from Hashcat base-36.
    """
    source = [int(value) & 0xFF for value in data]
    if operator == "h":
        return list(bytes(source).hex().encode("ascii"))
    if operator == "H":
        return list(bytes(source).hex().upper().encode("ascii"))
    if operator == "S":
        return [hashcat_shift_case_byte(value) for value in source]
    if operator == "v":
        n = int(position or 0)
        if n <= 0:
            return source
        out: list[int] = []
        insert = int(argument or 0) & 0xFF
        for index, value in enumerate(source, 1):
            out.append(value)
            if index % n == 0:
                out.append(insert)
        return out
    if operator == "B":
        n = int(position if position is not None else -1)
        if 0 <= n < len(source):
            source[n] = (source[n] + (int(argument or 0) & 0xFF)) & 0xFF
        return source
    raise ValueError(f"Unsupported Hashcat 8 operator: {operator!r}")


def decode_base36(value: str) -> int:
    """Decode one Hashcat position/count character (0-9, A-Z, a-z)."""
    if len(value) != 1:
        return -1
    char = value
    if "0" <= char <= "9":
        return ord(char) - ord("0")
    if "A" <= char <= "Z":
        return ord(char) - ord("A") + 10
    if "a" <= char <= "z":
        return ord(char) - ord("a") + 10
    return -1
