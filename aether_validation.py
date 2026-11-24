#!/usr/bin/env python3
"""Hashcat 8 rule-file validation and Aether-kernel compatibility checks.

The validator deliberately separates three questions:
1. Is the line syntactically valid Hashcat 8 rule syntax?
2. Is it legal in a rule file passed with ``-r`` (rather than CLI ``-j/-k``)?
3. Can the current Aether OpenCL interpreter benchmark every operation in the rule chain faithfully?

Only lines passing all three checks are sent to the Aether kernel. Supported
Hashcat -r command chains are executed sequentially; valid commands not yet
implemented by the kernel are reported separately.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
import json

HASHCAT_MAX_RULE_OPERATIONS = 31
AETHER_MAX_RULE_BYTES = 255  # one byte is reserved for the packed-buffer terminator
BASE36 = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
CLASS_CODES = frozenset("ludshHab")

# Operations accepted in ordinary Hashcat rule files.
NO_ARG_OPS = frozenset(":lucCSt rdf{}[]qkKhHE".replace(" ", ""))
ONE_BASE36_OPS = frozenset("TDLR+-. ,'pzyZY".replace(" ", ""))
TWO_BASE36_OPS = frozenset("xO*")
ONE_CHAR_OPS = frozenset("$^@e")
TWO_CHAR_OPS = frozenset("s")
NUM_CHAR_OPS = frozenset("iovB3")

# These are syntactically meaningful to Hashcat, but are only accepted in
# command-line -j/-k rules, not in a normal -r rule file.
CLI_ONLY_NO_ARG = frozenset("M46Q")
CLI_ONLY_ONE_BASE36 = frozenset("<>_")
CLI_ONLY_ONE_CHAR = frozenset("!/()")
CLI_ONLY_NUM_CHAR = frozenset("=%")
CLI_ONLY_THREE_BASE36 = frozenset("X")
CLI_ONLY_OPS = (
    CLI_ONLY_NO_ARG | CLI_ONLY_ONE_BASE36 | CLI_ONLY_ONE_CHAR |
    CLI_ONLY_NUM_CHAR | CLI_ONLY_THREE_BASE36
)

# Aether executes supported Hashcat -r command chains sequentially in its
# OpenCL kernel. These sets describe the commands implemented by that kernel;
# syntactically valid Hashcat commands outside the sets remain reportable as
# unsupported rather than being silently benchmarked as identity operations.
AETHER_NO_ARG = frozenset(":lucCSt rdf{}[]qkKhHE".replace(" ", ""))
AETHER_ONE_BASE36 = frozenset("TDLR+-. ,'pzyZY".replace(" ", ""))
AETHER_TWO_BASE36 = frozenset("xO*")
AETHER_ONE_CHAR = frozenset("$^@e")
AETHER_TWO_CHAR = frozenset("s")
AETHER_NUM_CHAR = frozenset("iovB3")


@dataclass
class RuleLineResult:
    line_number: int
    rule: str
    status: str
    reason: str = ""
    operation_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _is_base36(value: str) -> bool:
    return len(value) == 1 and value in BASE36


def _consume_operand(text: str, pos: int) -> tuple[str, int, int, bool] | None:
    """Consume one literal or Hashcat ``\\xHH`` operand.

    Returns (source spelling, new position, byte count, escaped flag).
    Whitespace is intentionally accepted here as a literal operand.
    """
    if pos >= len(text):
        return None
    if text.startswith("\\x", pos) and pos + 4 <= len(text):
        hex_part = text[pos + 2:pos + 4]
        if all(ch in "0123456789abcdefABCDEF" for ch in hex_part):
            return text[pos:pos + 4], pos + 4, 1, True
    char = text[pos]
    try:
        byte_count = len(char.encode("utf-8", "surrogateescape"))
    except UnicodeEncodeError:
        byte_count = 1
    return char, pos + 1, byte_count, False


def _parse_rule(rule: str) -> tuple[str, str, int, list[tuple[str, str]]]:
    """Return (status, reason, op_count, parsed operation signatures)."""
    pos = 0
    op_count = 0
    signatures: list[tuple[str, str]] = []
    cli_only_reason = ""
    non_ascii_or_escape = False

    def consume_char_arg(index: int) -> tuple[str, int, int] | None:
        nonlocal non_ascii_or_escape
        item = _consume_operand(rule, index)
        if item is None:
            return None
        spelling, next_pos, byte_count, escaped = item
        if escaped or any(ord(ch) > 127 for ch in spelling):
            non_ascii_or_escape = True
        return spelling, next_pos, byte_count

    while pos < len(rule):
        # Hashcat ignores whitespace between commands, but a space is still a
        # valid literal when consumed by an argument-taking operator.
        if rule[pos].isspace():
            pos += 1
            continue

        op = rule[pos]
        pos += 1
        args = ""
        arg_bytes = 0

        if op == "~":
            if pos >= len(rule):
                return "invalid", "Incomplete character-class command after '~'.", op_count, signatures
            class_op = rule[pos]
            pos += 1
            if class_op in ("s", "@", "e"):
                if pos >= len(rule) or rule[pos] != "?":
                    return "invalid", f"Character-class operator '~{class_op}' must be followed by '?'.", op_count, signatures
                pos += 1
                if pos >= len(rule) or rule[pos] not in CLASS_CODES:
                    return "invalid", "Unknown or missing Hashcat character class after '?'.", op_count, signatures
                class_code = rule[pos]
                pos += 1
                args = class_code
                if class_op == "s":
                    operand = consume_char_arg(pos)
                    if operand is None:
                        return "invalid", "'~s?C' requires a replacement character.", op_count, signatures
                    spelling, pos, arg_bytes = operand
                    args += spelling
            elif class_op in ("!", "/", "(", ")"):
                if pos >= len(rule) or rule[pos] != "?":
                    return "invalid", f"Character-class reject '~{class_op}' must be followed by '?'.", op_count, signatures
                pos += 1
                if pos >= len(rule) or rule[pos] not in CLASS_CODES:
                    return "invalid", "Unknown or missing Hashcat character class after '?'.", op_count, signatures
                args = rule[pos]
                pos += 1
                cli_only_reason = "Character-class reject commands are only supported with Hashcat -j/-k, not as -r rule-file entries."
            elif class_op in ("=", "%"):
                if pos >= len(rule) or not _is_base36(rule[pos]):
                    return "invalid", f"'~{class_op}' requires a base-36 position/count before '?'.", op_count, signatures
                args = rule[pos]
                pos += 1
                if pos >= len(rule) or rule[pos] != "?":
                    return "invalid", f"'~{class_op}' requires '?<class>' after its position/count.", op_count, signatures
                pos += 1
                if pos >= len(rule) or rule[pos] not in CLASS_CODES:
                    return "invalid", "Unknown or missing Hashcat character class after '?'.", op_count, signatures
                args += rule[pos]
                pos += 1
                cli_only_reason = "Character-class reject commands are only supported with Hashcat -j/-k, not as -r rule-file entries."
            else:
                return "invalid", f"Unknown Hashcat character-class operator '~{class_op}'.", op_count, signatures
            op_count += 1
            signatures.append(("~" + class_op, args))
            continue

        if op in NO_ARG_OPS or op in CLI_ONLY_NO_ARG:
            signatures.append((op, ""))
            op_count += 1
            if op in CLI_ONLY_NO_ARG:
                cli_only_reason = f"Operator '{op}' is only available in Hashcat -j/-k rules, not in a -r rule file."
            continue

        if op in ONE_BASE36_OPS or op in CLI_ONLY_ONE_BASE36:
            if pos >= len(rule) or not _is_base36(rule[pos]):
                return "invalid", f"Operator '{op}' requires one base-36 argument (0-9 or A-Z).", op_count, signatures
            args = rule[pos]
            pos += 1
            op_count += 1
            signatures.append((op, args))
            if op in CLI_ONLY_ONE_BASE36:
                cli_only_reason = f"Reject operator '{op}' is only available in Hashcat -j/-k rules, not in a -r rule file."
            continue

        if op in TWO_BASE36_OPS:
            if pos + 1 >= len(rule) or not _is_base36(rule[pos]) or not _is_base36(rule[pos + 1]):
                return "invalid", f"Operator '{op}' requires two base-36 arguments.", op_count, signatures
            args = rule[pos:pos + 2]
            pos += 2
            op_count += 1
            signatures.append((op, args))
            continue

        if op in ONE_CHAR_OPS or op in CLI_ONLY_ONE_CHAR:
            operand = consume_char_arg(pos)
            if operand is None:
                return "invalid", f"Operator '{op}' requires one character argument.", op_count, signatures
            args, pos, arg_bytes = operand
            op_count += max(1, arg_bytes) if op in ("$", "^") else 1
            signatures.append((op, args))
            if op in CLI_ONLY_ONE_CHAR:
                cli_only_reason = f"Reject operator '{op}' is only available in Hashcat -j/-k rules, not in a -r rule file."
            continue

        if op in TWO_CHAR_OPS:
            first = consume_char_arg(pos)
            if first is None:
                return "invalid", "Operator 's' requires two character arguments.", op_count, signatures
            first_arg, pos, first_bytes = first
            second = consume_char_arg(pos)
            if second is None:
                return "invalid", "Operator 's' requires two character arguments.", op_count, signatures
            second_arg, pos, second_bytes = second
            args = first_arg + second_arg
            op_count += 1
            signatures.append((op, args))
            continue

        if op in NUM_CHAR_OPS or op in CLI_ONLY_NUM_CHAR:
            if pos >= len(rule) or not _is_base36(rule[pos]):
                return "invalid", f"Operator '{op}' requires a base-36 position/count argument first.", op_count, signatures
            number = rule[pos]
            pos += 1
            operand = consume_char_arg(pos)
            if operand is None:
                return "invalid", f"Operator '{op}' requires a character argument after its position/count.", op_count, signatures
            char_arg, pos, arg_bytes = operand
            args = number + char_arg
            op_count += max(1, arg_bytes) if op in ("i", "o", "v") else 1
            signatures.append((op, args))
            if op in CLI_ONLY_NUM_CHAR:
                cli_only_reason = f"Reject operator '{op}' is only available in Hashcat -j/-k rules, not in a -r rule file."
            continue

        if op == "N":
            if pos >= len(rule) or not _is_base36(rule[pos]):
                return "invalid", "Operator 'N' requires a base-36 occurrence index followed by two characters.", op_count, signatures
            number = rule[pos]
            pos += 1
            first = consume_char_arg(pos)
            if first is None:
                return "invalid", "Operator 'N' requires a character to match.", op_count, signatures
            first_arg, pos, first_bytes = first
            second = consume_char_arg(pos)
            if second is None:
                return "invalid", "Operator 'N' requires a replacement character.", op_count, signatures
            second_arg, pos, second_bytes = second
            args = number + first_arg + second_arg
            op_count += 1
            signatures.append((op, args))
            continue

        if op == "X":
            if pos + 2 >= len(rule) or any(not _is_base36(ch) for ch in rule[pos:pos + 3]):
                return "invalid", "Operator 'X' requires three base-36 arguments.", op_count, signatures
            args = rule[pos:pos + 3]
            pos += 3
            op_count += 1
            signatures.append((op, args))
            cli_only_reason = "Memory extraction operator 'X' is only available in Hashcat -j/-k rules, not in a -r rule file."
            continue

        return "invalid", f"Unknown Hashcat rule operator '{op}'.", op_count, signatures

    if op_count == 0:
        return "invalid", "Empty rule.", 0, signatures
    if op_count > HASHCAT_MAX_RULE_OPERATIONS:
        return "invalid", f"Rule expands to {op_count} operations; Hashcat allows at most {HASHCAT_MAX_RULE_OPERATIONS}.", op_count, signatures
    if cli_only_reason:
        return "cli_only", cli_only_reason, op_count, signatures

    # The kernel does not parse escaped-byte operands or direct UTF-8 byte
    # sequences; those lines are valid Hashcat rules but not safely benchmarkable.
    if non_ascii_or_escape:
        return "unsupported", "Valid Hashcat rule, but Aether's current OpenCL kernel only supports literal ASCII operands (not \\xHH escapes or UTF-8 multi-byte operands).", op_count, signatures

    for op, args in signatures:
        supported = (
            (op in AETHER_NO_ARG and not args)
            or (op in AETHER_ONE_BASE36 and len(args) == 1)
            or (op in AETHER_TWO_BASE36 and len(args) == 2)
            or (op in AETHER_ONE_CHAR and len(args) == 1)
            or (op in AETHER_TWO_CHAR and len(args) == 2)
            or (op in AETHER_NUM_CHAR and len(args) == 2)
        )
        if not supported:
            return "unsupported", f"Valid Hashcat rule, but operator '{op}' is not implemented by the current Aether OpenCL interpreter.", op_count, signatures
    return "valid", "", op_count, signatures


def validate_rule_lines(lines: Iterable[str]) -> dict[str, Any]:
    """Validate iterable source lines and return benchmark-ready rules + stats."""
    results: list[RuleLineResult] = []
    benchmark_rules: list[dict[str, Any]] = []
    blank = comments = 0

    for line_number, raw_line in enumerate(lines, 1):
        # Drop line terminators only. Do not strip trailing spaces: a literal
        # space may be an operator argument (for example, ``$ ``).
        line = raw_line.rstrip("\r\n")
        if line_number == 1 and line.startswith("\ufeff"):
            # str.removeprefix() was added in Python 3.9; Aether also runs in
            # Python 3.8 environments, so remove the UTF-8 BOM compatibly.
            line = line[1:]
        if not line or line.isspace():
            blank += 1
            continue
        if line.lstrip().startswith("#"):
            comments += 1
            continue

        candidate = line.lstrip()
        status, reason, operations, _signatures = _parse_rule(candidate)
        encoded_length = len(candidate.encode("utf-8", "surrogateescape"))
        if status == "valid" and encoded_length > AETHER_MAX_RULE_BYTES:
            status = "unsupported"
            reason = (
                f"Valid Hashcat rule, but its {encoded_length}-byte source line exceeds "
                f"Aether's {AETHER_MAX_RULE_BYTES}-byte packed rule limit."
            )
        result = RuleLineResult(line_number, candidate, status, reason, operations)
        results.append(result)
        if status == "valid":
            benchmark_rules.append({"line_number": line_number, "rule": candidate, "operation_count": operations})

    counts = {
        "total_lines": 0,
        "active_rules": len(results),
        "benchmarkable_rules": sum(1 for item in results if item.status == "valid"),
        "invalid_rules": sum(1 for item in results if item.status == "invalid"),
        "cli_only_rules": sum(1 for item in results if item.status == "cli_only"),
        "unsupported_rules": sum(1 for item in results if item.status == "unsupported"),
        "comment_lines": comments,
        "blank_lines": blank,
    }
    counts["total_lines"] = counts["active_rules"] + comments + blank
    return {
        "summary": counts,
        "benchmark_rules": benchmark_rules,
        "issues": [item.to_dict() for item in results if item.status != "valid"],
        "results": [item.to_dict() for item in results],
    }


def validate_rule_file(path: str | Path) -> dict[str, Any]:
    """Read and validate a UTF-8 (or byte-preserving) Hashcat rule file."""
    source = Path(path)
    with source.open("r", encoding="utf-8-sig", errors="surrogateescape", newline="") as stream:
        report = validate_rule_lines(stream)
    report["source_name"] = source.name
    return report


def validate_rule_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Validate optimizer report records before writing the optimized rule file.

    Each report record represents exactly one rule. Embedded line breaks and
    non-string rule values are rejected rather than being interpreted as
    multiple commands or merged rules.
    """
    source_records = list(records)
    raw_rules: list[str] = []
    malformed_records: set[int] = set()
    for index, record in enumerate(source_records):
        value = record.get("rule") if isinstance(record, dict) else None
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            malformed_records.add(index)
            raw_rules.append("\x00")
        else:
            raw_rules.append(value)

    report = validate_rule_lines(raw_rules)
    valid_rules: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for index, (record, result) in enumerate(zip(source_records, report["results"])):
        if index in malformed_records:
            status = "invalid"
            reason = "Optimizer report entry must contain exactly one rule line as a string."
            rule_text = repr(record.get("rule") if isinstance(record, dict) else record)
        else:
            status = result["status"]
            reason = result["reason"]
            rule_text = result["rule"]

        if status == "valid":
            accepted = dict(record)
            accepted["rule"] = rule_text
            valid_rules.append(accepted)
        else:
            issues.append({
                "record_number": index + 1,
                "rule": rule_text,
                "status": status,
                "reason": reason,
                "operation_count": result.get("operation_count", 0),
            })

    summary = dict(report["summary"])
    return {"valid_rules": valid_rules, "summary": summary, "issues": issues}


def _display_rule_text(rule: str) -> str:
    """Make arbitrary source bytes printable in UTF-8 validation sidecars."""
    pieces: list[str] = []
    for char in str(rule):
        code = ord(char)
        if 0xDC80 <= code <= 0xDCFF:
            pieces.append(f"\\x{code - 0xDC00:02x}")
        elif 0xD800 <= code <= 0xDFFF:
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(char)
    return "".join(pieces)


def write_validation_artifacts(report: dict[str, Any], output_dir: str | Path, base_name: str) -> list[str]:
    """Write a compact JSON report and line-numbered issue lists."""
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    json_path = target / f"{base_name}_validation_report.json"
    public_report = {
        "source_name": report.get("source_name"),
        "summary": report["summary"],
        "issues": report["issues"],
    }
    json_path.write_text(json.dumps(public_report, ensure_ascii=True, indent=2), encoding="utf-8")
    written.append(str(json_path))

    issue_groups = (
        ("invalid_rules", "invalid", "invalid"),
        ("cli_only_rules", "cli_only", "cli_only"),
        ("unsupported_rules", "unsupported", "unsupported_by_aether"),
    )
    for suffix, status, _ in issue_groups:
        entries = [item for item in report["issues"] if item["status"] == status]
        if not entries:
            continue
        path = target / f"{base_name}_{suffix}.txt"
        with path.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(f"# Aether validation: {status}; source={report.get('source_name', '')}\n")
            stream.write("# Format: # line N: reason, followed by the exact source rule on the next line\n\n")
            for item in entries:
                reason = str(item.get("reason", "")).replace("\r", " ").replace("\n", " ")
                stream.write(f"# line {item['line_number']}: {reason}\n")
                stream.write(f"{_display_rule_text(item['rule'])}\n")
        written.append(str(path))
    return written
