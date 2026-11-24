from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hashcat_rule_ops import apply_hashcat8_operator
from aether_validation import validate_rule_lines
from rulest.common import _py_apply_single_rule, _validate_rule_for_gpu_impl
from rulest.kernel_source import GPUCompatibleRulesGenerator, GPU_KERNEL_TEMPLATE
from rulest.rulestripper import HashcatRuleValidator as RulestripperValidator
from rulest.rulestripper import _py_apply_single_rule as rulestripper_apply
from concentrator import is_valid_hashcat_rule, _min_apply_chain
from minimizer import _apply_single, apply_chain


def test_hashcat_8_hex_operators_are_byte_exact() -> None:
    assert bytes(apply_hashcat8_operator("h", b"Az\x00")) == b"417a00"
    assert bytes(apply_hashcat8_operator("H", b"Az\x00")) == b"417A00"
    assert _py_apply_single_rule("h", "Az") == "417a"
    assert _py_apply_single_rule("H", "Az") == "417A"
    assert rulestripper_apply("h", "Az") == "417a"
    assert _min_apply_chain("H", "Az") == "417A"
    assert _apply_single("h", "Az") == "417a"
    assert apply_chain("H", "Az") == "417A"


def test_hashcat_8_shift_case_uses_keyboard_map_not_simple_toggle() -> None:
    source = b"abc123!@#[]{}"
    expected = b"ABC!@#123{}[]"
    assert bytes(apply_hashcat8_operator("S", source)) == expected
    assert _py_apply_single_rule("S", source.decode("ascii")) == expected.decode("ascii")
    assert rulestripper_apply("S", source.decode("ascii")) == expected.decode("ascii")
    assert _min_apply_chain("S", source.decode("ascii")) == expected.decode("ascii")
    assert _apply_single("S", source.decode("ascii")) == expected.decode("ascii")


def test_hashcat_8_insert_every_n_includes_terminal_insert_when_divisible() -> None:
    assert bytes(apply_hashcat8_operator("v", b"abcd", 2, ord("-"))) == b"ab-cd-"
    assert bytes(apply_hashcat8_operator("v", b"abcde", 2, ord("-"))) == b"ab-cd-e"
    assert _py_apply_single_rule("v2-", "abcd") == "ab-cd-"
    assert rulestripper_apply("v2-", "abcd") == "ab-cd-"
    assert _min_apply_chain("v2-", "abcd") == "ab-cd-"
    assert _apply_single("v2-", "abcd") == "ab-cd-"
    assert apply_chain("v2-", "abcde") == "ab-cd-e"


def test_hashcat_8_byte_add_is_modulo_256_and_base36_indexed() -> None:
    assert bytes(apply_hashcat8_operator("B", b"AZ", 1, ord("!"))) == b"A{"
    assert bytes(apply_hashcat8_operator("B", b"A", 0, 0xFF)) == b"@"
    assert _py_apply_single_rule("B0!", "A") == "b"
    assert rulestripper_apply("B0!", "A") == "b"
    assert _min_apply_chain("B0!", "A") == "b"
    assert _apply_single("B0!", "A") == "b"
    # Base-36 B denotes position 11; out-of-range positions are a no-op.
    assert _py_apply_single_rule("BB!", "abc") == "abc"


def test_all_rule_validators_accept_the_five_hashcat_8_operators() -> None:
    rules = ("h", "H", "S", "v2-", "B1!")
    for rule in rules:
        assert _validate_rule_for_gpu_impl(rule), ("RULEST", rule)
        assert RulestripperValidator.validate_rule_for_gpu(rule), ("Rulestripper", rule)
        assert is_valid_hashcat_rule(rule), ("Concentrator", rule)
    report = validate_rule_lines([rule for rule in rules])
    assert report["summary"]["benchmarkable_rules"] == len(rules)
    assert report["summary"]["invalid_rules"] == 0
    assert report["summary"]["unsupported_rules"] == 0


def test_aether_validation_rejects_only_malformed_new_operator_arguments() -> None:
    report = validate_rule_lines(["h", "H", "S", "v2-", "B1!", "v-!", "B?!"])
    statuses = [item["status"] for item in report["results"]]
    assert statuses == ["valid", "valid", "valid", "valid", "valid", "invalid", "invalid"]


def test_rulest_gpu_kernel_and_generator_include_hashcat_8_operators() -> None:
    source = GPU_KERNEL_TEMPLATE
    for token in ("case 'h':", "case 'H':", "case 'S':", "cmd == 'v'", "cmd == 'B'", "shift_case_mask"):
        assert token in source, token

    generated = set(GPUCompatibleRulesGenerator().generate_gpu_compatible_rules())
    assert {"h", "H", "S", "v2-", "B1!"}.issubset(generated)


def test_hashcat_8_new_operators_compose_in_rule_chains() -> None:
    assert _py_apply_single_rule("h", "Az") == "417a"
    assert apply_chain("hB0!", "A") == "U1"


def test_rule_ranker_legacy_validator_accepts_hashcat_8_operators() -> None:
    import ast

    source_path = ROOT / "rule_ranker" / "ranker.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    selected = [
        node for node in tree.body
        if (isinstance(node, ast.FunctionDef) and node.name == "should_exclude_rule")
        or (isinstance(node, ast.ClassDef) and node.name == "HashcatRuleValidator")
    ]
    namespace = {"MAX_GPU_RULES": 255}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source_path), "exec"), namespace)
    validator = namespace["HashcatRuleValidator"]
    should_exclude = namespace["should_exclude_rule"]

    for rule in ("h", "H", "S", "v2-", "B1!"):
        assert validator.validate_rule_for_gpu(rule), rule
        assert not should_exclude(rule), rule
    for rule in ("v-!", "B?!", "hX"):
        assert not validator.validate_rule_for_gpu(rule), rule


def test_all_gpu_rule_engines_contain_hashcat_8_kernel_branches() -> None:
    aether = (ROOT / "aether.py").read_text(encoding="utf-8")
    ranker = (ROOT / "rule_ranker" / "ranker.py").read_text(encoding="utf-8")
    celf = (ROOT / "rule_ranker" / "celf_recompute_gpu.py").read_text(encoding="utf-8")
    rulest = (ROOT / "rulest" / "kernel_source.py").read_text(encoding="utf-8")

    for label, source in (("Rule Ranker", ranker), ("CELF GPU", celf)):
        for marker in ("case 'h':", "case 'H':", "case 'S':", "case 'v'", "case 'B'"):
            assert marker in source, f"{label} is missing {marker}"
    for label, source in (("Aether", aether), ("RULEST", rulest)):
        for marker in ("case 'h':", "case 'H':", "case 'S':"):
            assert marker in source, f"{label} is missing {marker}"
        if label == "Aether":
            for marker in ("case 'v':", "case 'B':", "apply_hashcat_rule"):
                assert marker in source, f"{label} is missing {marker}"
        else:
            for marker in ("cmd == 'v'", "cmd == 'B'"):
                assert marker in source, f"{label} is missing {marker}"
