from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _load_aether_without_opencl():
    fake_opencl = types.ModuleType("pyopencl")
    fake_opencl.Buffer = object
    spec = importlib.util.spec_from_file_location("aether_discovery_test", ROOT / "aether.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"pyopencl": fake_opencl}):
        spec.loader.exec_module(module)
    return module


def test_aether_accepts_the_same_rule_extensions_as_the_web_ui(tmp_path: Path) -> None:
    aether = _load_aether_without_opencl()
    expected = {".rule", ".rules", ".hr", ".hashcat", ".txt"}
    for suffix in expected:
        (tmp_path / f"sample{suffix}").write_text("l$1\n", encoding="ascii")
    (tmp_path / "ignored.csv").write_text("l$1\n", encoding="ascii")

    discovered = {Path(item).suffix.lower() for item in aether.find_rule_files([str(tmp_path)])}
    assert discovered == expected


def test_aether_accepts_uppercase_rule_extensions(tmp_path: Path) -> None:
    aether = _load_aether_without_opencl()
    source = tmp_path / "sample.RULES"
    source.write_text("h\n", encoding="ascii")
    assert aether.find_rule_files([str(source)]) == [str(source)]
