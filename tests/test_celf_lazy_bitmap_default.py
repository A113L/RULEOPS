"""Epoch-based lazy CELF bitmap initialization remains opt-in."""
from pathlib import Path
import ast


def test_lazy_seen_bitmap_initialization_is_opt_in():
    source_path = Path(__file__).resolve().parents[1] / "rulest" / "gpu_engine.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    engine = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "GPUEngine"
    )
    init = next(node for node in engine.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    assignment = next(
        node for node in ast.walk(init)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Attribute) and target.attr == "_celf_lazy_bitmap_init"
                for target in node.targets)
    )
    # The environment fallback is the last argument to os.environ.get(...).
    call = next(node for node in ast.walk(assignment.value)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "environ")
    assert isinstance(call.args[-1], ast.Constant)
    assert call.args[-1].value == "0"
