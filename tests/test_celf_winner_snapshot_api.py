"""Regression tests for the PyOpenCL CELF winner-snapshot copy API."""
from pathlib import Path
import ast


def test_device_to_device_snapshot_copies_do_not_pass_is_blocking():
    source_path = Path(__file__).resolve().parents[1] / "rulest" / "gpu_engine.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    engine = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "GPUEngine"
    )
    method = next(
        node for node in engine.body
        if isinstance(node, ast.FunctionDef) and node.name == "celf_capture_exact_winner_bitmap"
    )
    copies = [
        node for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "cl"
        and node.func.attr == "enqueue_copy"
    ]
    assert len(copies) == 2, "expected bitmap and epoch device-to-device snapshots"
    for call in copies:
        keywords = {kw.arg for kw in call.keywords}
        assert "src_offset" in keywords
        assert "dst_offset" in keywords
        assert "byte_count" in keywords
        assert "is_blocking" not in keywords, (
            "PyOpenCL's buffer-to-buffer enqueue_copy overload does not accept is_blocking"
        )
