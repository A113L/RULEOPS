"""Regression tests for PyOpenCL winner-ID readback overload arguments."""
import ast
from pathlib import Path


def _engine_method(name):
    source_path = Path(__file__).resolve().parents[1] / "rulest" / "gpu_engine.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    engine = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "GPUEngine"
    )
    return next(
        node for node in engine.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


def test_winner_id_buffer_to_host_read_uses_host_array_size():
    method = _engine_method("celf_materialize_winner_target_ids")
    calls = [
        node for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "cl"
        and node.func.attr == "enqueue_copy"
    ]
    # One readback for the count and one for the compacted ID prefix.
    assert len(calls) == 2
    ids_read = max(calls, key=lambda call: call.lineno)
    keywords = {kw.arg for kw in ids_read.keywords}
    assert "is_blocking" in keywords
    assert "byte_count" not in keywords, (
        "PyOpenCL's device-buffer -> host-array overload derives byte count "
        "from the destination ndarray and rejects byte_count"
    )
    # The host destination must be the n_ids-sized view, so the readback is
    # limited to the compacted prefix rather than the entire reusable buffer.
    host_arg = ids_read.args[1]
    assert isinstance(host_arg, ast.Name) and host_arg.id == "host_ids"
