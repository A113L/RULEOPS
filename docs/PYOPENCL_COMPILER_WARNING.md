# PyOpenCL CompilerWarning suppression

The `recompute-gpu` CELF path builds its kernels from
`rule_ranker/celf_recompute_gpu.py`. PyOpenCL can emit the generic
`CompilerWarning` notice when an OpenCL driver returns non-empty build output,
even when the program build succeeds.

The CELF build now suppresses only `pyopencl.CompilerWarning` during that
specific `Program.build()` call. It does not suppress `BuildError`, exceptions
from the driver, or unrelated Python warnings. A regression test verifies that
an unrelated warning remains visible.

This changes log noise only; it does not change kernel source, build options,
scoring, or GPU execution. Driver-specific compiler diagnostics are not
independently captured or evaluated by this change.
