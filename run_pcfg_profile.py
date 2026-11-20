#!/usr/bin/env python3
"""CLI entry point for the aggregate-only PCFG corpus profiler."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rulest.pcfg_profile import main


if __name__ == "__main__":
    raise SystemExit(main())
