#!/usr/bin/env python3
"""CLI entry point for the Top-N Seed Generator."""
import sys
from pathlib import Path

# Allow running from repository root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rulest.topn_seedgen import main

if __name__ == "__main__":
    raise SystemExit(main())
