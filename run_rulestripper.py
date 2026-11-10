#!/usr/bin/env python3
"""RULEOPS entry point for the shared-memory, spawn-safe Rulestripper."""
import multiprocessing as mp

from rulest.rulestripper import main


if __name__ == "__main__":
    mp.freeze_support()
    main()
