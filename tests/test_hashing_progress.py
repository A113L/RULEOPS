"""Regression tests for the "quiet down hashmap building" fix.

`build_indexed_open_addressing_table` and `fnv1a64_packed_records_chunked`
used to print their own unthrottled `[HASHMAP] ...` lines unconditionally
(the latter) or always-on-by-default (the former) while gpu_engine.py's CELF
target-table build already runs under a single-line ActivityHeartbeat -- the
two progress reporters interleaved and the heartbeat's one overwritten line
kept getting interrupted by a wall of separate scrolling prints. Both
functions can now be told to stay quiet via progress=False, which is what
gpu_engine.py's single call site now passes.
"""
import io
import os
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "rulest"))

import numpy as np
from hashing import build_indexed_open_addressing_table  # noqa: E402


class TestBuildIndexedOpenAddressingTableProgress:
    def test_progress_false_prints_nothing(self):
        keys = np.arange(1, 500, dtype=np.uint64) * 2654435761 % (2**63)
        buf = io.StringIO()
        with redirect_stdout(buf):
            build_indexed_open_addressing_table(keys, progress=False)
        assert buf.getvalue() == ""

    def test_progress_true_is_still_the_default_and_prints(self):
        # Backward compatibility: any other/future caller that doesn't pass
        # progress= at all must see unchanged behavior.
        keys = np.arange(1, 500, dtype=np.uint64) * 2654435761 % (2**63)
        buf = io.StringIO()
        with redirect_stdout(buf):
            build_indexed_open_addressing_table(keys)
        assert "[HASHMAP]" in buf.getvalue()

    def test_progress_false_result_matches_progress_true_result(self):
        # Quieting the function must not change what it computes.
        keys = np.arange(1, 500, dtype=np.uint64) * 2654435761 % (2**63)
        quiet = build_indexed_open_addressing_table(keys, progress=False)
        buf = io.StringIO()
        with redirect_stdout(buf):
            loud = build_indexed_open_addressing_table(keys, progress=True)
        for a, b in zip(quiet, loud):
            if isinstance(a, np.ndarray):
                assert np.array_equal(a, b)
            else:
                assert a == b


def test_packed_record_index_builder_matches_legacy_table_without_global_ids():
    import numpy as np
    from rulest.hashing import (
        build_indexed_open_addressing_table,
        build_indexed_open_addressing_table_from_packed_records,
        fnv1a64_packed_records_chunked,
        table_size_for_count,
    )

    records = [b"alpha", b"", b"too-long", b"beta", b"alpha"]
    offsets = np.empty(len(records), dtype=np.uint64)
    lengths = np.empty(len(records), dtype=np.int32)
    payload = bytearray()
    for index, record in enumerate(records):
        offsets[index] = len(payload)
        lengths[index] = len(record)
        payload.extend(record)
    packed = np.frombuffer(payload, dtype=np.uint8)
    valid_ids = np.asarray([0, 3, 4], dtype=np.int32)
    table_size = table_size_for_count(len(records), load_factor=0.50)

    fingerprints = fnv1a64_packed_records_chunked(
        packed, offsets, lengths, valid_ids, progress=False
    )
    expected = build_indexed_open_addressing_table(
        fingerprints, ids=valid_ids, table_size=table_size, progress=False
    )
    expected_hashes, expected_ids, expected_occupied, _, expected_inserted = expected
    expected_target_slots = np.full(len(records), -1, dtype=np.int32)
    placed = expected_ids >= 0
    expected_target_slots[expected_ids[placed]] = np.flatnonzero(placed)

    actual_target_slots = np.empty(len(records), dtype=np.int32)
    actual = build_indexed_open_addressing_table_from_packed_records(
        packed,
        offsets,
        lengths,
        table_size=table_size,
        max_record_len=5,
        target_slots_out=actual_target_slots,
        progress=False,
    )
    actual_hashes, actual_ids, actual_occupied, _, actual_inserted = actual

    assert actual_inserted == expected_inserted == len(valid_ids)
    assert np.array_equal(actual_hashes, expected_hashes)
    assert np.array_equal(actual_ids, expected_ids)
    assert np.array_equal(actual_occupied, expected_occupied)
    assert np.array_equal(actual_target_slots, expected_target_slots)


def test_packed_record_index_builder_matches_legacy_across_multiple_chunks(monkeypatch):
    import numpy as np
    from rulest.hashing import (
        build_indexed_open_addressing_table,
        build_indexed_open_addressing_table_from_packed_records,
        fnv1a64_packed_records_chunked,
        table_size_for_count,
    )

    monkeypatch.setenv("RULEST_HASHMAP_BUILD_BATCH", "4096")
    records = [f"target-{index % 137}".encode("ascii") for index in range(5000)]
    offsets = np.empty(len(records), dtype=np.uint64)
    lengths = np.empty(len(records), dtype=np.int32)
    payload = bytearray()
    for index, record in enumerate(records):
        offsets[index] = len(payload)
        lengths[index] = len(record)
        payload.extend(record)
    packed = np.frombuffer(payload, dtype=np.uint8)
    ids = np.arange(len(records), dtype=np.int32)
    table_size = table_size_for_count(len(records))

    fingerprints = fnv1a64_packed_records_chunked(
        packed, offsets, lengths, ids, progress=False
    )
    expected = build_indexed_open_addressing_table(
        fingerprints, ids=ids, table_size=table_size, progress=False
    )
    target_slots = np.empty(len(records), dtype=np.int32)
    actual = build_indexed_open_addressing_table_from_packed_records(
        packed, offsets, lengths,
        table_size=table_size,
        max_record_len=64,
        target_slots_out=target_slots,
        progress=False,
    )

    assert actual[4] == expected[4] == len(records)
    assert np.array_equal(actual[0], expected[0])
    assert np.array_equal(actual[1], expected[1])
    assert np.array_equal(actual[2], expected[2])
