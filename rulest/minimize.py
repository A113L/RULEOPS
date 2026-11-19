"""In-memory, offset-indexed functional rule minimization.

The minimizer stores one fixed-size signature record per input rule.  Each
record contains a 128-bit probe signature and an offset into the original
rule collection; it never stores a second Python tuple/string for a candidate.
Only records whose signatures collide are compacted to the front of the same
NumPy buffer and refined with later probe batches.
"""
import os
import time
import shutil
import hashlib
import multiprocessing as mp
from collections import Counter

import numpy as np
from tqdm import tqdm

from .common import (
    log_section, log_info, log_warn, bold, cyan, green, red, dim, _fmt_speed,
    STANDARD_PROGRESS_BAR_FORMAT,
    safe_worker_count, _py_apply_single_rule, _kb,
)

# Diverse probes run first. Remaining probes retain their original order.
_PRIORITY_PROBES = (
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "!@#$%^&*()-_=+[]{}|;:,.<>?/~",
    "averylongpassword1234567890abcdefghi",
    "qwertyuiopasdfgh",
    "a b",
    "Password",
    "p@ssw0rd",
    "correcthorsebattery",
    "averylongpassword1234567890abcdef",
    "superman123",
    "test1234",
)

MINIMIZE_PROBE_BATCH_SIZE = 8
MINIMIZE_BATCH_SIZE = 25_000
MINIMIZE_MAX_WORKERS = 8
_MINIMIZE_UNSUPPORTED_PREFIX = "__UNSUPPORTED__::"
_UNSUPPORTED_KIND = 1
_SUPPORTED_KIND = 0

# One row per rule: kind (1 byte), signature (16 bytes), source offset (4/8 bytes).
# The source offset refers to the stable `rules` list, not a copied rule string.
def _record_dtype(rule_count):
    index_dtype = "<u4" if rule_count <= 0xFFFFFFFF else "<u8"
    return np.dtype([("kind", "u1"), ("sig", "V16"), ("idx", index_dtype)])


_minimize_worker_probe_words = []


def _minimize_worker_init(probe_words):
    global _minimize_worker_probe_words
    _minimize_worker_probe_words = probe_words


def _apply_compiled_chain(parts, word):
    """Apply a pre-split rule chain, matching common.py's py_apply_chain."""
    current = word
    for operation in parts:
        current = _py_apply_single_rule(operation, current)
        if current is None:
            return None
    return current


def _unsupported_rule_signature(rule):
    # Kind is stored separately in the record, so this hash only distinguishes
    # exact rule strings within the unsupported-rule class. Hash collisions are
    # checked against the original text during final collision resolution.
    return hashlib.blake2b(
        rule.encode("utf-8", errors="surrogatepass"), digest_size=16
    ).digest()


def _probe_chunk_signature_raw(rule, probe_words, start, stop):
    """Return (16-byte digest, kind) without hex/string allocations."""
    digest = hashlib.blake2b(digest_size=16)
    parts = rule.split()
    for word in probe_words[start:stop]:
        output = _apply_compiled_chain(parts, word)
        if output is None:
            return _unsupported_rule_signature(rule), _UNSUPPORTED_KIND
        encoded = output.encode("utf-8", errors="replace")
        digest.update(len(encoded).to_bytes(4, "little"))
        digest.update(encoded)
    return digest.digest(), _SUPPORTED_KIND


def _probe_chunk_signature(rule, probe_words, start, stop):
    """Backward-compatible textual signature used by the public hash helper."""
    signature, kind = _probe_chunk_signature_raw(rule, probe_words, start, stop)
    if kind == _UNSUPPORTED_KIND:
        return _MINIMIZE_UNSUPPORTED_PREFIX + rule
    return signature.hex()


def _extend_signature_raw(previous, previous_kind, chunk_signature, chunk_kind):
    if previous_kind == _UNSUPPORTED_KIND or chunk_kind == _UNSUPPORTED_KIND:
        if chunk_kind == _UNSUPPORTED_KIND:
            return chunk_signature, _UNSUPPORTED_KIND
        return previous, previous_kind
    digest = hashlib.blake2b(digest_size=16)
    digest.update(previous)
    digest.update(chunk_signature)
    return digest.digest(), _SUPPORTED_KIND


def _extend_signature(previous, chunk_signature):
    """Backward-compatible textual signature extension."""
    if previous.startswith(_MINIMIZE_UNSUPPORTED_PREFIX):
        return previous
    if chunk_signature.startswith(_MINIMIZE_UNSUPPORTED_PREFIX):
        return chunk_signature
    digest = hashlib.blake2b(digest_size=16)
    digest.update(bytes.fromhex(previous))
    digest.update(bytes.fromhex(chunk_signature))
    return digest.hexdigest()


def compute_rule_signature_hash(rule, probe_words):
    """Return the historical deterministic textual signature (GA cache API)."""
    return _probe_chunk_signature(rule, probe_words, 0, len(probe_words))


def _ordered_probe_words(probe_words):
    """Move diverse probes forward while preserving every supplied probe."""
    remaining = list(probe_words)
    ordered = []
    for preferred in _PRIORITY_PROBES:
        try:
            index = remaining.index(preferred)
        except ValueError:
            continue
        ordered.append(remaining.pop(index))
    ordered.extend(remaining)
    return ordered


def _chunk_ranges(n_probes):
    if n_probes <= 0:
        return [(0, 0)]
    return [
        (start, min(n_probes, start + MINIMIZE_PROBE_BATCH_SIZE))
        for start in range(0, n_probes, MINIMIZE_PROBE_BATCH_SIZE)
    ]


def _minimize_worker_initial(task):
    index, rule, start, stop = task
    signature, kind = _probe_chunk_signature_raw(
        rule, _minimize_worker_probe_words, start, stop
    )
    return index, signature, kind


def _minimize_worker_refine(task):
    slot, rule, previous, previous_kind, start, stop = task
    chunk_signature, chunk_kind = _probe_chunk_signature_raw(
        rule, _minimize_worker_probe_words, start, stop
    )
    signature, kind = _extend_signature_raw(
        previous, previous_kind, chunk_signature, chunk_kind
    )
    return slot, signature, kind


def _worker_configuration(n_total):
    n_workers = safe_worker_count(min(MINIMIZE_MAX_WORKERS, mp.cpu_count(), max(1, n_total // 200 + 1)))
    return n_workers, n_total >= 500 and n_workers > 1


def _make_pool(n_workers, use_mp, probe_words):
    global _minimize_worker_probe_words
    _minimize_worker_probe_words = probe_words
    if not use_mp:
        return None
    ctx = mp.get_context("fork" if hasattr(os, "fork") else "spawn")
    return ctx.Pool(
        processes=n_workers,
        initializer=_minimize_worker_init,
        initargs=(probe_words,),
    )


def _imap(pool, function, tasks, chunksize=128):
    if pool is None:
        return map(function, tasks)
    return pool.imap_unordered(function, tasks, chunksize=chunksize)


def _pool_finish(pool, early_exit):
    if pool is None:
        return
    try:
        if early_exit:
            pool.terminate()
        else:
            pool.close()
    finally:
        pool.join()


def _progress_tick(pbar, pending, done, start_time, hits_total, force=False):
    now = time.time()
    if pending >= 2048 or force or now - _progress_tick.last_update >= 0.75:
        if pending:
            pbar.update(pending)
        elapsed = max(0.001, now - start_time)
        speed = _fmt_speed(done / elapsed, "rules")
        pbar.set_postfix({
            "rules": cyan(f"{done:,}"),
            "hits": cyan(f"{hits_total:,}"),
            "spd": green(speed),
        }, refresh=False)
        _progress_tick.last_update = now
        return 0
    return pending


_progress_tick.last_update = 0.0


def _classify_and_compact(records, active_count, keep_mask):
    """Mark unique offsets and compact only collisions in-place."""
    if active_count <= 0:
        return 0
    active = records[:active_count]
    active.sort(order=("kind", "sig", "idx"), kind="quicksort")
    if active_count == 1:
        keep_mask[int(active["idx"][0])] = True
        return 0

    same = (active["kind"][1:] == active["kind"][:-1]) & (
        active["sig"][1:] == active["sig"][:-1]
    )
    if not np.any(same):
        # Common large-ruleset path: no index arrays or collision mask needed.
        keep_mask[active["idx"]] = True
        return 0

    collision_mask = np.zeros(active_count, dtype=np.bool_)
    collision_mask[:-1] |= same
    collision_mask[1:] |= same
    collision_count = int(np.count_nonzero(collision_mask))
    if collision_count * 2 < active_count:
        # Few collisions: mark all as kept, then clear only collision offsets.
        keep_mask[active["idx"]] = True
        collision_offsets = active["idx"][collision_mask]
        keep_mask[collision_offsets] = False
    else:
        # Collision-heavy pass: materialize only the (smaller) singleton offsets.
        single_offsets = active["idx"][~collision_mask]
        keep_mask[single_offsets] = True
    if collision_count:
        # np.compress supports an output view into the input buffer, allowing
        # collision compaction without allocating a second candidate array.
        np.compress(collision_mask, active, axis=0, out=active[:collision_count])
    return collision_count


def _resolve_final_collisions(records, active_count, rules, rule_counter, keep_mask):
    """Resolve the last collision groups with RuleEST's historical priority."""
    if active_count <= 0:
        return
    active = records[:active_count]
    active.sort(order=("kind", "sig", "idx"), kind="quicksort")
    pos = 0
    while pos < active_count:
        kind = int(active["kind"][pos])
        signature = active["sig"][pos]
        end = pos + 1
        while end < active_count and int(active["kind"][end]) == kind and active["sig"][end] == signature:
            end += 1

        if kind == _UNSUPPORTED_KIND:
            # Different unsupported rules must never be merged. The digest is
            # only an index; compare exact text to guard against hash collisions.
            seen_rules = set()
            for cursor in range(pos, end):
                index = int(active["idx"][cursor])
                rule = rules[index]
                if rule not in seen_rules:
                    seen_rules.add(rule)
                    keep_mask[index] = True
        else:
            best_index = int(active["idx"][pos])
            best_rule = rules[best_index]
            best_count = int(rule_counter[best_rule])
            best_depth = len(best_rule.split())
            for cursor in range(pos + 1, end):
                index = int(active["idx"][cursor])
                rule = rules[index]
                count = int(rule_counter[rule])
                depth = len(rule.split())
                if (count > best_count or
                    (count == best_count and depth < best_depth) or
                    (count == best_count and depth == best_depth and rule < best_rule)):
                    best_index = index
                    best_rule = rule
                    best_count = count
                    best_depth = depth
            keep_mask[best_index] = True
        pos = end


def minimize_by_signature(rule_counter, probe_words):
    if not rule_counter:
        return Counter()
    log_section("POST-PROCESSING — Signature-Based Functional Minimization")
    n = len(rule_counter)
    probes = _ordered_probe_words(probe_words)
    chunks = _chunk_ranges(len(probes))
    layout = "+".join(str(stop - start) for start, stop in chunks)
    log_info(f"[MINIMIZE] Candidates  : {bold(str(n))}")
    log_info(f"[MINIMIZE] Probe words : {bold(str(len(probes)))}")
    log_info(f"[MINIMIZE] Progressive : {bold(layout)} probes/pass")
    log_info("[MINIMIZE] Indexing    : in-memory offsets (no temporary database)")
    return _minimize_offsets(rule_counter, probes, chunks)


def _minimize_offsets(rule_counter, probe_words, chunks=None):
    """Progressively minimize using a compact offset-indexed NumPy buffer."""
    n_total = len(rule_counter)
    chunks = chunks or _chunk_ranges(len(probe_words))
    n_workers, use_mp = _worker_configuration(n_total)
    log_info(f"[MINIMIZE] Workers     : {bold(str(n_workers if use_mp else 1))}")

    # One list of references gives each original rule a stable integer offset.
    # Unlike list(rule_counter.items()), this does not allocate N Python tuples.
    rules = list(rule_counter)
    records = np.empty(n_total, dtype=_record_dtype(n_total))
    records["idx"] = np.arange(n_total, dtype=records.dtype["idx"])
    keep_mask = np.zeros(n_total, dtype=np.bool_)

    pool = _make_pool(n_workers, use_mp, probe_words)
    batch_size = max(1, int(MINIMIZE_BATCH_SIZE))
    early_exit = False
    started = time.time()
    try:
        start, stop = chunks[0]
        done = pending_ui = hits_total = 0
        _progress_tick.last_update = time.time()
        with tqdm(total=n_total, desc=green(f"  Minimize probes {start + 1}-{stop}"),
                  unit="rule", ncols=shutil.get_terminal_size((80, 24)).columns,
                  bar_format=STANDARD_PROGRESS_BAR_FORMAT) as pbar:
            for offset in range(0, n_total, batch_size):
                stop_at = min(n_total, offset + batch_size)
                tasks = (
                    (index, rules[index], start, stop)
                    for index in range(offset, stop_at)
                )
                for index, signature, kind in _imap(pool, _minimize_worker_initial, tasks):
                    if _kb.poll():
                        early_exit = True
                        log_warn("[MIN] Early exit — returning the original rule set without partial deduplication")
                        break
                    records["sig"][index] = signature
                    records["kind"][index] = kind
                    hits_total += int(rule_counter[rules[index]])
                    done += 1
                    pending_ui += 1
                    pending_ui = _progress_tick(
                        pbar, pending_ui, done, started, hits_total, force=False
                    )
                if early_exit:
                    break
            _progress_tick(pbar, pending_ui, done, started, hits_total, force=True)

        if early_exit:
            return _log_minimize_result(rule_counter, n_total, n_total)

        active_count = _classify_and_compact(records, n_total, keep_mask)
        if active_count == 0:
            log_info("[MINIMIZE] All candidates are unique on the first probe batch; remaining probes skipped")
            return rule_counter

        for pass_number, (start, stop) in enumerate(chunks[1:], start=2):
            if active_count == 0:
                break
            pass_started = time.time()
            done = pending_ui = hits_total = 0
            _progress_tick.last_update = pass_started
            log_info(
                f"[MINIMIZE] Probe pass {pass_number}/{len(chunks)} "
                f"({start + 1}-{stop}/{len(probe_words)}): "
                f"{active_count:,} unresolved candidates"
            )
            with tqdm(total=active_count,
                      desc=green(f"  Refine probes {start + 1}-{stop}"),
                      unit="rule", ncols=shutil.get_terminal_size((80, 24)).columns,
                      bar_format=STANDARD_PROGRESS_BAR_FORMAT) as pbar:
                for offset in range(0, active_count, batch_size):
                    stop_at = min(active_count, offset + batch_size)

                    def refine_tasks():
                        for slot in range(offset, stop_at):
                            index = int(records["idx"][slot])
                            yield (
                                slot,
                                rules[index],
                                bytes(records["sig"][slot]),
                                int(records["kind"][slot]),
                                start,
                                stop,
                            )

                    for slot, signature, kind in _imap(
                            pool, _minimize_worker_refine, refine_tasks(), chunksize=256):
                        if _kb.poll():
                            early_exit = True
                            log_warn("[MIN] Early exit — returning the original rule set without partial deduplication")
                            break
                        records["sig"][slot] = signature
                        records["kind"][slot] = kind
                        index = int(records["idx"][slot])
                        hits_total += int(rule_counter[rules[index]])
                        done += 1
                        pending_ui += 1
                        pending_ui = _progress_tick(
                            pbar, pending_ui, done, pass_started, hits_total, force=False
                        )
                    if early_exit:
                        break
                _progress_tick(pbar, pending_ui, done, pass_started, hits_total, force=True)

            if early_exit:
                return _log_minimize_result(rule_counter, n_total, n_total)
            active_count = _classify_and_compact(records, active_count, keep_mask)
            log_info(
                f"[MINIMIZE] Probe pass {pass_number}: "
                f"{n_total - active_count:,} finalized, {active_count:,} unresolved"
            )

        _resolve_final_collisions(records, active_count, rules, rule_counter, keep_mask)
        kept_count = int(np.count_nonzero(keep_mask))
        if kept_count == n_total:
            return rule_counter

        survivors = Counter()
        for index, rule in enumerate(rules):
            if keep_mask[index]:
                survivors[rule] = rule_counter[rule]
        return _log_minimize_result(survivors, n_total, n_total)
    finally:
        _pool_finish(pool, early_exit)


def _log_minimize_result(survivors, n_total, processed):
    removed = max(0, processed - len(survivors))
    log_info(f"[MINIMIZE] {green('Done')}")
    log_info(f"           Rules processed   : {bold(str(processed)):>12s}")
    log_info(f"           Rules kept        : {bold(green(str(len(survivors)))):>12s}")
    log_info(f"           Rules removed     : {bold(red(str(removed))):>12s}  ({removed/max(1,processed):.1%})")
    if processed < n_total:
        log_warn(f"[MINIMIZE] Partial result: {n_total - processed:,} candidates were not processed")
    return survivors
