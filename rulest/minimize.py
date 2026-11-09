"""Progressive, signature-based functional minimization.

Rules are compared against the same complete probe-word set as before, but
most candidates are now evaluated in small probe batches.  Candidates that
become unique after an early batch are finalized immediately; only colliding
buckets proceed to the next batch.  This preserves the exact equivalence
relation defined by all probes while avoiding unnecessary Python rule
applications for the majority of candidates.

Large candidate sets use a streaming SQLite work table.  Input items are
iterated lazily (no ``list(rule_counter.items())`` copy), worker results are
written in batches, and only unresolved collision rows are revisited.
"""
import os
import time
import shutil
import hashlib
import sqlite3
import tempfile
import multiprocessing as mp
from collections import Counter

from tqdm import tqdm

from .common import (
    log_section, log_info, log_warn, bold, cyan, green, red, dim, _fmt_speed,
    STANDARD_PROGRESS_BAR_FORMAT,
    safe_worker_count, _py_apply_single_rule,
    MINIMIZE_DISK_THRESHOLD, MINIMIZE_DISK_BATCH_SIZE, _kb,
)

# The first pass intentionally uses probes with varied character classes and
# lengths.  Remaining probes are appended in their original order.  Probe
# order does not change the equivalence relation; it only helps split buckets
# sooner.
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
# SQLite batches are deliberately larger than the historical 10k UPSERT
# batches: the temporary DB is disposable, so amortize Python/SQLite calls.
MINIMIZE_SQLITE_BATCH_SIZE = max(25_000, int(MINIMIZE_DISK_BATCH_SIZE))
_MINIMIZE_UNSUPPORTED_PREFIX = "__UNSUPPORTED__::"

# Module-level worker state/functions are picklable on Windows spawn.
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


def _probe_chunk_signature(rule, probe_words, start, stop):
    """Hash outputs for one probe slice without building a temporary list.

    The rule is split once per candidate rather than once per probe.  Length-
    prefixing keeps output boundaries unambiguous and avoids allocating the
    old ``outputs`` list plus joined/encoded copy for every candidate.
    """
    digest = hashlib.blake2b(digest_size=16)
    parts = rule.split()
    for word in probe_words[start:stop]:
        output = _apply_compiled_chain(parts, word)
        if output is None:
            # Unsupported rules are intentionally never merged with another
            # rule, matching the historic minimizer's sentinel behavior.
            return _MINIMIZE_UNSUPPORTED_PREFIX + rule
        encoded = output.encode('utf-8', errors='replace')
        digest.update(len(encoded).to_bytes(4, 'little'))
        digest.update(encoded)
    return digest.hexdigest()


def _extend_signature(previous, chunk_signature):
    """Append a probe-chunk digest to a previous partial signature."""
    if previous.startswith(_MINIMIZE_UNSUPPORTED_PREFIX):
        return previous
    if chunk_signature.startswith(_MINIMIZE_UNSUPPORTED_PREFIX):
        return chunk_signature
    digest = hashlib.blake2b(digest_size=16)
    digest.update(bytes.fromhex(previous))
    digest.update(bytes.fromhex(chunk_signature))
    return digest.hexdigest()


def compute_rule_signature_hash(rule, probe_words):
    """Return a deterministic full signature (also used by the GA cache)."""
    return _probe_chunk_signature(rule, probe_words, 0, len(probe_words))


def _ordered_probe_words(probe_words):
    """Move diverse probes forward while preserving every supplied probe."""
    source = list(probe_words)
    remaining = list(source)
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
    rule, count, start, stop = task
    sig = _probe_chunk_signature(rule, _minimize_worker_probe_words, start, stop)
    return sig, rule, count


def _minimize_worker_refine(task):
    previous, rule, count, start, stop = task
    chunk_sig = _probe_chunk_signature(rule, _minimize_worker_probe_words, start, stop)
    return _extend_signature(previous, chunk_sig), rule, count


def _minimize_worker_disk_initial(task):
    row_id, rule, count, depth, start, stop = task
    sig = _probe_chunk_signature(rule, _minimize_worker_probe_words, start, stop)
    return row_id, rule, count, depth, sig


def _minimize_worker_disk_refine(task):
    row_id, rule, count, previous, start, stop = task
    chunk_sig = _probe_chunk_signature(rule, _minimize_worker_probe_words, start, stop)
    return row_id, count, _extend_signature(previous, chunk_sig)


def _worker_configuration(n_total):
    n_workers = safe_worker_count(min(mp.cpu_count(), max(1, n_total // 200 + 1)))
    use_mp = n_total >= 500 and n_workers > 1
    return n_workers, use_mp


def _make_pool(n_workers, use_mp, probe_words):
    global _minimize_worker_probe_words
    # The same worker entry points are used by the serial fallback.
    _minimize_worker_probe_words = probe_words
    if not use_mp:
        return None
    # Linux fork avoids serializing the large parent state; Windows uses spawn
    # and only initializes workers with the short probe list.
    if hasattr(os, 'fork'):
        ctx = mp.get_context('fork')
    else:
        ctx = mp.get_context('spawn')
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


def _add_bucket(singletons, collisions, signature, candidate):
    """Store singleton buckets compactly; allocate lists only on collision."""
    group = collisions.get(signature)
    if group is not None:
        group.append(candidate)
        return
    previous = singletons.pop(signature, None)
    if previous is None:
        singletons[signature] = candidate
    else:
        collisions[signature] = [previous, candidate]


def _progress_tick(pbar, pending, done, start_time, hits_total, force=False):
    """Render minimization progress in the same vocabulary as Stages 0–2.

    ``rules`` is the number of candidates processed in the current probe pass.
    ``hits`` is the sum of input per-rule hit counts processed in that pass.
    As in Stages 1 and 2, this is a sum across rule candidates and can include
    overlapping target words; it is not a count of distinct cracked words.
    """
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
    if n > MINIMIZE_DISK_THRESHOLD:
        return _minimize_disk(rule_counter, probes, chunks)
    return _minimize_mem(rule_counter, probes, chunks)


def _minimize_mem(rule_counter, probe_words, chunks=None):
    n_total = len(rule_counter)
    chunks = chunks or _chunk_ranges(len(probe_words))
    n_workers, use_mp = _worker_configuration(n_total)
    log_info(f"[MINIMIZE] Workers     : {bold(str(n_workers if use_mp else 1))}")
    pool = _make_pool(n_workers, use_mp, probe_words)
    survivors = Counter()
    early_exit = False
    started = time.time()

    try:
        # First probe pass across every input rule.  Singletons are finalized
        # immediately; only signatures with collisions retain candidate lists.
        start, stop = chunks[0]
        singletons = {}
        collisions = {}
        done = pending_ui = hits_total = 0
        _progress_tick.last_update = time.time()
        with tqdm(total=n_total, desc=green(f"  Minimize probes {start + 1}-{stop}"),
                  unit="rule", ncols=shutil.get_terminal_size((80, 24)).columns,
                  bar_format=STANDARD_PROGRESS_BAR_FORMAT) as pbar:
            tasks = ((rule, count, start, stop) for rule, count in rule_counter.items())
            for signature, rule, count in _imap(pool, _minimize_worker_initial, tasks):
                if _kb.poll():
                    early_exit = True
                    log_warn("[MIN] Early exit — preserving processed candidates without partial-signature deduplication")
                    break
                _add_bucket(singletons, collisions, signature, (rule, count))
                hits_total += int(count)
                done += 1
                pending_ui += 1
                pending_ui = _progress_tick(
                    pbar, pending_ui, done, started, hits_total, force=False
                )
            _progress_tick(pbar, pending_ui, done, started, hits_total, force=True)

        if early_exit:
            for rule, count in singletons.values():
                survivors[rule] = count
            for group in collisions.values():
                for rule, count in group:
                    survivors[rule] = count
            return _log_minimize_result(survivors, n_total, len(singletons) + sum(len(g) for g in collisions.values()))

        for rule, count in singletons.values():
            survivors[rule] = count
        singletons.clear()
        pending_groups = collisions
        collisions = None

        for start, stop in chunks[1:]:
            if not pending_groups:
                break
            pending_total = sum(len(group) for group in pending_groups.values())
            next_singletons = {}
            next_collisions = {}
            done = pending_ui = hits_total = 0
            phase_started = time.time()
            _progress_tick.last_update = phase_started
            with tqdm(total=pending_total,
                      desc=green(f"  Refine probes {start + 1}-{stop}"),
                      unit="rule", ncols=shutil.get_terminal_size((80, 24)).columns,
                      bar_format=STANDARD_PROGRESS_BAR_FORMAT) as pbar:
                def refine_tasks():
                    for previous, group in pending_groups.items():
                        for rule, count in group:
                            yield previous, rule, count, start, stop

                for signature, rule, count in _imap(pool, _minimize_worker_refine, refine_tasks()):
                    if _kb.poll():
                        early_exit = True
                        log_warn("[MIN] Early exit — preserving unresolved collision buckets individually")
                        break
                    _add_bucket(next_singletons, next_collisions, signature, (rule, count))
                    hits_total += int(count)
                    done += 1
                    pending_ui += 1
                    pending_ui = _progress_tick(
                        pbar, pending_ui, done, phase_started, hits_total, force=False
                    )
                _progress_tick(pbar, pending_ui, done, phase_started, hits_total, force=True)

            if early_exit:
                # Do not merge candidates based on an incomplete probe prefix.
                for group in pending_groups.values():
                    for rule, count in group:
                        survivors[rule] = count
                pending_groups = {}
                break

            for rule, count in next_singletons.values():
                survivors[rule] = count
            next_singletons.clear()
            pending_groups = next_collisions

        if not early_exit:
            for group in pending_groups.values():
                best_rule, best_count = min(
                    group,
                    key=lambda item: (-item[1], len(item[0].split()), item[0]),
                )
                survivors[best_rule] = best_count
    finally:
        _pool_finish(pool, early_exit)

    return _log_minimize_result(survivors, n_total, n_total)


def _log_minimize_result(survivors, n_total, processed):
    removed = max(0, processed - len(survivors))
    log_info(f"[MINIMIZE] {green('Done')}")
    log_info(f"           Rules processed   : {bold(str(processed)):>12s}")
    log_info(f"           Rules kept        : {bold(green(str(len(survivors)))):>12s}")
    log_info(f"           Rules removed     : {bold(red(str(removed))):>12s}  ({removed/max(1,processed):.1%})")
    if processed < n_total:
        log_warn(f"[MINIMIZE] Partial result: {n_total - processed:,} candidates were not processed")
    return survivors


def _sqlite_exec_progress(conn, sql, description, params=(), progress_ops=200_000):
    """Execute a potentially expensive SQLite statement with a live heartbeat.

    The disk-backed minimizer used to perform several multi-million-row SQL
    operations after the first tqdm reached 100%, without emitting anything.
    These indeterminate bars report SQLite virtual-machine work so those
    transitions no longer look like a frozen ``probes 1-8`` pass.
    """
    started = time.monotonic()
    last_postfix = [started]
    with tqdm(
        total=None,
        desc=green(f"  {description}"),
        unit="vm-op",
        ncols=shutil.get_terminal_size((80, 24)).columns,
        bar_format=STANDARD_PROGRESS_BAR_FORMAT,
    ) as pbar:
        def _progress():
            now = time.monotonic()
            pbar.update(progress_ops)
            if now - last_postfix[0] >= 1.0:
                pbar.set_postfix({"elapsed": f"{now - started:.0f}s"}, refresh=False)
                last_postfix[0] = now
            return 0

        conn.set_progress_handler(_progress, progress_ops)
        try:
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor
        finally:
            conn.set_progress_handler(None, 0)


def _sqlite_scalar_progress(conn, sql, description, params=(), progress_ops=200_000):
    """Fetch one aggregate result while exposing long SQLite scans."""
    started = time.monotonic()
    last_postfix = [started]
    with tqdm(
        total=None,
        desc=green(f"  {description}"),
        unit="vm-op",
        ncols=shutil.get_terminal_size((80, 24)).columns,
        bar_format=STANDARD_PROGRESS_BAR_FORMAT,
    ) as pbar:
        def _progress():
            now = time.monotonic()
            pbar.update(progress_ops)
            if now - last_postfix[0] >= 1.0:
                pbar.set_postfix({"elapsed": f"{now - started:.0f}s"}, refresh=False)
                last_postfix[0] = now
            return 0

        conn.set_progress_handler(_progress, progress_ops)
        try:
            row = conn.execute(sql, params).fetchone()
            return row[0] if row else 0
        finally:
            conn.set_progress_handler(None, 0)


def _counter_from_sql(conn, query, total, description):
    """Materialize a partial result with a visible, hit-aware progress bar."""
    result = Counter()
    started = time.time()
    done = pending_ui = hits_total = 0
    _progress_tick.last_update = started
    with tqdm(
        total=total,
        desc=green(f"  {description}"),
        unit="rule",
        ncols=shutil.get_terminal_size((80, 24)).columns,
        bar_format=STANDARD_PROGRESS_BAR_FORMAT,
    ) as pbar:
        cursor = conn.execute(query)
        while True:
            rows = cursor.fetchmany(8192)
            if not rows:
                break
            for rule, count in rows:
                result[rule] = count
                hits_total += int(count)
            batch_size = len(rows)
            done += batch_size
            pending_ui += batch_size
            pending_ui = _progress_tick(
                pbar, pending_ui, done, started, hits_total, force=False
            )
        _progress_tick(pbar, pending_ui, done, started, hits_total, force=True)
    return result


def _minimize_disk(rule_counter, probe_words, chunks=None):
    """Progressive minimization backed by SQLite, retaining only collisions.

    The old implementation updated millions of candidate rows from active=1
    to active=0 after every probe pass.  On a mostly-unique 3-6M candidate set,
    that mass UPDATE plus the later Python loop rebuilding a Counter made the
    completed first pass appear to hang.  This version stores only collision
    signatures in a compact temporary table.  If all signatures are unique,
    the original Counter can be returned directly with no 3M-row copy.
    """
    tmp_fd, tmp_path = tempfile.mkstemp(suffix='.db', prefix='ruleops_minimize_')
    os.close(tmp_fd)
    conn = None
    n_total = len(rule_counter)
    chunks = chunks or _chunk_ranges(len(probe_words))
    n_workers, use_mp = _worker_configuration(n_total)
    log_info(f"[MINIMIZE] Temp DB     : {dim(tmp_path)}")
    log_info(f"[MINIMIZE] Workers     : {bold(str(n_workers if use_mp else 1))}")
    pool = _make_pool(n_workers, use_mp, probe_words)
    early_exit = False
    initial_done = 0

    try:
        conn = sqlite3.connect(tmp_path)
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA synchronous = OFF")
        # Keep large GROUP BY / UPDATE work tables off the Python heap.  The
        # temporary SQLite file is disposable and bounded by the OS temp area.
        conn.execute("PRAGMA temp_store = FILE")
        conn.execute("PRAGMA cache_size = -65536")
        conn.execute("PRAGMA locking_mode = EXCLUSIVE")
        conn.execute("""
            CREATE TABLE candidates (
                id INTEGER PRIMARY KEY,
                rule TEXT NOT NULL,
                count INTEGER NOT NULL,
                depth INTEGER NOT NULL,
                sig TEXT NOT NULL
            )
        """)
        conn.commit()

        # Initial pass: stream Counter.items() directly to workers and insert
        # bounded batches.  No second 3.8M-entry Python list is created.
        start, stop = chunks[0]
        insert_batch = []
        done = pending_ui = hits_total = 0
        _progress_tick.last_update = time.time()
        pass_started = time.time()
        with tqdm(total=n_total, desc=green(f"  Minimize probes {start + 1}-{stop}"),
                  unit="rule", ncols=shutil.get_terminal_size((80, 24)).columns,
                  bar_format=STANDARD_PROGRESS_BAR_FORMAT) as pbar:
            def initial_tasks():
                for row_id, (rule, count) in enumerate(rule_counter.items(), 1):
                    yield row_id, rule, count, len(rule.split()), start, stop

            for row_id, rule, count, depth, signature in _imap(
                    pool, _minimize_worker_disk_initial, initial_tasks()):
                if _kb.poll():
                    early_exit = True
                    log_warn("[MIN] Early exit during initial probe pass; keeping only processed candidates")
                    break
                insert_batch.append((row_id, rule, count, depth, signature))
                hits_total += int(count)
                done += 1
                pending_ui += 1
                if len(insert_batch) >= MINIMIZE_SQLITE_BATCH_SIZE:
                    conn.executemany(
                        "INSERT INTO candidates(id,rule,count,depth,sig) VALUES (?,?,?,?,?)",
                        insert_batch,
                    )
                    conn.commit()
                    insert_batch.clear()
                pending_ui = _progress_tick(
                    pbar, pending_ui, done, pass_started, hits_total, force=False
                )
            if insert_batch:
                conn.executemany(
                    "INSERT INTO candidates(id,rule,count,depth,sig) VALUES (?,?,?,?,?)",
                    insert_batch,
                )
                conn.commit()
                insert_batch.clear()
            initial_done = done
            _progress_tick(pbar, pending_ui, done, pass_started, hits_total, force=True)

        if early_exit:
            partial = _counter_from_sql(
                conn, "SELECT rule,count FROM candidates ORDER BY id",
                initial_done, "Keep processed candidates"
            )
            return _log_minimize_result(partial, n_total, initial_done)

        # The index allows SQLite to classify equal signatures in index order.
        # Its work is now visible instead of being hidden after the first bar.
        _sqlite_exec_progress(
            conn,
            "CREATE INDEX idx_candidates_sig ON candidates(sig)",
            "Index probe signatures",
        )
        conn.execute("""
            CREATE TEMP TABLE pending_signatures (
                sig TEXT PRIMARY KEY
            ) WITHOUT ROWID
        """)
        conn.commit()
        _sqlite_exec_progress(
            conn,
            """INSERT INTO pending_signatures(sig)
               SELECT sig FROM candidates GROUP BY sig HAVING COUNT(*) > 1""",
            f"Classify collisions {start + 1}-{stop}",
        )

        pending_rows = _sqlite_scalar_progress(
            conn,
            """SELECT COUNT(*) FROM pending_signatures AS p
               JOIN candidates AS c INDEXED BY idx_candidates_sig ON c.sig=p.sig""",
            "Count unresolved candidates",
        )
        pending_groups = _sqlite_scalar_progress(
            conn, "SELECT COUNT(*) FROM pending_signatures", "Count collision groups"
        )
        unique_rows = n_total - pending_rows
        log_info(
            f"[MINIMIZE] Probes {start + 1}-{stop}: "
            f"{green(f'{unique_rows:,} unique')} finalized, "
            f"{cyan(f'{pending_rows:,}')} candidates in {pending_groups:,} collision groups"
        )

        # This is the common large-wordlist fast path: if the first 8 probes
        # distinguish every candidate, no later probe pass or Counter rebuild
        # is needed.  Returning the input mapping also avoids a multi-million
        # row Python/SQLite round trip.
        if pending_rows == 0:
            log_info("[MINIMIZE] All candidates are unique on the first probe batch; remaining probes skipped")
            return rule_counter

        for pass_number, (start, stop) in enumerate(chunks[1:], start=2):
            if pending_rows == 0:
                break

            conn.execute("DROP TABLE IF EXISTS stage_updates")
            conn.execute("CREATE TEMP TABLE stage_updates (id INTEGER PRIMARY KEY, sig TEXT NOT NULL)")
            conn.commit()
            update_batch = []
            done = pending_ui = hits_total = 0
            phase_started = time.time()
            _progress_tick.last_update = phase_started
            log_info(
                f"[MINIMIZE] Probe pass {pass_number}/{len(chunks)} "
                f"({start + 1}-{stop}/{len(probe_words)}): "
                f"{pending_rows:,} unresolved candidates in {pending_groups:,} groups"
            )
            with tqdm(total=pending_rows,
                      desc=green(f"  Refine probes {start + 1}-{stop}"),
                      unit="rule", ncols=shutil.get_terminal_size((80, 24)).columns,
                      bar_format=STANDARD_PROGRESS_BAR_FORMAT) as pbar:
                # Fetch bounded chunks on the main thread.  The worker pool
                # receives only these small Python tuples, never SQLite state.
                cursor = conn.execute("""
                    SELECT c.id,c.rule,c.count,c.sig
                    FROM pending_signatures AS p
                    JOIN candidates AS c INDEXED BY idx_candidates_sig ON c.sig=p.sig
                """)
                while True:
                    source_rows = cursor.fetchmany(8192)
                    if not source_rows:
                        break
                    tasks = ((row_id, rule, count, signature, start, stop)
                             for row_id, rule, count, signature in source_rows)
                    for row_id, count, signature in _imap(
                            pool, _minimize_worker_disk_refine, tasks, chunksize=256):
                        if _kb.poll():
                            early_exit = True
                            log_warn("[MIN] Early exit during refinement; unresolved candidates kept individually")
                            break
                        update_batch.append((row_id, signature))
                        hits_total += int(count)
                        done += 1
                        pending_ui += 1
                        if len(update_batch) >= MINIMIZE_SQLITE_BATCH_SIZE:
                            conn.executemany(
                                "INSERT INTO stage_updates(id,sig) VALUES (?,?)", update_batch
                            )
                            conn.commit()
                            update_batch.clear()
                        pending_ui = _progress_tick(
                            pbar, pending_ui, done, phase_started, hits_total, force=False
                        )
                    if early_exit:
                        break
                if update_batch and not early_exit:
                    conn.executemany(
                        "INSERT INTO stage_updates(id,sig) VALUES (?,?)", update_batch
                    )
                    conn.commit()
                    update_batch.clear()
                _progress_tick(pbar, pending_ui, done, phase_started, hits_total, force=True)

            if early_exit:
                # stage_updates may be incomplete.  Do not apply partial
                # signatures and do not merge any collision candidates.
                conn.execute("DROP TABLE IF EXISTS stage_updates")
                conn.commit()
                return rule_counter

            # Apply only the candidates that were actually unresolved in the
            # previous pass, then classify collisions only within that subset.
            _sqlite_exec_progress(conn, """
                UPDATE candidates
                SET sig=(SELECT stage_updates.sig FROM stage_updates
                         WHERE stage_updates.id=candidates.id)
                WHERE id IN (SELECT id FROM stage_updates)
            """, f"Apply probe signatures {start + 1}-{stop}")
            conn.execute("DELETE FROM pending_signatures")
            conn.commit()
            _sqlite_exec_progress(conn, """
                INSERT INTO pending_signatures(sig)
                SELECT sig FROM stage_updates
                GROUP BY sig HAVING COUNT(*) > 1
            """, f"Classify collisions {start + 1}-{stop}")
            conn.execute("DROP TABLE stage_updates")
            conn.commit()

            pending_rows = _sqlite_scalar_progress(
                conn,
                """SELECT COUNT(*) FROM pending_signatures AS p
                   JOIN candidates AS c INDEXED BY idx_candidates_sig ON c.sig=p.sig""",
                "Count unresolved candidates",
            )
            pending_groups = _sqlite_scalar_progress(
                conn, "SELECT COUNT(*) FROM pending_signatures", "Count collision groups"
            )
            unique_rows = n_total - pending_rows
            log_info(
                f"[MINIMIZE] Probes {start + 1}-{stop}: "
                f"{green(f'{unique_rows:,} unique')} finalized, "
                f"{cyan(f'{pending_rows:,}')} candidates in {pending_groups:,} collision groups"
            )
            if pending_rows == 0:
                log_info("[MINIMIZE] All candidates are unique; remaining probes skipped")
                return rule_counter

        # The original Counter already contains every candidate.  Copy it once
        # using dict's optimized copy path, then remove only losing members of
        # the final collision groups instead of rebuilding millions of
        # singleton entries row by row from SQLite.
        survivors = rule_counter.copy()
        removed = 0
        cursor = conn.execute("""
            SELECT c.sig,c.rule,c.count,c.depth
            FROM pending_signatures AS p
            JOIN candidates AS c INDEXED BY idx_candidates_sig ON c.sig=p.sig
            ORDER BY c.sig ASC, c.count DESC, c.depth ASC, c.rule ASC
        """)
        last_signature = None
        collision_rows = pending_rows
        done = pending_ui = hits_total = 0
        started = time.time()
        _progress_tick.last_update = started
        with tqdm(total=collision_rows,
                  desc=green("  Resolve final collisions"), unit="rule",
                  ncols=shutil.get_terminal_size((80, 24)).columns,
                  bar_format=STANDARD_PROGRESS_BAR_FORMAT) as pbar:
            while True:
                rows = cursor.fetchmany(8192)
                if not rows:
                    break
                for signature, rule, count, depth in rows:
                    if signature == last_signature:
                        survivors.pop(rule, None)
                        removed += 1
                    else:
                        last_signature = signature
                    hits_total += int(count)
                batch_size = len(rows)
                done += batch_size
                pending_ui += batch_size
                pending_ui = _progress_tick(
                    pbar, pending_ui, done, started, hits_total, force=False
                )
            _progress_tick(pbar, pending_ui, done, started, hits_total, force=True)

        conn.close()
        conn = None
        log_info(f"[MINIMIZE] Final collision resolution removed {removed:,} duplicate rules")
        return _log_minimize_result(survivors, n_total, n_total)
    finally:
        _pool_finish(pool, early_exit)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
